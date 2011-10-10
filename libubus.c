/*
 * Copyright (C) 2011 Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>

#include <libubox/blob.h>
#include <libubox/blobmsg.h>
#include <libubox/usock.h>

#include "libubus.h"
#include "ubusmsg.h"

#define STATIC_IOV(_var) { .iov_base = (char *) &(_var), .iov_len = sizeof(_var) }

const char *__ubus_strerror[__UBUS_STATUS_LAST] = {
	[UBUS_STATUS_OK] = "Success",
	[UBUS_STATUS_INVALID_COMMAND] = "Invalid command",
	[UBUS_STATUS_INVALID_ARGUMENT] = "Invalid argument",
	[UBUS_STATUS_METHOD_NOT_FOUND] = "Method not found",
	[UBUS_STATUS_NOT_FOUND] = "Not found",
	[UBUS_STATUS_NO_DATA] = "No response",
	[UBUS_STATUS_PERMISSION_DENIED] = "Permission denied",
	[UBUS_STATUS_TIMEOUT] = "Request timed out",
	[UBUS_STATUS_NOT_SUPPORTED] = "Operation not supported",
	[UBUS_STATUS_UNKNOWN_ERROR] = "Unknown error",
};

static struct blob_buf b;

static const struct blob_attr_info ubus_policy[UBUS_ATTR_MAX] = {
	[UBUS_ATTR_STATUS] = { .type = BLOB_ATTR_INT32 },
	[UBUS_ATTR_OBJID] = { .type = BLOB_ATTR_INT32 },
	[UBUS_ATTR_OBJPATH] = { .type = BLOB_ATTR_STRING },
	[UBUS_ATTR_METHOD] = { .type = BLOB_ATTR_STRING },
};
static struct blob_attr *attrbuf[UBUS_ATTR_MAX];

struct ubus_pending_data {
	struct list_head list;
	int type;
	struct blob_attr data[];
};

static int ubus_cmp_id(const void *k1, const void *k2, void *ptr)
{
	const uint32_t *id1 = k1, *id2 = k2;

	if (*id1 < *id2)
		return -1;
	else
		return *id1 > *id2;
}

static struct blob_attr **ubus_parse_msg(struct blob_attr *msg)
{
	blob_parse(msg, attrbuf, ubus_policy, UBUS_ATTR_MAX);
	return attrbuf;
}

const char *ubus_strerror(int error)
{
	static char err[32];

	if (error < 0 || error >= __UBUS_STATUS_LAST)
		goto out;

	if (!__ubus_strerror[error])
		goto out;

	return __ubus_strerror[error];

out:
	sprintf(err, "Unknown error: %d", error);
	return err;
}

static void wait_data(int fd, bool write)
{
	struct pollfd pfd = { .fd = fd };

	pfd.events = write ? POLLOUT : POLLIN;
	poll(&pfd, 1, 0);
}

static int writev_retry(int fd, struct iovec *iov, int iov_len)
{
	int len = 0;

	do {
		int cur_len = writev(fd, iov, iov_len);
		if (cur_len < 0) {
			switch(errno) {
			case EAGAIN:
				wait_data(fd, true);
				break;
			case EINTR:
				break;
			default:
				return -1;
			}
			continue;
		}
		len += cur_len;
		while (cur_len >= iov->iov_len) {
			cur_len -= iov->iov_len;
			iov_len--;
			iov++;
			if (!cur_len || !iov_len)
				return len;
		}
		iov->iov_len -= cur_len;
	} while (1);
}

static int ubus_send_msg(struct ubus_context *ctx, uint32_t seq,
			 struct blob_attr *msg, int cmd, uint32_t peer)
{
	struct ubus_msghdr hdr;
	struct iovec iov[2] = {
		STATIC_IOV(hdr)
	};

	hdr.version = 0;
	hdr.type = cmd;
	hdr.seq = seq;
	hdr.peer = peer;

	if (!msg) {
		blob_buf_init(&b, 0);
		msg = b.head;
	}

	iov[1].iov_base = (char *) msg;
	iov[1].iov_len = blob_raw_len(msg);

	return writev_retry(ctx->sock.fd, iov, ARRAY_SIZE(iov));
}

static int ubus_start_request(struct ubus_context *ctx, struct ubus_request *req,
			      struct blob_attr *msg, int cmd, uint32_t peer)
{
	memset(req, 0, sizeof(*req));

	if (msg && blob_pad_len(msg) > UBUS_MAX_MSGLEN)
		return -1;

	INIT_LIST_HEAD(&req->list);
	INIT_LIST_HEAD(&req->pending);
	req->ctx = ctx;
	req->peer = peer;
	req->seq = ++ctx->request_seq;
	return ubus_send_msg(ctx, req->seq, msg, cmd, peer);
}

static bool recv_retry(int fd, struct iovec *iov, bool wait)
{
	int bytes;

	while (iov->iov_len > 0) {
		if (wait)
			wait_data(fd, false);

		bytes = read(fd, iov->iov_base, iov->iov_len);
		if (bytes < 0) {
			bytes = 0;
			if (uloop_cancelled)
				return false;
			if (errno == EINTR)
				continue;

			if (errno != EAGAIN)
				return false;
		}
		if (!wait && !bytes)
			return false;

		wait = true;
		iov->iov_len -= bytes;
		iov->iov_base += bytes;
	}

	return true;
}

static bool ubus_validate_hdr(struct ubus_msghdr *hdr)
{
	if (hdr->version != 0)
		return false;

	if (blob_raw_len(hdr->data) < sizeof(*hdr->data))
		return false;

	if (blob_pad_len(hdr->data) > UBUS_MAX_MSGLEN)
		return false;

	return true;
}

static bool get_next_msg(struct ubus_context *ctx)
{
	struct iovec iov = STATIC_IOV(ctx->msgbuf.hdr);

	/* receive header + start attribute */
	iov.iov_len += sizeof(struct blob_attr);
	if (!recv_retry(ctx->sock.fd, &iov, false))
		return false;

	iov.iov_len = blob_len(ctx->msgbuf.hdr.data);
	if (iov.iov_len > 0 && !recv_retry(ctx->sock.fd, &iov, true))
		return false;

	return ubus_validate_hdr(&ctx->msgbuf.hdr);
}

static bool ubus_get_status(struct ubus_msghdr *hdr, int *ret)
{
	ubus_parse_msg(hdr->data);

	if (!attrbuf[UBUS_ATTR_STATUS])
		return false;

	*ret = blob_get_u32(attrbuf[UBUS_ATTR_STATUS]);
	return true;
}

static void req_data_cb(struct ubus_request *req, int type, struct blob_attr *data)
{
	struct blob_attr **attr;

	if (req->raw_data_cb)
		req->raw_data_cb(req, type, data);

	if (!req->data_cb)
		return;

	attr = ubus_parse_msg(data);
	req->data_cb(req, type, attr[UBUS_ATTR_DATA]);
}

static void ubus_process_req_data(struct ubus_request *req)
{
	struct ubus_pending_data *data;

	while (!list_empty(&req->pending)) {
		data = list_first_entry(&req->pending,
			struct ubus_pending_data, list);
		list_del(&data->list);
		if (!req->cancelled)
			req_data_cb(req, data->type, data->data);
		free(data);
	}
}

static void ubus_req_complete_cb(struct ubus_request *req)
{
	ubus_complete_handler_t cb = req->complete_cb;

	if (!cb)
		return;

	req->complete_cb = NULL;
	cb(req, req->status_code);
}

static int ubus_process_req_status(struct ubus_request *req, struct ubus_msghdr *hdr)
{
	int ret = UBUS_STATUS_INVALID_ARGUMENT;

	if (!list_empty(&req->list))
		list_del(&req->list);

	ubus_get_status(hdr, &ret);
	req->peer = hdr->peer;
	req->status_msg = true;
	req->status_code = ret;
	if (!req->blocked)
		ubus_req_complete_cb(req);

	return ret;
}

static void ubus_req_data(struct ubus_request *req, struct ubus_msghdr *hdr)
{
	struct ubus_pending_data *data;
	int len;

	if (!req->blocked) {
		req->blocked = true;
		req_data_cb(req, hdr->type, hdr->data);
		ubus_process_req_data(req);
		req->blocked = false;

		if (req->status_msg)
			ubus_req_complete_cb(req);

		return;
	}

	len = blob_raw_len(hdr->data);
	data = calloc(1, sizeof(*data) + len);
	if (!data)
		return;

	data->type = hdr->type;
	memcpy(data->data, hdr->data, len);
	list_add(&data->list, &req->pending);
}

static struct ubus_request *ubus_find_request(struct ubus_context *ctx, uint32_t seq, uint32_t peer)
{
	struct ubus_request *req;

	list_for_each_entry(req, &ctx->requests, list) {
		if (seq != req->seq || peer != req->peer)
			continue;

		return req;
	}
	return NULL;
}

static void ubus_process_invoke(struct ubus_context *ctx, struct ubus_msghdr *hdr)
{
	struct ubus_request_data req;
	struct ubus_object *obj;
	uint32_t objid = 0;
	int method;
	int ret = 0;

	req.peer = hdr->peer;
	req.seq = hdr->seq;
	ubus_parse_msg(hdr->data);

	if (!attrbuf[UBUS_ATTR_OBJID])
		return;

	objid = blob_get_u32(attrbuf[UBUS_ATTR_OBJID]);

	if (!attrbuf[UBUS_ATTR_METHOD]) {
		ret = UBUS_STATUS_INVALID_ARGUMENT;
		goto send;
	}

	obj = avl_find_element(&ctx->objects, &objid, obj, avl);
	if (!obj) {
		ret = UBUS_STATUS_NOT_FOUND;
		goto send;
	}

	for (method = 0; method < obj->n_methods; method++)
		if (!obj->methods[method].name ||
		    !strcmp(obj->methods[method].name,
		            blob_data(attrbuf[UBUS_ATTR_METHOD])))
			goto found;

	/* not found */
	ret = UBUS_STATUS_METHOD_NOT_FOUND;
	goto send;

found:
	req.object = objid;
	ret = obj->methods[method].handler(ctx, obj, &req,
					   blob_data(attrbuf[UBUS_ATTR_METHOD]),
					   attrbuf[UBUS_ATTR_DATA]);

send:
	blob_buf_init(&b, 0);
	blob_put_int32(&b, UBUS_ATTR_STATUS, ret);
	blob_put_int32(&b, UBUS_ATTR_OBJID, objid);
	ubus_send_msg(ctx, req.seq, b.head, UBUS_MSG_STATUS, req.peer);
}

static void ubus_process_msg(struct ubus_context *ctx, struct ubus_msghdr *hdr)
{
	struct ubus_request *req;

	switch(hdr->type) {
	case UBUS_MSG_STATUS:
		req = ubus_find_request(ctx, hdr->seq, hdr->peer);
		if (!req)
			break;

		ubus_process_req_status(req, hdr);
		break;

	case UBUS_MSG_DATA:
		req = ubus_find_request(ctx, hdr->seq, hdr->peer);
		if (req && (req->data_cb || req->raw_data_cb))
			ubus_req_data(req, hdr);
		break;

	case UBUS_MSG_INVOKE:
		ubus_process_invoke(ctx, hdr);
		break;
	}
}

void ubus_abort_request(struct ubus_context *ctx, struct ubus_request *req)
{
	if (!list_empty(&req->list))
		return;

	req->cancelled = true;
	ubus_process_req_data(req);
	list_del(&req->list);
}

void ubus_complete_request_async(struct ubus_context *ctx, struct ubus_request *req)
{
	if (!list_empty(&req->list))
		return;

	list_add(&req->list, &ctx->requests);
}

static void ubus_handle_data(struct uloop_fd *u, unsigned int events)
{
	struct ubus_context *ctx = container_of(u, struct ubus_context, sock);
	struct ubus_msghdr *hdr = &ctx->msgbuf.hdr;

	while (get_next_msg(ctx)) {
		ubus_process_msg(ctx, hdr);
		if (uloop_cancelled)
			break;
	}

	if (u->eof)
		ctx->connection_lost(ctx);
}

static void ubus_sync_req_cb(struct ubus_request *req, int ret)
{
	req->status_msg = true;
	req->status_code = ret;
	uloop_end();
}

struct ubus_sync_req_cb {
	struct uloop_timeout timeout;
	struct ubus_request *req;
};

static void ubus_sync_req_timeout_cb(struct uloop_timeout *timeout)
{
	struct ubus_sync_req_cb *cb;

	cb = container_of(timeout, struct ubus_sync_req_cb, timeout);
	ubus_sync_req_cb(cb->req, UBUS_STATUS_TIMEOUT);
}

int ubus_complete_request(struct ubus_context *ctx, struct ubus_request *req,
			  int timeout)
{
	struct ubus_sync_req_cb cb;
	ubus_complete_handler_t complete_cb = req->complete_cb;
	bool registered = ctx->sock.registered;
	bool cancelled = uloop_cancelled;
	int status = UBUS_STATUS_NO_DATA;

	if (!registered) {
		uloop_init();
		ubus_add_uloop(ctx);
	}

	if (timeout) {
		memset(&cb, 0, sizeof(cb));
		cb.req = req;
		cb.timeout.cb = ubus_sync_req_timeout_cb;
		uloop_timeout_set(&cb.timeout, timeout);
	}

	ubus_complete_request_async(ctx, req);
	req->complete_cb = ubus_sync_req_cb;

	uloop_run();

	if (timeout)
		uloop_timeout_cancel(&cb.timeout);

	if (req->status_msg)
		status = req->status_code;

	req->complete_cb = complete_cb;
	if (req->complete_cb)
		req->complete_cb(req, status);

	uloop_cancelled = cancelled;
	if (!registered)
		uloop_fd_delete(&ctx->sock);

	return status;
}

struct ubus_lookup_request {
	struct ubus_request req;
	ubus_lookup_handler_t cb;
};

static void ubus_lookup_cb(struct ubus_request *ureq, int type, struct blob_attr *msg)
{
	struct ubus_lookup_request *req;
	struct ubus_object_data obj;
	struct blob_attr **attr;

	req = container_of(ureq, struct ubus_lookup_request, req);
	attr = ubus_parse_msg(msg);

	if (!attr[UBUS_ATTR_OBJID] || !attr[UBUS_ATTR_OBJPATH] ||
	    !attr[UBUS_ATTR_OBJTYPE])
		return;

	memset(&obj, 0, sizeof(obj));
	obj.id = blob_get_u32(attr[UBUS_ATTR_OBJID]);
	obj.path = blob_data(attr[UBUS_ATTR_OBJPATH]);
	obj.type_id = blob_get_u32(attr[UBUS_ATTR_OBJTYPE]);
	obj.signature = attr[UBUS_ATTR_SIGNATURE];
	req->cb(ureq->ctx, &obj, ureq->priv);
}

int ubus_lookup(struct ubus_context *ctx, const char *path,
		ubus_lookup_handler_t cb, void *priv)
{
	struct ubus_lookup_request lookup;

	blob_buf_init(&b, 0);
	if (path)
		blob_put_string(&b, UBUS_ATTR_OBJPATH, path);

	if (ubus_start_request(ctx, &lookup.req, b.head, UBUS_MSG_LOOKUP, 0) < 0)
		return UBUS_STATUS_INVALID_ARGUMENT;

	lookup.req.raw_data_cb = ubus_lookup_cb;
	lookup.req.priv = priv;
	lookup.cb = cb;
	return ubus_complete_request(ctx, &lookup.req, 0);
}

static void ubus_lookup_id_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr **attr;
	uint32_t *id = req->priv;

	attr = ubus_parse_msg(msg);

	if (!attr[UBUS_ATTR_OBJID])
		return;

	*id = blob_get_u32(attr[UBUS_ATTR_OBJID]);
}

int ubus_lookup_id(struct ubus_context *ctx, const char *path, uint32_t *id)
{
	struct ubus_request req;

	blob_buf_init(&b, 0);
	if (path)
		blob_put_string(&b, UBUS_ATTR_OBJPATH, path);

	if (ubus_start_request(ctx, &req, b.head, UBUS_MSG_LOOKUP, 0) < 0)
		return UBUS_STATUS_INVALID_ARGUMENT;

	req.raw_data_cb = ubus_lookup_id_cb;
	req.priv = id;

	return ubus_complete_request(ctx, &req, 0);
}

int ubus_send_reply(struct ubus_context *ctx, struct ubus_request_data *req,
		    struct blob_attr *msg)
{
	int ret;

	blob_buf_init(&b, 0);
	blob_put_int32(&b, UBUS_ATTR_OBJID, req->object);
	blob_put(&b, UBUS_ATTR_DATA, blob_data(msg), blob_len(msg));
	ret = ubus_send_msg(ctx, req->seq, b.head, UBUS_MSG_DATA, req->peer);
	if (ret < 0)
		return UBUS_STATUS_NO_DATA;

	return 0;
}

int ubus_invoke_async(struct ubus_context *ctx, uint32_t obj, const char *method,
                       struct blob_attr *msg, struct ubus_request *req)
{
	blob_buf_init(&b, 0);
	blob_put_int32(&b, UBUS_ATTR_OBJID, obj);
	blob_put_string(&b, UBUS_ATTR_METHOD, method);
	if (msg)
		blob_put(&b, UBUS_ATTR_DATA, blob_data(msg), blob_len(msg));

	if (ubus_start_request(ctx, req, b.head, UBUS_MSG_INVOKE, obj) < 0)
		return UBUS_STATUS_INVALID_ARGUMENT;

	return 0;
}

int ubus_invoke(struct ubus_context *ctx, uint32_t obj, const char *method,
                struct blob_attr *msg, ubus_data_handler_t cb, void *priv,
		int timeout)
{
	struct ubus_request req;

	ubus_invoke_async(ctx, obj, method, msg, &req);
	req.data_cb = cb;
	req.priv = priv;
	return ubus_complete_request(ctx, &req, timeout);
}

static void ubus_add_object_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct ubus_object *obj = req->priv;

	ubus_parse_msg(msg);

	if (!attrbuf[UBUS_ATTR_OBJID])
		return;

	obj->id = blob_get_u32(attrbuf[UBUS_ATTR_OBJID]);

	if (attrbuf[UBUS_ATTR_OBJTYPE])
		obj->type->id = blob_get_u32(attrbuf[UBUS_ATTR_OBJTYPE]);

	obj->avl.key = &obj->id;
	avl_insert(&req->ctx->objects, &obj->avl);
}

static void ubus_push_method_data(const struct ubus_method *m)
{
	void *mtbl;
	int i;

	mtbl = blobmsg_open_table(&b, m->name);

	for (i = 0; i < m->n_policy; i++)
		blobmsg_add_u32(&b, m->policy[i].name, m->policy[i].type);

	blobmsg_close_table(&b, mtbl);
}

static bool ubus_push_object_type(const struct ubus_object_type *type)
{
	void *s;
	int i;

	s = blob_nest_start(&b, UBUS_ATTR_SIGNATURE);

	for (i = 0; i < type->n_methods; i++)
		ubus_push_method_data(&type->methods[i]);

	blob_nest_end(&b, s);

	return true;
}

static int __ubus_add_object(struct ubus_context *ctx, struct ubus_object *obj)
{
	struct ubus_request req;
	int ret;

	blob_buf_init(&b, 0);

	if (obj->name && obj->type) {
		blob_put_string(&b, UBUS_ATTR_OBJPATH, obj->name);

		if (obj->type->id)
			blob_put_int32(&b, UBUS_ATTR_OBJTYPE, obj->type->id);
		else if (!ubus_push_object_type(obj->type))
			return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (ubus_start_request(ctx, &req, b.head, UBUS_MSG_ADD_OBJECT, 0) < 0)
		return UBUS_STATUS_INVALID_ARGUMENT;

	req.raw_data_cb = ubus_add_object_cb;
	req.priv = obj;
	ret = ubus_complete_request(ctx, &req, 0);
	if (ret)
		return ret;

	if (!obj->id)
		return UBUS_STATUS_NO_DATA;

	return 0;
}

int ubus_add_object(struct ubus_context *ctx, struct ubus_object *obj)
{
	if (!obj->name || !obj->type)
		return UBUS_STATUS_INVALID_ARGUMENT;

	return __ubus_add_object(ctx, obj);
}

static void ubus_remove_object_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct ubus_object *obj = req->priv;

	ubus_parse_msg(msg);

	if (!attrbuf[UBUS_ATTR_OBJID])
		return;

	obj->id = 0;

	if (attrbuf[UBUS_ATTR_OBJTYPE] && obj->type)
		obj->type->id = 0;

	avl_delete(&req->ctx->objects, &obj->avl);
}

int ubus_remove_object(struct ubus_context *ctx, struct ubus_object *obj)
{
	struct ubus_request req;
	int ret;

	blob_buf_init(&b, 0);
	blob_put_int32(&b, UBUS_ATTR_OBJID, obj->id);

	if (ubus_start_request(ctx, &req, b.head, UBUS_MSG_REMOVE_OBJECT, 0) < 0)
		return UBUS_STATUS_INVALID_ARGUMENT;

	req.raw_data_cb = ubus_remove_object_cb;
	req.priv = obj;
	ret = ubus_complete_request(ctx, &req, 0);
	if (ret)
		return ret;

	if (obj->id)
		return UBUS_STATUS_NO_DATA;

	return 0;
}

static int ubus_event_cb(struct ubus_context *ctx, struct ubus_object *obj,
			 struct ubus_request_data *req,
			 const char *method, struct blob_attr *msg)
{
	struct ubus_event_handler *ev;

	ev = container_of(obj, struct ubus_event_handler, obj);
	ev->cb(ctx, ev, method, msg);
	return 0;
}

static const struct ubus_method event_method = {
	.name = NULL,
	.handler = ubus_event_cb,
};

int ubus_register_event_handler(struct ubus_context *ctx,
				struct ubus_event_handler *ev,
				const char *pattern)
{
	struct ubus_object *obj = &ev->obj;
	struct blob_buf b2;
	int ret;

	if (!obj->id) {
		obj->methods = &event_method;
		obj->n_methods = 1;

		if (!!obj->name ^ !!obj->type)
			return UBUS_STATUS_INVALID_ARGUMENT;

		ret = __ubus_add_object(ctx, obj);
		if (ret)
			return ret;
	}

	/* use a second buffer, ubus_invoke() overwrites the primary one */
	memset(&b2, 0, sizeof(b2));
	blob_buf_init(&b2, 0);
	blobmsg_add_u32(&b2, "object", obj->id);
	if (pattern)
		blobmsg_add_string(&b2, "pattern", pattern);

	return ubus_invoke(ctx, UBUS_SYSTEM_OBJECT_EVENT, "register", b2.head,
			  NULL, NULL, 0);
}

int ubus_send_event(struct ubus_context *ctx, const char *id,
		    struct blob_attr *data)
{
	struct ubus_request req;
	void *s;

	blob_buf_init(&b, 0);
	blob_put_int32(&b, UBUS_ATTR_OBJID, UBUS_SYSTEM_OBJECT_EVENT);
	blob_put_string(&b, UBUS_ATTR_METHOD, "send");
	s = blob_nest_start(&b, UBUS_ATTR_DATA);
	blobmsg_add_string(&b, "id", id);
	blobmsg_add_field(&b, BLOBMSG_TYPE_TABLE, "data", blob_data(data), blob_len(data));
	blob_nest_end(&b, s);

	if (ubus_start_request(ctx, &req, b.head, UBUS_MSG_INVOKE, UBUS_SYSTEM_OBJECT_EVENT) < 0)
		return UBUS_STATUS_INVALID_ARGUMENT;

	return ubus_complete_request(ctx, &req, 0);
}

static void ubus_default_connection_lost(struct ubus_context *ctx)
{
	if (ctx->sock.registered)
		uloop_end();
}

struct ubus_context *ubus_connect(const char *path)
{
	struct ubus_context *ctx;
	struct {
		struct ubus_msghdr hdr;
		struct blob_attr data;
	} hdr;
	struct blob_attr *buf;

	if (!path)
		path = UBUS_UNIX_SOCKET;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		goto error;

	ctx->sock.fd = usock(USOCK_UNIX, path, NULL);
	if (ctx->sock.fd < 0)
		goto error_free;

	ctx->sock.cb = ubus_handle_data;

	if (read(ctx->sock.fd, &hdr, sizeof(hdr)) != sizeof(hdr))
		goto error_close;

	if (!ubus_validate_hdr(&hdr.hdr))
		goto error_close;

	if (hdr.hdr.type != UBUS_MSG_HELLO)
		goto error_close;

	buf = calloc(1, blob_raw_len(&hdr.data));
	if (!buf)
		goto error_close;

	memcpy(buf, &hdr.data, sizeof(hdr.data));
	if (read(ctx->sock.fd, blob_data(buf), blob_len(buf)) != blob_len(buf))
		goto error_free_buf;

	ctx->local_id = hdr.hdr.peer;
	free(buf);

	ctx->connection_lost = ubus_default_connection_lost;

	INIT_LIST_HEAD(&ctx->requests);
	avl_init(&ctx->objects, ubus_cmp_id, false, NULL);

	if (!ctx->local_id)
		goto error_close;

	fcntl(ctx->sock.fd, F_SETFL, fcntl(ctx->sock.fd, F_GETFL) | O_NONBLOCK);

	return ctx;

error_free_buf:
	free(buf);
error_close:
	close(ctx->sock.fd);
error_free:
	free(ctx);
error:
	return NULL;
}

void ubus_free(struct ubus_context *ctx)
{
	close(ctx->sock.fd);
	free(ctx);
}
