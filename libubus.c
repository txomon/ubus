/*
 * Copyright (C) 2011-2012 Felix Fietkau <nbd@openwrt.org>
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
#include <sys/socket.h>
#include <unistd.h>

#include <libubox/blob.h>
#include <libubox/blobmsg.h>

#include "libubus.h"
#include "libubus-internal.h"
#include "ubusmsg.h"

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
	[UBUS_STATUS_CONNECTION_FAILED] = "Connection failed",
};

struct blob_buf b __hidden = {};

struct ubus_pending_data {
	struct list_head list;
	int type;
	struct blob_attr data[];
};

struct ubus_pending_invoke {
	struct list_head list;
	struct ubus_msghdr hdr;
};

static void ubus_process_pending_invoke(struct ubus_context *ctx);

static int ubus_cmp_id(const void *k1, const void *k2, void *ptr)
{
	const uint32_t *id1 = k1, *id2 = k2;

	if (*id1 < *id2)
		return -1;
	else
		return *id1 > *id2;
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

static bool ubus_get_status(struct ubus_msghdr *hdr, int *ret)
{
	struct blob_attr **attrbuf = ubus_parse_msg(hdr->data);

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
		list_del_init(&req->list);

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

void ubus_complete_deferred_request(struct ubus_context *ctx, struct ubus_request_data *req, int ret)
{
	blob_buf_init(&b, 0);
	blob_put_int32(&b, UBUS_ATTR_STATUS, ret);
	blob_put_int32(&b, UBUS_ATTR_OBJID, req->object);
	ubus_send_msg(ctx, req->seq, b.head, UBUS_MSG_STATUS, req->peer);
}

void __hidden ubus_process_msg(struct ubus_context *ctx, struct ubus_msghdr *hdr)
{
	struct ubus_pending_invoke *pending;
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
		if (ctx->stack_depth > 2) {
			pending = calloc(1, sizeof(*pending) +
				blob_raw_len(hdr->data));

			if (!pending)
				return;

			memcpy(&pending->hdr, hdr, sizeof(*hdr) +
				blob_raw_len(hdr->data));
			list_add(&pending->list, &ctx->pending);
		} else {
			ubus_process_invoke(ctx, hdr);
		}
		break;

	case UBUS_MSG_UNSUBSCRIBE:
		ubus_process_unsubscribe(ctx, hdr);
		break;

	case UBUS_MSG_NOTIFY:
		ubus_process_notify(ctx, hdr);
		break;
	}
}

static void ubus_process_pending_invoke(struct ubus_context *ctx)
{
	struct ubus_pending_invoke *pending, *tmp;

	list_for_each_entry_safe(pending, tmp, &ctx->pending, list) {
		list_del(&pending->list);
		ubus_process_msg(ctx, &pending->hdr);
		free(pending);
		if (ctx->stack_depth > 2)
			break;
	}
}

void ubus_abort_request(struct ubus_context *ctx, struct ubus_request *req)
{
	if (!list_empty(&req->list))
		return;

	req->cancelled = true;
	ubus_process_req_data(req);
	list_del_init(&req->list);
}

void ubus_complete_request_async(struct ubus_context *ctx, struct ubus_request *req)
{
	if (!list_empty(&req->list))
		return;

	list_add(&req->list, &ctx->requests);
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

	ctx->stack_depth++;
	while (!req->status_msg) {
		bool cancelled = uloop_cancelled;
		uloop_cancelled = false;
		uloop_run();
		uloop_cancelled = cancelled;
	}
	ctx->stack_depth--;

	if (timeout)
		uloop_timeout_cancel(&cb.timeout);

	if (req->status_msg)
		status = req->status_code;

	req->complete_cb = complete_cb;
	if (req->complete_cb)
		req->complete_cb(req, status);

	if (!registered)
		uloop_fd_delete(&ctx->sock);

	if (!ctx->stack_depth)
		ubus_process_pending_invoke(ctx);

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

int __hidden ubus_start_request(struct ubus_context *ctx, struct ubus_request *req,
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

		ret = ubus_add_object(ctx, obj);
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

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->sock.fd = -1;
	ctx->sock.cb = ubus_handle_data;
	ctx->connection_lost = ubus_default_connection_lost;

	INIT_LIST_HEAD(&ctx->requests);
	INIT_LIST_HEAD(&ctx->pending);
	avl_init(&ctx->objects, ubus_cmp_id, false, NULL);
	if (ubus_reconnect(ctx, path)) {
		free(ctx);
		ctx = NULL;
	}

	return ctx;
}

void ubus_free(struct ubus_context *ctx)
{
	close(ctx->sock.fd);
	free(ctx);
}
