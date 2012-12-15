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

#include "libubus.h"
#include "libubus-internal.h"

struct ubus_pending_data {
	struct list_head list;
	int type;
	struct blob_attr data[];
};

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

static void __ubus_process_req_data(struct ubus_request *req)
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

void ubus_abort_request(struct ubus_context *ctx, struct ubus_request *req)
{
	if (!list_empty(&req->list))
		return;

	req->cancelled = true;
	__ubus_process_req_data(req);
	list_del_init(&req->list);
}

void ubus_complete_request_async(struct ubus_context *ctx, struct ubus_request *req)
{
	if (!list_empty(&req->list))
		return;

	list_add(&req->list, &ctx->requests);
}

static void
ubus_req_complete_cb(struct ubus_request *req)
{
	ubus_complete_handler_t cb = req->complete_cb;

	if (!cb)
		return;

	req->complete_cb = NULL;
	cb(req, req->status_code);
}

static void
ubus_set_req_status(struct ubus_request *req, int ret)
{
	if (!list_empty(&req->list))
		list_del_init(&req->list);

	req->status_msg = true;
	req->status_code = ret;
	if (!req->blocked)
		ubus_req_complete_cb(req);
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
	ubus_set_req_status(cb->req, UBUS_STATUS_TIMEOUT);
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
		ubus_process_pending_msg(ctx);

	return status;
}

void ubus_complete_deferred_request(struct ubus_context *ctx, struct ubus_request_data *req, int ret)
{
	blob_buf_init(&b, 0);
	blob_put_int32(&b, UBUS_ATTR_STATUS, ret);
	blob_put_int32(&b, UBUS_ATTR_OBJID, req->object);
	ubus_send_msg(ctx, req->seq, b.head, UBUS_MSG_STATUS, req->peer);
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

static void
ubus_notify_complete_cb(struct ubus_request *req, int ret)
{
	struct ubus_notify_request *nreq;

	nreq = container_of(req, struct ubus_notify_request, req);
	if (!nreq->complete_cb)
		return;

	nreq->complete_cb(nreq, 0, 0);
}

static int
__ubus_notify_async(struct ubus_context *ctx, struct ubus_object *obj,
		    const char *type, struct blob_attr *msg,
		    struct ubus_notify_request *req, bool reply)
{
	memset(req, 0, sizeof(*req));

	blob_buf_init(&b, 0);
	blob_put_int32(&b, UBUS_ATTR_OBJID, obj->id);
	blob_put_string(&b, UBUS_ATTR_METHOD, type);

	if (!reply)
		blob_put_int8(&b, UBUS_ATTR_NO_REPLY, true);

	if (msg)
		blob_put(&b, UBUS_ATTR_DATA, blob_data(msg), blob_len(msg));

	if (ubus_start_request(ctx, &req->req, b.head, UBUS_MSG_NOTIFY, obj->id) < 0)
		return UBUS_STATUS_INVALID_ARGUMENT;

	/* wait for status message from ubusd first */
	req->req.notify = true;
	req->pending = 1;
	req->id[0] = obj->id;
	req->req.complete_cb = ubus_notify_complete_cb;

	return 0;
}

int ubus_notify_async(struct ubus_context *ctx, struct ubus_object *obj,
		      const char *type, struct blob_attr *msg,
		      struct ubus_notify_request *req)
{
	return __ubus_notify_async(ctx, obj, type, msg, req, true);
}

int ubus_notify(struct ubus_context *ctx, struct ubus_object *obj,
		const char *type, struct blob_attr *msg, int timeout)
{
	struct ubus_notify_request req;
	int ret;

	ret = __ubus_notify_async(ctx, obj, type, msg, &req, timeout >= 0);
	if (ret < 0)
		return ret;

	if (timeout < 0)
		return 0;

	return ubus_complete_request(ctx, &req.req, timeout);
}

static bool ubus_get_status(struct ubus_msghdr *hdr, int *ret)
{
	struct blob_attr **attrbuf = ubus_parse_msg(hdr->data);

	if (!attrbuf[UBUS_ATTR_STATUS])
		return false;

	*ret = blob_get_u32(attrbuf[UBUS_ATTR_STATUS]);
	return true;
}

static int
ubus_process_req_status(struct ubus_request *req, struct ubus_msghdr *hdr)
{
	int ret = UBUS_STATUS_INVALID_ARGUMENT;

	ubus_get_status(hdr, &ret);
	req->peer = hdr->peer;
	ubus_set_req_status(req, ret);

	return ret;
}

static void
ubus_process_req_data(struct ubus_request *req, struct ubus_msghdr *hdr)
{
	struct ubus_pending_data *data;
	int len;

	if (!req->blocked) {
		req->blocked = true;
		req_data_cb(req, hdr->type, hdr->data);
		__ubus_process_req_data(req);
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

static int
ubus_find_notify_id(struct ubus_notify_request *n, uint32_t objid)
{
	uint32_t pending = n->pending;
	int i;

	for (i = 0; pending; i++, pending >>= 1) {
		if (!(pending & 1))
			continue;

		if (n->id[i] == objid)
			return i;
	}

	return -1;
}

static struct ubus_request *
ubus_find_request(struct ubus_context *ctx, uint32_t seq, uint32_t peer, int *id)
{
	struct ubus_request *req;

	list_for_each_entry(req, &ctx->requests, list) {
		struct ubus_notify_request *nreq;
		nreq = container_of(req, struct ubus_notify_request, req);

		if (seq != req->seq)
			continue;

		if (req->notify) {
			if (!nreq->pending)
				continue;

			*id = ubus_find_notify_id(nreq, peer);
			if (*id < 0)
				continue;
		} else if (peer != req->peer)
			continue;

		return req;
	}
	return NULL;
}

static void ubus_process_notify_status(struct ubus_request *req, int id, struct ubus_msghdr *hdr)
{
	struct ubus_notify_request *nreq;
	struct blob_attr **tb;
	struct blob_attr *cur;
	int rem, idx = 1;
	int ret = 0;

	nreq = container_of(req, struct ubus_notify_request, req);
	nreq->pending &= ~(1 << id);

	if (!id) {
		/* first id: ubusd's status message with a list of ids */
		tb = ubus_parse_msg(hdr->data);
		if (tb[UBUS_ATTR_SUBSCRIBERS]) {
			blob_for_each_attr(cur, tb[UBUS_ATTR_SUBSCRIBERS], rem) {
				if (!blob_check_type(blob_data(cur), blob_len(cur), BLOB_ATTR_INT32))
					continue;

				nreq->pending |= (1 << idx);
				nreq->id[idx] = blob_get_int32(cur);
				idx++;

				if (idx == UBUS_MAX_NOTIFY_PEERS + 1)
					break;
			}
		}
	} else {
		ubus_get_status(hdr, &ret);
		if (nreq->status_cb)
			nreq->status_cb(nreq, id, ret);
	}

	if (!nreq->pending)
		ubus_set_req_status(req, 0);
}

void __hidden ubus_process_req_msg(struct ubus_context *ctx, struct ubus_msghdr *hdr)
{
	struct ubus_request *req;
	int id = -1;

	switch(hdr->type) {
	case UBUS_MSG_STATUS:
		req = ubus_find_request(ctx, hdr->seq, hdr->peer, &id);
		if (!req)
			break;

		if (id >= 0)
			ubus_process_notify_status(req, id, hdr);
		else
			ubus_process_req_status(req, hdr);
		break;

	case UBUS_MSG_DATA:
		req = ubus_find_request(ctx, hdr->seq, hdr->peer, &id);
		if (req && (req->data_cb || req->raw_data_cb))
			ubus_process_req_data(req, hdr);
		break;
	}
}
