#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libubox/blob.h>
#include <libubox/blobmsg.h>
#include <libubox/usock.h>

#include "libubus.h"
#include "ubusmsg.h"

#define DEBUG 1

#ifdef DEBUG
#define DPRINTF(_format, ...) fprintf(stderr, "ubus: " _format, ## __VA_ARGS__)
#else
#define DPRINTF(...) do {} while(0)
#endif

#define STATIC_IOV(_var) { .iov_base = (char *) &(_var), .iov_len = sizeof(_var) }

const char *__ubus_strerror[__UBUS_STATUS_LAST] = {
	[UBUS_STATUS_OK] = "Success",
	[UBUS_STATUS_INVALID_COMMAND] = "Invalid command",
	[UBUS_STATUS_INVALID_ARGUMENT] = "Invalid argument",
	[UBUS_STATUS_NOT_FOUND] = "Not found",
	[UBUS_STATUS_NO_DATA] = "No response",
};

static struct blob_buf b;

static const struct blob_attr_info ubus_policy[UBUS_ATTR_MAX] = {
	[UBUS_ATTR_STATUS] = { .type = BLOB_ATTR_INT32 },
	[UBUS_ATTR_OBJID] = { .type = BLOB_ATTR_INT32 },
	[UBUS_ATTR_OBJPATH] = { .type = BLOB_ATTR_STRING },
};
static struct blob_attr *attrbuf[UBUS_ATTR_MAX];

struct ubus_pending_data {
	struct list_head list;
	int type;
	struct blob_attr data[];
};

struct blob_attr **ubus_parse_msg(struct blob_attr *msg)
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

int ubus_start_request(struct ubus_context *ctx, struct ubus_request *req,
		       struct blob_attr *msg, int cmd, uint32_t peer)
{
	struct ubus_msghdr hdr;
	struct iovec iov[2] = {
		STATIC_IOV(hdr)
	};

	memset(req, 0, sizeof(*req));
	hdr.version = 0;
	hdr.type = cmd;
	hdr.seq = ++ctx->request_seq;
	hdr.peer = peer;

	req->peer = hdr.peer;
	req->seq = hdr.seq;

	if (!msg) {
		blob_buf_init(&b, 0);
		msg = b.head;
	}

	iov[1].iov_base = (char *) msg;
	iov[1].iov_len = blob_raw_len(msg);
	INIT_LIST_HEAD(&req->list);
	INIT_LIST_HEAD(&req->pending);

	return writev(ctx->sock.fd, iov, 2);
}

static bool recv_retry(int fd, struct iovec *iov, bool wait)
{
	int bytes;

	while (iov->iov_len > 0) {
		bytes = read(fd, iov->iov_base, iov->iov_len);
		if (bytes < 0) {
			bytes = 0;
			if (errno == EINTR)
				continue;

			if (errno != EAGAIN) {
				perror("read");
				return false;
			}
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

	if (blob_raw_len(hdr->data) + sizeof(*hdr) > UBUS_MAX_MSGLEN)
		return false;

	return true;
}

static bool get_next_msg(struct ubus_context *ctx, bool wait)
{
	struct iovec iov = STATIC_IOV(ctx->msgbuf.hdr);

	/* receive header + start attribute */
	iov.iov_len += sizeof(struct blob_attr);
	if (!recv_retry(ctx->sock.fd, &iov, wait))
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

	*ret = blob_get_int32(attrbuf[UBUS_ATTR_STATUS]);
	return true;
}

static void ubus_process_req_data(struct ubus_request *req)
{
	struct ubus_pending_data *data;

	while (!list_empty(&req->pending)) {
		data = list_first_entry(&req->pending,
			struct ubus_pending_data, list);
		list_del(&data->list);
		req->data_cb(req, data->type, data->data);
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
		req->data_cb(req, hdr->type, hdr->data);
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

static void ubus_process_msg(struct ubus_context *ctx, struct ubus_msghdr *hdr)
{
	struct ubus_request *req;

	list_for_each_entry(req, &ctx->requests, list) {
		if (hdr->seq != req->seq || hdr->peer != req->peer)
			continue;

		switch(hdr->type) {
		case UBUS_MSG_STATUS:
			ubus_process_req_status(req, hdr);
			return;
		case UBUS_MSG_DATA:
			if (req->data_cb)
				ubus_req_data(req, hdr);
			break;
		default:
			DPRINTF("unknown message type: %d\n", hdr->type);
			break;
		}
	}
}

void ubus_abort_request(struct ubus_context *ctx, struct ubus_request *req)
{
	if (!list_empty(&req->list))
		return;

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

	while (get_next_msg(ctx, false))
		ubus_process_msg(ctx, hdr);
}

int ubus_complete_request(struct ubus_context *ctx, struct ubus_request *req)
{
	struct ubus_msghdr *hdr = &ctx->msgbuf.hdr;

	if (!list_empty(&req->list))
		list_del(&req->list);

	while (1) {
		if (req->status_msg)
			return req->status_code;

		if (!get_next_msg(ctx, true))
			return UBUS_STATUS_NO_DATA;

		if (hdr->seq != req->seq || hdr->peer != req->peer)
			goto skip;

		switch(hdr->type) {
		case UBUS_MSG_STATUS:
			return ubus_process_req_status(req, hdr);
		case UBUS_MSG_DATA:
			if (req->data_cb)
				ubus_req_data(req, hdr);
			continue;
		default:
			DPRINTF("unknown message type: %d\n", hdr->type);
			continue;
		}

skip:
		ubus_process_msg(ctx, hdr);
	}
}

void ubus_invoke_async(struct ubus_context *ctx, uint32_t obj, const char *method,
                       struct blob_attr *msg, struct ubus_request *req)
{
	blob_buf_init(&b, 0);
	blob_put_int32(&b, UBUS_ATTR_OBJID, obj);
	blob_put_string(&b, UBUS_ATTR_METHOD, method);
	blob_put(&b, UBUS_ATTR_DATA, blob_data(msg), blob_len(msg));

	ubus_start_request(ctx, req, b.head, UBUS_MSG_INVOKE, obj);
}

int ubus_invoke(struct ubus_context *ctx, uint32_t obj, const char *method,
                struct blob_attr *msg, ubus_data_handler_t cb, void *priv)
{
	struct ubus_request req;

	ubus_invoke_async(ctx, obj, method, msg, &req);
	req.data_cb = cb;
	req.priv = priv;
	return ubus_complete_request(ctx, &req);
}

static void ubus_publish_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct ubus_object *obj = req->priv;

	ubus_parse_msg(msg);

	if (!attrbuf[UBUS_ATTR_OBJID])
		return;

	obj->id = blob_get_int32(attrbuf[UBUS_ATTR_OBJID]);

	if (attrbuf[UBUS_ATTR_OBJTYPE])
		obj->type->id = blob_get_int32(attrbuf[UBUS_ATTR_OBJTYPE]);
}

static bool ubus_push_table_data(const struct ubus_signature **sig, int *rem, bool array)
{
	const struct ubus_signature *cur;
	bool nest_type;
	void *nest;

	while (rem) {
		cur = (*sig)++;
		(*rem)--;
		switch(cur->type) {
		case UBUS_SIGNATURE_END:
			return !array;
		case BLOBMSG_TYPE_INT32:
		case BLOBMSG_TYPE_STRING:
			blobmsg_add_u32(&b, cur->name, cur->type);
			break;
		case BLOBMSG_TYPE_TABLE:
		case BLOBMSG_TYPE_ARRAY:
			nest_type = cur->type == BLOBMSG_TYPE_ARRAY;
			nest = blobmsg_open_nested(&b, cur->name, nest_type);
			if (!ubus_push_table_data(sig, rem, nest_type))
				return false;
			blobmsg_close_table(&b, nest);
			break;
		default:
			return false;
		}
		if (array)
			return true;
	}
	return false;
}

static bool ubus_push_object_type(struct ubus_object_type *type)
{
	void *s, *m;
	int rem = type->n_signature;
	const struct ubus_signature *sig = type->signature;

	s = blob_nest_start(&b, UBUS_ATTR_SIGNATURE);
	while (rem) {
		if (sig->type != UBUS_SIGNATURE_METHOD)
			return false;

		m = blobmsg_open_table(&b, sig->name);

		sig++;
		rem--;
		if (!ubus_push_table_data(&sig, &rem, false))
			return false;

		blobmsg_close_table(&b, m);
	}
	blob_nest_end(&b, s);

	return true;
}

int ubus_publish(struct ubus_context *ctx, struct ubus_object *obj)
{
	struct ubus_request req;
	int ret;

	if (obj->id || !obj->name || !obj->type)
		return UBUS_STATUS_INVALID_ARGUMENT;

	blob_buf_init(&b, 0);
	blob_put_string(&b, UBUS_ATTR_OBJPATH, obj->name);
	if (obj->parent)
		blob_put_int32(&b, UBUS_ATTR_OBJID, obj->parent->id);

	if (obj->type->id)
		blob_put_int32(&b, UBUS_ATTR_OBJTYPE, obj->type->id);
	else if (!ubus_push_object_type(obj->type))
		return UBUS_STATUS_INVALID_ARGUMENT;

	ubus_start_request(ctx, &req, b.head, UBUS_MSG_PUBLISH, 0);
	req.data_cb = ubus_publish_cb;
	req.priv = obj;
	ret = ubus_complete_request(ctx, &req);
	if (ret)
		return ret;

	if (!obj->id)
		return UBUS_STATUS_NO_DATA;

	return 0;
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
	if (ctx->sock.fd < 0) {
		DPRINTF("Failed to connect to server\n");
		goto error_free;
	}
	ctx->sock.cb = ubus_handle_data;

	if (read(ctx->sock.fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
		DPRINTF("Failed to read initial message data\n");
		goto error_close;
	}

	if (!ubus_validate_hdr(&hdr.hdr)) {
		DPRINTF("Failed to validate initial message header\n");
		goto error_close;
	}

	if (hdr.hdr.type != UBUS_MSG_HELLO) {
		DPRINTF("Unexpected initial message\n");
		goto error_close;
	}

	buf = calloc(1, blob_raw_len(&hdr.data));
	if (!buf)
		goto error_close;

	memcpy(buf, &hdr.data, sizeof(hdr.data));
	if (read(ctx->sock.fd, blob_data(buf), blob_len(buf)) != blob_len(buf)) {
		DPRINTF("Failed to retrieve initial message data\n");
		goto error_free_buf;
	}

	ctx->local_id = hdr.hdr.peer;
	free(buf);

	if (!ctx->local_id) {
		DPRINTF("Failed to get local peer id\n");
		goto error_close;
	}

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
