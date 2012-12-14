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
#include <sys/uio.h>
#include <sys/socket.h>

#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#include <libubox/usock.h>
#include <libubox/blob.h>
#include <libubox/blobmsg.h>

#include "libubus.h"
#include "libubus-internal.h"

#define STATIC_IOV(_var) { .iov_base = (char *) &(_var), .iov_len = sizeof(_var) }

static const struct blob_attr_info ubus_policy[UBUS_ATTR_MAX] = {
	[UBUS_ATTR_STATUS] = { .type = BLOB_ATTR_INT32 },
	[UBUS_ATTR_OBJID] = { .type = BLOB_ATTR_INT32 },
	[UBUS_ATTR_OBJPATH] = { .type = BLOB_ATTR_STRING },
	[UBUS_ATTR_METHOD] = { .type = BLOB_ATTR_STRING },
	[UBUS_ATTR_ACTIVE] = { .type = BLOB_ATTR_INT8 },
	[UBUS_ATTR_NO_REPLY] = { .type = BLOB_ATTR_INT8 },
	[UBUS_ATTR_SUBSCRIBERS] = { .type = BLOB_ATTR_NESTED },
};

static struct blob_attr *attrbuf[UBUS_ATTR_MAX];

__hidden struct blob_attr **ubus_parse_msg(struct blob_attr *msg)
{
	blob_parse(msg, attrbuf, ubus_policy, UBUS_ATTR_MAX);
	return attrbuf;
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

int __hidden ubus_send_msg(struct ubus_context *ctx, uint32_t seq,
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

void __hidden ubus_handle_data(struct uloop_fd *u, unsigned int events)
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

static void
ubus_refresh_state(struct ubus_context *ctx)
{
	struct ubus_object *obj, *tmp;

	/* clear all type IDs, they need to be registered again */
	avl_for_each_element(&ctx->objects, obj, avl)
		obj->type->id = 0;

	/* push out all objects again */
	avl_for_each_element_safe(&ctx->objects, obj, avl, tmp) {
		obj->id = 0;
		avl_delete(&ctx->objects, &obj->avl);
		ubus_add_object(ctx, obj);
	}
}

int ubus_reconnect(struct ubus_context *ctx, const char *path)
{
	struct {
		struct ubus_msghdr hdr;
		struct blob_attr data;
	} hdr;
	struct blob_attr *buf;
	int ret = UBUS_STATUS_UNKNOWN_ERROR;

	if (!path)
		path = UBUS_UNIX_SOCKET;

	if (ctx->sock.fd >= 0) {
		if (ctx->sock.registered)
			uloop_fd_delete(&ctx->sock);

		close(ctx->sock.fd);
	}

	ctx->sock.fd = usock(USOCK_UNIX, path, NULL);
	if (ctx->sock.fd < 0)
		return UBUS_STATUS_CONNECTION_FAILED;

	if (read(ctx->sock.fd, &hdr, sizeof(hdr)) != sizeof(hdr))
		goto out_close;

	if (!ubus_validate_hdr(&hdr.hdr))
		goto out_close;

	if (hdr.hdr.type != UBUS_MSG_HELLO)
		goto out_close;

	buf = calloc(1, blob_raw_len(&hdr.data));
	if (!buf)
		goto out_close;

	memcpy(buf, &hdr.data, sizeof(hdr.data));
	if (read(ctx->sock.fd, blob_data(buf), blob_len(buf)) != blob_len(buf))
		goto out_free;

	ctx->local_id = hdr.hdr.peer;
	if (!ctx->local_id)
		goto out_free;

	ret = UBUS_STATUS_OK;
	fcntl(ctx->sock.fd, F_SETFL, fcntl(ctx->sock.fd, F_GETFL) | O_NONBLOCK);

	ubus_refresh_state(ctx);

out_free:
	free(buf);
out_close:
	if (ret)
		close(ctx->sock.fd);

	return ret;
}
