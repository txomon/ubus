#include <sys/socket.h>
#include <sys/uio.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include <libubox/blob.h>
#include <libubox/uloop.h>
#include <libubox/usock.h>
#include <libubox/list.h>

#include "ubusd.h"

static struct avl_tree clients;

static struct ubus_msg_buf *ubus_msg_unshare(struct ubus_msg_buf *ub)
{
	ub = realloc(ub, sizeof(*ub) + ub->len);
	if (!ub)
		return NULL;

	ub->refcount = 1;
	memcpy(ub + 1, ub->data, ub->len);
	ub->data = (void *) (ub + 1);
	return ub;
}

struct ubus_msg_buf *ubus_msg_ref(struct ubus_msg_buf *ub)
{
	if (ub->refcount == ~0)
		return ubus_msg_unshare(ub);

	ub->refcount++;
	return ub;
}

struct ubus_msg_buf *ubus_msg_new(void *data, int len, bool shared)
{
	struct ubus_msg_buf *ub;
	int buflen = sizeof(*ub);

	if (!shared)
		buflen += len;

	ub = calloc(1, buflen);
	if (!ub)
		return NULL;

	if (shared) {
		ub->refcount = ~0;
		ub->data = data;
	} else {
		ub->refcount = 1;
		ub->data = (void *) (ub + 1);
		if (data)
			memcpy(ub + 1, data, len);
	}

	ub->len = len;
	return ub;
}

void ubus_msg_free(struct ubus_msg_buf *ub)
{
	switch (ub->refcount) {
	case 1:
	case ~0:
		free(ub);
		break;
	default:
		ub->refcount--;
		break;
	}
}

static int ubus_msg_writev(int fd, struct ubus_msg_buf *ub, int offset)
{
	struct iovec iov[2];

	if (offset < sizeof(ub->hdr)) {
		iov[0].iov_base = ((char *) &ub->hdr) + offset;
		iov[0].iov_len = sizeof(ub->hdr) - offset;
		iov[1].iov_base = (char *) ub->data;
		iov[1].iov_len = ub->len;
		return writev(fd, iov, 2);
	} else {
		offset -= sizeof(ub->hdr);
		return write(fd, ((char *) ub->data) + offset, ub->len - offset);
	}
}

/* takes the msgbuf reference */
void ubus_msg_send(struct ubus_client *cl, struct ubus_msg_buf *ub)
{
	int written;

	if (cl->buf_head)
		goto queue;

	written = ubus_msg_writev(cl->sock.fd, ub, 0);
	if (written > 0 && written < ub->len + sizeof(ub->hdr)) {
		cl->buf_head_ofs = written;

		/* get an event once we can write to the socket again */
		uloop_fd_add(&cl->sock, ULOOP_READ | ULOOP_WRITE | ULOOP_EDGE_TRIGGER);
		goto queue;
	}

	ubus_msg_free(ub);
	return;

queue:
	ub = ubus_msg_unshare(ub);
	ub->next = NULL;
	*cl->buf_tail = ub;
	cl->buf_tail = &ub->next;
}

static void handle_client_disconnect(struct ubus_client *cl)
{
	struct ubus_object *obj;

	while (!list_empty(&cl->objects)) {
		obj = list_first_entry(&cl->objects, struct ubus_object, list);
		ubusd_free_object(obj);
	}

	ubus_free_id(&clients, &cl->id);
	uloop_fd_delete(&cl->sock);
	close(cl->sock.fd);
	free(cl);
}

static void client_cb(struct uloop_fd *sock, unsigned int events)
{
	struct ubus_client *cl = container_of(sock, struct ubus_client, sock);
	struct ubus_msg_buf *ub;

	/* first try to tx more pending data */
	while (cl->buf_head) {
		struct ubus_msg_buf *ub = cl->buf_head;
		int written;

		written = ubus_msg_writev(sock->fd, ub, cl->buf_head_ofs);
		if (written < 0) {
			switch(errno) {
			case EINTR:
			case EAGAIN:
				break;
			default:
				goto disconnect;
			}
			break;
		}
		if (written == 0)
			break;

		cl->buf_head_ofs += written;
		if (cl->buf_head_ofs < ub->len + sizeof(ub->hdr))
			break;

		cl->buf_head_ofs = 0;
		cl->buf_head = ub->next;
		if (!cl->buf_head)
			cl->buf_tail = &cl->buf_head;
	}

	/* prevent further ULOOP_WRITE events if we don't have data
	 * to send anymore */
	if (!cl->buf_head && (events & ULOOP_WRITE))
		uloop_fd_add(sock, ULOOP_READ | ULOOP_EDGE_TRIGGER);

retry:
	if (!sock->eof && cl->pending_msg_offset < sizeof(cl->hdrbuf)) {
		int offset = cl->pending_msg_offset;
		int bytes;

		bytes = read(sock->fd, (char *)&cl->hdrbuf + offset, sizeof(cl->hdrbuf) - offset);
		if (bytes < 0)
			goto out;

		cl->pending_msg_offset += bytes;
		if (cl->pending_msg_offset < sizeof(cl->hdrbuf))
			goto out;

		if (blob_len(&cl->hdrbuf.data) + sizeof(cl->hdrbuf) > UBUS_MAX_MSGLEN)
			goto disconnect;

		cl->pending_msg = ubus_msg_new(NULL, blob_raw_len(&cl->hdrbuf.data), false);
		if (!cl->pending_msg)
			goto disconnect;

		memcpy(&cl->pending_msg->hdr, &cl->hdrbuf.hdr, sizeof(cl->hdrbuf.hdr));
		memcpy(cl->pending_msg->data, &cl->hdrbuf.data, sizeof(cl->hdrbuf.data));
	}

	ub = cl->pending_msg;
	if (ub) {
		int offset = cl->pending_msg_offset - sizeof(ub->hdr);
		int len = blob_raw_len(ub->data) - offset;
		int bytes = 0;

		if (len > 0) {
			bytes = read(sock->fd, (char *) ub->data + offset, len);
			if (bytes <= 0)
				goto out;
		}

		if (bytes < len) {
			cl->pending_msg_offset += bytes;
			goto out;
		}

		/* accept message */
		cl->pending_msg_offset = 0;
		cl->pending_msg = NULL;
		ubusd_receive_message(cl, ub);
		goto retry;
	}

out:
	if (!sock->eof || cl->buf_head)
		return;

disconnect:
	handle_client_disconnect(cl);
}

struct ubus_client *ubusd_get_client_by_id(uint32_t id)
{
	struct ubus_id *clid;

	clid = ubus_find_id(&clients, id);
	if (!clid)
		return NULL;

	return container_of(clid, struct ubus_client, id);
}

static bool get_next_connection(int fd)
{
	struct ubus_client *cl;
	int client_fd;

	client_fd = accept(fd, NULL, 0);
	if (client_fd < 0) {
		switch (errno) {
		case ECONNABORTED:
		case EINTR:
			return true;
		default:
			return false;
		}
	}

	cl = calloc(1, sizeof(*cl));
	cl->sock.fd = client_fd;

	INIT_LIST_HEAD(&cl->objects);
	if (!ubus_alloc_id(&clients, &cl->id))
		goto error;

	cl->sock.cb = client_cb;
	uloop_fd_add(&cl->sock, ULOOP_READ | ULOOP_EDGE_TRIGGER);
	if (!ubusd_send_hello(cl))
		goto error_free;

	return true;

error_free:
	ubus_free_id(&clients, &cl->id);
error:
	close(cl->sock.fd);
	free(cl);
	return true;
}

static void server_cb(struct uloop_fd *fd, unsigned int events)
{
	bool next;

	do {
		next = get_next_connection(fd->fd);
	} while (next);
}

static struct uloop_fd server_fd = {
	.cb = server_cb,
};

int main(int argc, char **argv)
{
	int ret = 0;

	signal(SIGPIPE, SIG_IGN);

	ubus_init_id_tree(&clients);

	uloop_init();

	unlink(UBUS_UNIX_SOCKET);
	server_fd.fd = usock(USOCK_UNIX | USOCK_SERVER | USOCK_NONBLOCK, UBUS_UNIX_SOCKET, NULL);
	if (server_fd.fd < 0) {
		perror("usock");
		ret = -1;
		goto out;
	}
	uloop_fd_add(&server_fd, ULOOP_READ | ULOOP_EDGE_TRIGGER);

	uloop_run();

out:
	uloop_done();
	return ret;
}
