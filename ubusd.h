#ifndef __UBUSD_H
#define __UBUSD_H

#include <libubox/list.h>
#include <libubox/uloop.h>
#include <libubox/blobmsg.h>
#include "ubus_common.h"
#include "ubusd_id.h"
#include "ubusd_obj.h"
#include "ubusmsg.h"

#define UBUS_UNIX_SOCKET "./ubus.sock"
#define UBUSD_CLIENT_BACKLOG	32
#define UBUS_OBJ_HASH_BITS	4

struct ubus_msg_buf {
	struct ubus_msg_buf *next;
	uint32_t refcount; /* ~0: uses external data buffer */
	struct ubus_msghdr hdr;
	struct blob_attr *data;
	int len;
};

struct ubus_client {
	struct ubus_id id;
	struct uloop_fd sock;

	struct {
		struct ubus_msghdr hdr;
		struct blob_attr data;
	} hdrbuf;

	struct list_head objects;

	int pending_msg_offset;
	struct ubus_msg_buf *pending_msg;

	unsigned int buf_head_ofs;
	struct ubus_msg_buf *buf_head;
	struct ubus_msg_buf **buf_tail;

	struct ubus_msg_buf *requests[UBUSD_CLIENT_BACKLOG];
	unsigned int req_head, req_tail;
};

struct ubus_path {
	struct list_head list;
	const char name[];
};

struct ubus_msg_buf *ubus_msg_new(void *data, int len, bool shared);
void ubus_msg_send(struct ubus_client *cl, struct ubus_msg_buf *ub);
struct ubus_msg_buf *ubus_msg_ref(struct ubus_msg_buf *ub);
void ubus_msg_free(struct ubus_msg_buf *ub);

struct ubus_client *ubusd_get_client_by_id(uint32_t id);

void ubusd_receive_message(struct ubus_client *cl, struct ubus_msg_buf *ub);
bool ubusd_send_hello(struct ubus_client *cl);

struct blob_attr **ubus_parse_msg(struct blob_attr *msg);


#endif
