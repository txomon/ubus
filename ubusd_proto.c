#include <arpa/inet.h>
#include "ubusd.h"

struct blob_buf b;
static struct ubus_msg_buf *retmsg;
static int *retmsg_data;

static struct blob_attr *attrbuf[UBUS_ATTR_MAX];

typedef int (*ubus_cmd_cb)(struct ubus_client *cl, struct ubus_msg_buf *ub, struct blob_attr **attr);

static const struct blob_attr_info ubus_policy[UBUS_ATTR_MAX] = {
	[UBUS_ATTR_SIGNATURE] = { .type = BLOB_ATTR_NESTED },
	[UBUS_ATTR_OBJTYPE] = { .type = BLOB_ATTR_INT32 },
	[UBUS_ATTR_OBJPATH] = { .type = BLOB_ATTR_STRING },
	[UBUS_ATTR_OBJID] = { .type = BLOB_ATTR_INT32 },
	[UBUS_ATTR_STATUS] = { .type = BLOB_ATTR_INT32 },
};

static struct blob_attr **ubus_parse_msg(struct blob_attr *msg)
{
	blob_parse(msg, attrbuf, ubus_policy, UBUS_ATTR_MAX);
	return attrbuf;
}

static void ubus_msg_init(struct ubus_msg_buf *ub, uint8_t type, uint16_t seq, uint32_t peer)
{
	ub->hdr.version = 0;
	ub->hdr.type = type;
	ub->hdr.seq = seq;
	ub->hdr.peer = peer;
}

static struct ubus_msg_buf *ubus_msg_from_blob(bool shared)
{
	return ubus_msg_new(b.head, blob_raw_len(b.head), shared);
}

static struct ubus_msg_buf *ubus_reply_from_blob(struct ubus_msg_buf *ub, bool shared)
{
	struct ubus_msg_buf *new;

	new = ubus_msg_new(b.head, blob_raw_len(b.head), shared);
	if (!new)
		return NULL;

	ubus_msg_init(new, UBUS_MSG_DATA, ub->hdr.seq, ub->hdr.peer);
	return new;
}

bool ubusd_send_hello(struct ubus_client *cl)
{
	struct ubus_msg_buf *ub;

	blob_buf_init(&b, 0);
	ub = ubus_msg_from_blob(true);
	if (!ub)
		return false;

	ubus_msg_init(ub, UBUS_MSG_HELLO, 0, cl->id.id);
	ubus_msg_send(cl, ub, true);
	return true;
}

static int ubusd_send_pong(struct ubus_client *cl, struct ubus_msg_buf *ub, struct blob_attr **attr)
{
	ub->hdr.type = UBUS_MSG_DATA;
	ubus_msg_send(cl, ub, false);
	return 0;
}

static int ubusd_handle_remove_object(struct ubus_client *cl, struct ubus_msg_buf *ub, struct blob_attr **attr)
{
	struct ubus_object *obj;

	if (!attr[UBUS_ATTR_OBJID])
		return UBUS_STATUS_INVALID_ARGUMENT;

	obj = ubusd_find_object(blob_get_u32(attr[UBUS_ATTR_OBJID]));
	if (!obj)
		return UBUS_STATUS_NOT_FOUND;

	if (obj->client != cl)
		return UBUS_STATUS_PERMISSION_DENIED;

	blob_buf_init(&b, 0);
	blob_put_int32(&b, UBUS_ATTR_OBJID, obj->id.id);

	/* check if we're removing the object type as well */
	if (obj->type && obj->type->refcount == 1)
		blob_put_int32(&b, UBUS_ATTR_OBJTYPE, obj->type->id.id);

	ubusd_free_object(obj);

	ub = ubus_reply_from_blob(ub, true);
	if (!ub)
		return UBUS_STATUS_NO_DATA;

	ubus_msg_send(cl, ub, true);
	return 0;
}

static int ubusd_handle_add_object(struct ubus_client *cl, struct ubus_msg_buf *ub, struct blob_attr **attr)
{
	struct ubus_object *obj;

	obj = ubusd_create_object(cl, attr);
	if (!obj)
		return UBUS_STATUS_INVALID_ARGUMENT;

	blob_buf_init(&b, 0);
	blob_put_int32(&b, UBUS_ATTR_OBJID, obj->id.id);
	if (attr[UBUS_ATTR_SIGNATURE])
		blob_put_int32(&b, UBUS_ATTR_OBJTYPE, obj->type->id.id);

	ub = ubus_reply_from_blob(ub, true);
	if (!ub)
		return UBUS_STATUS_NO_DATA;

	ubus_msg_send(cl, ub, true);
	return 0;
}

static void ubusd_send_obj(struct ubus_client *cl, struct ubus_msg_buf *ub, struct ubus_object *obj)
{
	struct ubus_method *m;
	void *s;

	blob_buf_init(&b, 0);

	if (obj->path.key)
		blob_put_string(&b, UBUS_ATTR_OBJPATH, obj->path.key);
	blob_put_int32(&b, UBUS_ATTR_OBJID, obj->id.id);
	blob_put_int32(&b, UBUS_ATTR_OBJTYPE, obj->type->id.id);

	s = blob_nest_start(&b, UBUS_ATTR_SIGNATURE);
	list_for_each_entry(m, &obj->type->methods, list)
		blob_put(&b, blob_id(m->data), blob_data(m->data), blob_len(m->data));
	blob_nest_end(&b, s);

	ub = ubus_reply_from_blob(ub, true);
	if (!ub)
		return;

	ubus_msg_send(cl, ub, true);
}

static int ubusd_handle_lookup(struct ubus_client *cl, struct ubus_msg_buf *ub, struct blob_attr **attr)
{
	struct ubus_object *obj;
	char *objpath;
	bool wildcard = false;
	bool found = false;
	int len;

	if (!attr[UBUS_ATTR_OBJPATH]) {
		avl_for_each_element(&path, obj, path)
			ubusd_send_obj(cl, ub, obj);
		return 0;
	}

	objpath = blob_data(attr[UBUS_ATTR_OBJPATH]);
	len = strlen(objpath);
	if (objpath[len - 1] != '*') {
		obj = avl_find_element(&path, objpath, obj, path);
		if (!obj)
			return UBUS_STATUS_NOT_FOUND;

		ubusd_send_obj(cl, ub, obj);
		return 0;
	}

	objpath[--len] = 0;
	wildcard = true;

	obj = avl_find_ge_element(&path, objpath, obj, path);
	if (!obj)
		return UBUS_STATUS_NOT_FOUND;

	while (!strncmp(objpath, obj->path.key, len)) {
		found = true;
		ubusd_send_obj(cl, ub, obj);
		if (obj == avl_last_element(&path, obj, path))
			break;
		obj = avl_next_element(obj, path);
	}

	if (!found)
		return UBUS_STATUS_NOT_FOUND;

	return 0;
}

static int ubusd_handle_invoke(struct ubus_client *cl, struct ubus_msg_buf *ub, struct blob_attr **attr)
{
	struct ubus_object *obj = NULL;
	struct ubus_id *id;
	const char *method;

	if (!attr[UBUS_ATTR_METHOD] || !attr[UBUS_ATTR_OBJID])
		return UBUS_STATUS_INVALID_ARGUMENT;

	id = ubus_find_id(&objects, blob_get_u32(attr[UBUS_ATTR_OBJID]));
	if (!id)
		return UBUS_STATUS_NOT_FOUND;

	obj = container_of(id, struct ubus_object, id);

	method = blob_data(attr[UBUS_ATTR_METHOD]);

	if (!obj->client)
		return obj->recv_msg(cl, method, attr[UBUS_ATTR_DATA]);

	blob_buf_init(&b, 0);
	blob_put_int32(&b, UBUS_ATTR_OBJID, obj->id.id);
	blob_put_string(&b, UBUS_ATTR_METHOD, method);
	if (attr[UBUS_ATTR_DATA])
		blob_put(&b, UBUS_ATTR_DATA, blob_data(attr[UBUS_ATTR_DATA]),
			 blob_len(attr[UBUS_ATTR_DATA]));

	ubus_msg_free(ub);

	ub = ubus_reply_from_blob(ub, true);
	if (!ub)
		return UBUS_STATUS_NO_DATA;

	ub->hdr.type = UBUS_MSG_INVOKE;
	ub->hdr.peer = cl->id.id;
	ubus_msg_send(obj->client, ub, true);

	return -1;
}

static struct ubus_client *ubusd_get_client_by_id(uint32_t id)
{
	struct ubus_id *clid;

	clid = ubus_find_id(&clients, id);
	if (!clid)
		return NULL;

	return container_of(clid, struct ubus_client, id);
}

static int ubusd_handle_response(struct ubus_client *cl, struct ubus_msg_buf *ub, struct blob_attr **attr)
{
	struct ubus_object *obj;

	if (!attr[UBUS_ATTR_OBJID] ||
	    (ub->hdr.type == UBUS_MSG_STATUS && !attr[UBUS_ATTR_STATUS]) ||
	    (ub->hdr.type == UBUS_MSG_DATA && !attr[UBUS_ATTR_DATA]))
		goto error;

	obj = ubusd_find_object(blob_get_u32(attr[UBUS_ATTR_OBJID]));
	if (!obj)
		goto error;

	if (cl != obj->client)
		goto error;

	cl = ubusd_get_client_by_id(ub->hdr.peer);
	if (!cl)
		goto error;

	ub->hdr.peer = blob_get_u32(attr[UBUS_ATTR_OBJID]);
	ubus_msg_send(cl, ub, true);
	return -1;

error:
	ubus_msg_free(ub);
	return -1;
}

static const ubus_cmd_cb handlers[__UBUS_MSG_LAST] = {
	[UBUS_MSG_PING] = ubusd_send_pong,
	[UBUS_MSG_ADD_OBJECT] = ubusd_handle_add_object,
	[UBUS_MSG_REMOVE_OBJECT] = ubusd_handle_remove_object,
	[UBUS_MSG_LOOKUP] = ubusd_handle_lookup,
	[UBUS_MSG_INVOKE] = ubusd_handle_invoke,
	[UBUS_MSG_STATUS] = ubusd_handle_response,
	[UBUS_MSG_DATA] = ubusd_handle_response,
};

void ubusd_receive_message(struct ubus_client *cl, struct ubus_msg_buf *ub)
{
	ubus_cmd_cb cb = NULL;
	int ret;

	retmsg->hdr.seq = ub->hdr.seq;
	retmsg->hdr.peer = ub->hdr.peer;

	if (ub->hdr.type < __UBUS_MSG_LAST)
		cb = handlers[ub->hdr.type];

	if (cb)
		ret = cb(cl, ub, ubus_parse_msg(ub->data));
	else
		ret = UBUS_STATUS_INVALID_COMMAND;

	if (ret == -1)
		return;

	ubus_msg_free(ub);

	*retmsg_data = htonl(ret);
	ubus_msg_send(cl, retmsg, false);
}

static void __init ubusd_proto_init(void)
{
	blob_buf_init(&b, 0);
	blob_put_int32(&b, UBUS_ATTR_STATUS, 0);

	retmsg = ubus_msg_from_blob(false);
	if (!retmsg)
		exit(1);

	retmsg->hdr.type = UBUS_MSG_STATUS;
	retmsg_data = blob_data(blob_data(retmsg->data));
}
