#include <arpa/inet.h>
#include "ubusd.h"

static struct avl_tree patterns;
static LIST_HEAD(catch_all);
static struct ubus_object *event_obj;
static int event_seq = 0;
static int obj_event_seq = 0;

enum evs_type {
	EVS_PATTERN,
	EVS_CATCHALL
};

struct event_source {
	struct list_head list;
	struct ubus_object *obj;
	enum evs_type type;
	union {
		struct {
			struct avl_node avl;
			bool partial;
		} pattern;
		struct {
			struct list_head list;
		} catchall;
	};
};

static void ubusd_delete_event_source(struct event_source *evs)
{
	list_del(&evs->list);
	switch (evs->type) {
	case EVS_PATTERN:
		avl_delete(&patterns, &evs->pattern.avl);
		break;
	case EVS_CATCHALL:
		list_del(&evs->catchall.list);
		break;
	}
	free(evs);
}

void ubusd_event_cleanup_object(struct ubus_object *obj)
{
	struct event_source *ev;

	while (!list_empty(&obj->events)) {
		ev = list_first_entry(&obj->events, struct event_source, list);
		ubusd_delete_event_source(ev);
	}
}

enum {
	EVREG_PATTERN,
	EVREG_OBJECT,
	EVREG_LAST,
};

static struct blobmsg_policy evr_policy[] = {
	[EVREG_PATTERN] = { .name = "pattern", .type = BLOBMSG_TYPE_STRING },
	[EVREG_OBJECT] = { .name = "object", .type = BLOBMSG_TYPE_INT32 },
};


static struct event_source *ubusd_alloc_event_source(struct ubus_object *obj, enum evs_type type, int datalen)
{
	struct event_source *evs;

	evs = calloc(1, sizeof(*evs) + datalen);
	list_add(&evs->list, &obj->events);
	evs->obj = obj;
	evs->type = type;
	return evs;
}

static int ubusd_alloc_catchall(struct ubus_object *obj)
{
	struct event_source *evs;

	evs = ubusd_alloc_event_source(obj, EVS_CATCHALL, 0);
	list_add(&evs->catchall.list, &catch_all);

	return 0;
}

static int ubusd_alloc_event_pattern(struct ubus_client *cl, struct blob_attr *msg)
{
	struct event_source *ev;
	struct ubus_object *obj;
	struct blob_attr *attr[EVREG_LAST];
	char *pattern;
	uint32_t id;
	bool partial = false;
	int len;

	blobmsg_parse(evr_policy, EVREG_LAST, attr, blob_data(msg), blob_len(msg));
	if (!attr[EVREG_OBJECT])
		return UBUS_STATUS_INVALID_ARGUMENT;

	id = blobmsg_get_u32(attr[EVREG_OBJECT]);
	if (id < UBUS_SYSTEM_OBJECT_MAX)
		return UBUS_STATUS_PERMISSION_DENIED;

	obj = ubusd_find_object(id);
	if (!obj)
		return UBUS_STATUS_NOT_FOUND;

	if (obj->client != cl)
		return UBUS_STATUS_PERMISSION_DENIED;

	if (!attr[EVREG_PATTERN])
		return ubusd_alloc_catchall(obj);

	pattern = blobmsg_data(attr[EVREG_PATTERN]);

	len = strlen(pattern);
	if (pattern[len - 1] == '*') {
		partial = true;
		pattern[len - 1] = 0;
		len--;
	}

	ev = ubusd_alloc_event_source(obj, EVS_PATTERN, len + 1);
	ev->pattern.partial = partial;
	ev->pattern.avl.key = (void *) (ev + 1);
	strcpy(ev->pattern.avl.key, pattern);
	avl_insert(&patterns, &ev->pattern.avl);

	return 0;
}

typedef struct ubus_msg_buf *(*event_fill_cb)(void *priv, const char *id);

static void ubusd_send_event_msg(struct ubus_msg_buf **ub, struct ubus_client *cl,
				 struct ubus_object *obj, const char *id,
				 event_fill_cb fill_cb, void *cb_priv)
{
	uint32_t *objid_ptr;

	/* do not loop back events */
	if (obj->client == cl)
	    return;

	/* do not send duplicate events */
	if (obj->event_seen == obj_event_seq)
		return;

	obj->event_seen = obj_event_seq;

	if (!*ub) {
		*ub = fill_cb(cb_priv, id);
		(*ub)->hdr.type = UBUS_MSG_INVOKE;
		(*ub)->hdr.peer = 0;
	}

	objid_ptr = blob_data(blob_data((*ub)->data));
	*objid_ptr = htonl(obj->id.id);

	(*ub)->hdr.seq = ++event_seq;
	ubus_msg_send(obj->client, *ub, false);
}

bool strmatch_len(const char *s1, const char *s2, int *len)
{
	for (*len = 0; s1[*len] == s2[*len]; (*len)++)
		if (!s1[*len])
			return true;

	return false;
}

static int ubusd_send_event(struct ubus_client *cl, const char *id,
			    event_fill_cb fill_cb, void *cb_priv)
{
	struct ubus_msg_buf *ub = NULL;
	struct event_source *ev;
	int match_len = 0;

	list_for_each_entry(ev, &catch_all, catchall.list)
		ubusd_send_event_msg(&ub, cl, ev->obj, id, fill_cb, cb_priv);

	obj_event_seq++;

	/*
	 * Since this tree is sorted alphabetically, we can only expect to find
	 * matching entries as long as the number of matching characters
	 * between the pattern string and our string is monotonically increasing.
	 */
	avl_for_each_element(&patterns, ev, pattern.avl) {
		const char *key = ev->pattern.avl.key;
		int cur_match_len;
		bool full_match;

		full_match = strmatch_len(id, key, &cur_match_len);
		if (cur_match_len < match_len)
			break;

		match_len = cur_match_len;

		if (!full_match) {
			if (!ev->pattern.partial)
				continue;

			if (match_len != strlen(key))
				continue;
		}

		ubusd_send_event_msg(&ub, cl, ev->obj, id, fill_cb, cb_priv);
	}

	if (ub)
		ubus_msg_free(ub);

	return 0;
}

enum {
	EVMSG_ID,
	EVMSG_DATA,
	EVMSG_LAST,
};

static struct blobmsg_policy ev_policy[] = {
	[EVMSG_ID] = { .name = "id", .type = BLOBMSG_TYPE_STRING },
	[EVMSG_DATA] = { .name = "data", .type = BLOBMSG_TYPE_TABLE },
};

static struct ubus_msg_buf *
ubusd_create_event_from_msg(void *priv, const char *id)
{
	struct blob_attr *msg = priv;

	blob_buf_init(&b, 0);
	blob_put_int32(&b, UBUS_ATTR_OBJID, 0);
	blob_put_string(&b, UBUS_ATTR_METHOD, id);
	blob_put(&b, UBUS_ATTR_DATA, blobmsg_data(msg), blobmsg_data_len(msg));

	return ubus_msg_new(b.head, blob_raw_len(b.head), true);
}

static int ubusd_forward_event(struct ubus_client *cl, struct blob_attr *msg)
{
	struct blob_attr *data;
	struct blob_attr *attr[EVMSG_LAST];
	const char *id;

	blobmsg_parse(ev_policy, EVMSG_LAST, attr, blob_data(msg), blob_len(msg));
	if (!attr[EVMSG_ID] || !attr[EVMSG_DATA])
		return UBUS_STATUS_INVALID_ARGUMENT;

	id = blobmsg_data(attr[EVMSG_ID]);
	data = attr[EVMSG_DATA];

	if (!strncmp(id, "ubus.", 5))
		return UBUS_STATUS_PERMISSION_DENIED;

	return ubusd_send_event(cl, id, ubusd_create_event_from_msg, data);
}

static int ubusd_event_recv(struct ubus_client *cl, const char *method, struct blob_attr *msg)
{
	if (!strcmp(method, "register"))
		return ubusd_alloc_event_pattern(cl, msg);

	if (!strcmp(method, "send"))
		return ubusd_forward_event(cl, msg);

	return UBUS_STATUS_INVALID_COMMAND;
}

static struct ubus_msg_buf *
ubusd_create_object_event_msg(void *priv, const char *id)
{
	struct ubus_object *obj = priv;
	void *s;

	blob_buf_init(&b, 0);
	blob_put_int32(&b, UBUS_ATTR_OBJID, 0);
	blob_put_string(&b, UBUS_ATTR_METHOD, id);
	s = blob_nest_start(&b, UBUS_ATTR_DATA);
	blobmsg_add_u32(&b, "id", obj->id.id);
	blobmsg_add_string(&b, "path", obj->path.key);
	blob_nest_end(&b, s);

	return ubus_msg_new(b.head, blob_raw_len(b.head), true);
}

void ubusd_send_obj_event(struct ubus_object *obj, bool add)
{
	const char *id = add ? "ubus.object.add" : "ubus.object.remove";

	ubusd_send_event(NULL, id, ubusd_create_object_event_msg, obj);
}

void ubusd_event_init(void)
{
	ubus_init_string_tree(&patterns, true);
	event_obj = ubusd_create_object_internal(NULL, UBUS_SYSTEM_OBJECT_EVENT);
	event_obj->recv_msg = ubusd_event_recv;
}

