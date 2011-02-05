#include "ubusd.h"

static struct avl_tree patterns;
static LIST_HEAD(catch_all);
static struct ubus_object *event_obj;

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
		} pattern;
		struct {
			struct list_head list;
		} catchall;
	};
};

struct event_pattern {
	struct event_source evs;
	struct list_head list;
};

struct event_catchall {
	struct event_source evs;

	struct list_head list;
	struct ubus_object *obj;
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
	EVMSG_PATTERN,
	EVMSG_OBJECT,
	EVMSG_LAST,
};

static struct blobmsg_policy ev_policy[] = {
	[EVMSG_PATTERN] = { .name = "pattern", .type = BLOBMSG_TYPE_STRING },
	[EVMSG_OBJECT] = { .name = "object", .type = BLOBMSG_TYPE_INT32 },
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
	struct blob_attr *attr[EVMSG_LAST];
	const char *pattern;
	uint32_t id;

	blobmsg_parse(ev_policy, EVMSG_LAST, attr, blob_data(msg), blob_len(msg));
	if (!attr[EVMSG_OBJECT])
		return UBUS_STATUS_INVALID_ARGUMENT;

	id = blobmsg_get_u32(attr[EVMSG_OBJECT]);
	if (id < UBUS_SYSTEM_OBJECT_MAX)
		return UBUS_STATUS_PERMISSION_DENIED;

	obj = ubusd_find_object(id);
	if (!obj)
		return UBUS_STATUS_NOT_FOUND;

	if (obj->client != cl)
		return UBUS_STATUS_PERMISSION_DENIED;

	if (!attr[EVMSG_PATTERN])
		return ubusd_alloc_catchall(obj);

	pattern = blobmsg_data(attr[EVMSG_PATTERN]);
	ev = ubusd_alloc_event_source(obj, EVS_PATTERN, strlen(pattern) + 1);
	ev->pattern.avl.key = (void *) (ev + 1);
	strcpy(ev->pattern.avl.key, pattern);
	avl_insert(&patterns, &ev->pattern.avl);

	return 0;
}

static int ubusd_event_recv(struct ubus_client *cl, const char *method, struct blob_attr *msg)
{
	if (!strcmp(method, "register"))
		return ubusd_alloc_event_pattern(cl, msg);

	return UBUS_STATUS_INVALID_COMMAND;
}

void ubusd_event_init(void)
{
	ubus_init_string_tree(&patterns, true);
	event_obj = ubusd_create_object_internal(NULL, UBUS_SYSTEM_OBJECT_EVENT);
	event_obj->recv_msg = ubusd_event_recv;
}

