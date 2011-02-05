#include "ubusd.h"

static struct avl_tree patterns;
static struct ubus_object *event_obj;

struct event_pattern {
	struct avl_node avl;

	struct ubus_object *obj;
	struct list_head list;

	const char *path;
};

static void ubusd_delete_event_pattern(struct event_pattern *ev)
{
	list_del(&ev->list);
	avl_delete(&patterns, &ev->avl);
	free(ev);
}

void ubusd_event_cleanup_object(struct ubus_object *obj)
{
	struct event_pattern *ev;

	while (!list_empty(&obj->event_patterns)) {
		ev = list_first_entry(&obj->event_patterns,
				      struct event_pattern, list);
		ubusd_delete_event_pattern(ev);
	}
}

static int ubusd_event_recv(struct ubus_client *cl, const char *method, struct blob_attr *msg)
{
	fprintf(stderr, "event: call to method '%s'\n", method);
	return 0;
}

void ubusd_event_init(void)
{
	ubus_init_string_tree(&patterns, true);
	event_obj = ubusd_create_object_internal(NULL, UBUS_SYSTEM_OBJECT_EVENT);
	event_obj->recv_msg = ubusd_event_recv;
}

