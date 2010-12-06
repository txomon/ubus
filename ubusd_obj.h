#ifndef __UBUSD_OBJ_H
#define __UBUSD_OBJ_H

#include "ubusd_id.h"

extern struct avl_tree obj_types;
extern struct avl_tree objects;
extern struct avl_tree path;

struct ubus_client;
struct ubus_msg_buf;

struct ubus_object_type {
	struct ubus_id id;
	int refcount;
	struct list_head methods;
};

struct ubus_method {
	struct list_head list;
	const char *name;
	struct blob_attr data[];
};

struct ubus_object {
	struct ubus_id id;
	struct list_head list;

	struct ubus_object_type *type;

	struct avl_node path;
};

struct ubus_object *ubusd_create_object(struct ubus_client *cl, struct blob_attr **attr);
void ubusd_free_object(struct ubus_object *obj);

#endif
