#include "ubusd.h"
#include "ubusd_obj.h"

struct avl_tree obj_types;
struct avl_tree objects;
struct avl_tree path;

static void ubus_unref_object_type(struct ubus_object_type *type)
{
	struct ubus_method *m;

	if (--type->refcount > 0)
		return;

	while (!list_empty(&type->methods)) {
		m = list_first_entry(&type->methods, struct ubus_method, list);
		list_del(&m->list);
		free(m);
	}

	ubus_free_id(&obj_types, &type->id);
	free(type);
}

static bool ubus_create_obj_method(struct ubus_object_type *type, struct blob_attr *attr)
{
	struct ubus_method *m;
	int bloblen = blob_raw_len(attr);

	m = calloc(1, sizeof(*m) + bloblen);
	if (!m)
		return false;

	list_add(&m->list, &type->methods);
	memcpy(m->data, attr, bloblen);
	m->name = blobmsg_name(m->data);

	return true;
}

static struct ubus_object_type *ubus_create_obj_type(struct blob_attr *sig)
{
	struct ubus_object_type *type;
	struct blob_attr *pos;
	int rem;

	type = calloc(1, sizeof(*type));
	type->refcount = 1;

	if (!ubus_alloc_id(&obj_types, &type->id, 0))
		goto error_free;

	INIT_LIST_HEAD(&type->methods);

	blob_for_each_attr(pos, sig, rem) {
		if (!blobmsg_check_attr(pos, true))
			goto error_unref;

		if (!ubus_create_obj_method(type, pos))
			goto error_unref;
	}

	return type;

error_unref:
	ubus_unref_object_type(type);
	return NULL;

error_free:
	free(type);
	return NULL;
}

static struct ubus_object_type *ubus_get_obj_type(uint32_t obj_id)
{
	struct ubus_object_type *type;
	struct ubus_id *id;

	id = ubus_find_id(&obj_types, obj_id);
	if (!id)
		return NULL;

	type = container_of(id, struct ubus_object_type, id);
	type->refcount++;
	return type;
}

struct ubus_object *ubusd_create_object_internal(struct ubus_object_type *type, uint32_t id)
{
	struct ubus_object *obj;

	obj = calloc(1, sizeof(*obj));
	if (!obj)
		return NULL;

	if (!ubus_alloc_id(&objects, &obj->id, id))
		goto error_free;

	obj->type = type;
	INIT_LIST_HEAD(&obj->list);
	INIT_LIST_HEAD(&obj->events);
	if (type)
		type->refcount++;

	return obj;

error_free:
	free(obj);
	return NULL;
}

struct ubus_object *ubusd_create_object(struct ubus_client *cl, struct blob_attr **attr)
{
	struct ubus_object *obj;
	struct ubus_object_type *type = NULL;

	if (attr[UBUS_ATTR_OBJTYPE])
		type = ubus_get_obj_type(blob_get_int32(attr[UBUS_ATTR_OBJTYPE]));
	else if (attr[UBUS_ATTR_SIGNATURE])
		type = ubus_create_obj_type(attr[UBUS_ATTR_SIGNATURE]);

	if (!!type ^ !!attr[UBUS_ATTR_OBJPATH])
		return NULL;

	obj = ubusd_create_object_internal(type, 0);
	if (type)
		ubus_unref_object_type(type);

	if (!obj)
		return NULL;

	if (attr[UBUS_ATTR_OBJPATH]) {
		obj->path.key = strdup(blob_data(attr[UBUS_ATTR_OBJPATH]));
		if (!obj->path.key)
			goto free;

		if (avl_insert(&path, &obj->path) != 0) {
			free(obj->path.key);
			obj->path.key = NULL;
			goto free;
		}
	}

	obj->client = cl;
	list_add(&obj->list, &cl->objects);

	return obj;

free:
	ubusd_free_object(obj);
	return NULL;
}

void ubusd_free_object(struct ubus_object *obj)
{
	ubusd_event_cleanup_object(obj);
	if (obj->path.key) {
		avl_delete(&path, &obj->path);
		free(obj->path.key);
	}
	if (!list_empty(&obj->list))
		list_del(&obj->list);
	ubus_free_id(&objects, &obj->id);
	if (obj->type)
		ubus_unref_object_type(obj->type);
	free(obj);
}

static void __init ubusd_obj_init(void)
{
	ubus_init_id_tree(&objects);
	ubus_init_id_tree(&obj_types);
	ubus_init_string_tree(&path, false);
	ubusd_event_init();
}
