#include <libubox/avl.h>
#include <libubox/list.h>
#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <stdint.h>
#include "ubusmsg.h"
#include "ubus_common.h"

struct ubus_context;
struct ubus_msg_src;
struct ubus_object;
struct ubus_request;
struct ubus_request_data;
struct ubus_object_data;
struct ubus_event_handler;

typedef void (*ubus_lookup_handler_t)(struct ubus_context *ctx,
				      struct ubus_object_data *obj,
				      void *priv);
typedef int (*ubus_handler_t)(struct ubus_context *ctx, struct ubus_object *obj,
			      struct ubus_request_data *req,
			      const char *method, struct blob_attr *msg);
typedef void (*ubus_event_handler_t)(struct ubus_context *ctx, struct ubus_event_handler *ev,
				     const char *type, struct blob_attr *msg);
typedef void (*ubus_data_handler_t)(struct ubus_request *req,
				    int type, struct blob_attr *msg);
typedef void (*ubus_complete_handler_t)(struct ubus_request *req, int ret);


#define UBUS_SIGNATURE(_type, _name)	{ .type = _type, .name = _name }

#define UBUS_METHOD_START(_name)		UBUS_SIGNATURE(UBUS_SIGNATURE_METHOD, _name)
#define UBUS_METHOD_END()			UBUS_SIGNATURE(UBUS_SIGNATURE_END, NULL)

#define UBUS_FIELD(_type, _name)		UBUS_SIGNATURE(BLOBMSG_TYPE_ ## _type, _name)

#define UBUS_ARRAY(_name)			UBUS_FIELD(ARRAY, _name)
#define UBUS_ARRAY_END()			UBUS_SIGNATURE(UBUS_SIGNATURE_END, NULL)

#define UBUS_TABLE_START(_name)			UBUS_FIELD(TABLE, _name)
#define UBUS_TABLE_END()			UBUS_SIGNATURE(UBUS_SIGNATURE_END, NULL)

#define UBUS_OBJECT_TYPE(_name, _signature)		\
	{						\
		.name = _name,				\
		.id = 0,				\
		.n_signature = ARRAY_SIZE(_signature),	\
		.signature = _signature			\
	}

struct ubus_signature {
	enum blobmsg_type type;
	const char *name;
};

struct ubus_object_type {
	const char *name;
	uint32_t id;
	int n_signature;
	const struct ubus_signature *signature;
};

struct ubus_method {
	const char *name;
	ubus_handler_t handler;
};

struct ubus_object {
	struct avl_node avl;

	const char *name;
	uint32_t id;

	const char *path;
	struct ubus_object_type *type;

	const struct ubus_method *methods;
	int n_methods;
};

struct ubus_event_handler {
	struct ubus_object obj;

	ubus_event_handler_t cb;
};

struct ubus_context {
	struct list_head requests;
	struct avl_tree objects;

	struct uloop_fd sock;

	uint32_t local_id;
	uint32_t request_seq;

	void (*connection_lost)(struct ubus_context *ctx);

	struct {
		struct ubus_msghdr hdr;
		char data[UBUS_MAX_MSGLEN];
	} msgbuf;
};

struct ubus_object_data {
	uint32_t id;
	uint32_t type_id;
	const char *path;
	struct blob_attr *signature;
};

struct ubus_request_data {
	uint32_t object;
	uint32_t peer;
	uint32_t seq;
};

struct ubus_request {
	struct list_head list;

	struct list_head pending;
	bool status_msg;
	int status_code;
	bool blocked;
	bool cancelled;

	uint32_t peer;
	uint32_t seq;

	ubus_data_handler_t raw_data_cb;
	ubus_data_handler_t data_cb;
	ubus_complete_handler_t complete_cb;

	struct ubus_context *ctx;
	void *priv;
};


struct ubus_context *ubus_connect(const char *path);
void ubus_free(struct ubus_context *ctx);

const char *ubus_strerror(int error);

static inline void ubus_add_uloop(struct ubus_context *ctx)
{
	uloop_fd_add(&ctx->sock, ULOOP_EDGE_TRIGGER | ULOOP_BLOCKING | ULOOP_READ);
}

/* ----------- raw request handling ----------- */

/* wait for a request to complete and return its status */
int ubus_complete_request(struct ubus_context *ctx, struct ubus_request *req);

/* complete a request asynchronously */
void ubus_complete_request_async(struct ubus_context *ctx,
				 struct ubus_request *req);

/* abort an asynchronous request */
void ubus_abort_request(struct ubus_context *ctx, struct ubus_request *req);

/* ----------- objects ----------- */

int ubus_lookup(struct ubus_context *ctx, const char *path,
		ubus_lookup_handler_t cb, void *priv);

int ubus_lookup_id(struct ubus_context *ctx, const char *path, uint32_t *id);

/* make an object visible to remote connections */
int ubus_add_object(struct ubus_context *ctx, struct ubus_object *obj);

/* remove the object from the ubus connection */
int ubus_remove_object(struct ubus_context *ctx, struct ubus_object *obj);

/* ----------- rpc ----------- */

/* invoke a method on a specific object */
int ubus_invoke(struct ubus_context *ctx, uint32_t obj, const char *method,
                struct blob_attr *msg, ubus_data_handler_t cb, void *priv);

/* asynchronous version of ubus_invoke() */
int ubus_invoke_async(struct ubus_context *ctx, uint32_t obj, const char *method,
                      struct blob_attr *msg, struct ubus_request *req);

/* send a reply to an incoming object method call */
int ubus_send_reply(struct ubus_context *ctx, struct ubus_request_data *req,
		    struct blob_attr *msg);

/* ----------- events ----------- */

int ubus_send_event(struct ubus_context *ctx, const char *id,
		    struct blob_attr *data);

int ubus_register_event_handler(struct ubus_context *ctx,
				struct ubus_event_handler *ev,
				const char *pattern);

static inline int ubus_unregister_event_handler(struct ubus_context *ctx,
						struct ubus_event_handler *ev)
{
    return ubus_remove_object(ctx, &ev->obj);
}
