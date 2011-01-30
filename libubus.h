#include <libubox/list.h>
#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <stdint.h>
#include "ubusmsg.h"
#include "ubus_common.h"

struct ubus_msg_src;
struct ubus_object;
struct ubus_request;
struct ubus_request_data;

typedef void (*ubus_handler_t)(struct ubus_object *obj,
			       struct ubus_request_data *req,
			       const char *method, struct blob_attr *msg);
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

struct ubus_object {
	const char *name;
	uint32_t id;

	const char *path;
	struct ubus_object *parent;

	struct ubus_object_type *type;
};

struct ubus_context {
	struct list_head requests;
	struct list_head objects;
	struct uloop_fd sock;

	uint32_t local_id;
	uint32_t request_seq;

	struct {
		struct ubus_msghdr hdr;
		char data[UBUS_MAX_MSGLEN - sizeof(struct ubus_msghdr)];
	} msgbuf;
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

	uint32_t peer;
	uint32_t seq;

	ubus_data_handler_t data_cb;
	ubus_complete_handler_t complete_cb;

	void *priv;
};

#define BLOBMSG_END_TABLE	BLOBMSG_TYPE_UNSPEC

struct ubus_context *ubus_connect(const char *path);
void ubus_free(struct ubus_context *ctx);

const char *ubus_strerror(int error);

/* ----------- helpers for message handling ----------- */

struct blob_attr **ubus_parse_msg(struct blob_attr *msg);

/* ----------- raw request handling ----------- */

/* start a raw request */
int ubus_start_request(struct ubus_context *ctx, struct ubus_request *req,
		       struct blob_attr *msg, int cmd, uint32_t peer);

/* wait for a request to complete and return its status */
int ubus_complete_request(struct ubus_context *ctx, struct ubus_request *req);

/* complete a request asynchronously */
void ubus_complete_request_async(struct ubus_context *ctx,
				 struct ubus_request *req);

/* abort an asynchronous request */
void ubus_abort_request(struct ubus_context *ctx, struct ubus_request *req);

/* ----------- rpc ----------- */

/* invoke a method on a specific object */
int ubus_invoke(struct ubus_context *ctx, uint32_t obj, const char *method,
                struct blob_attr *msg, ubus_data_handler_t cb, void *priv);
int ubus_invoke_path(struct ubus_context *ctx, const char *path, const char *method,
                struct blob_attr *msg, ubus_data_handler_t cb, void *priv);

/* asynchronous version of ubus_invoke() */
void ubus_invoke_async(struct ubus_context *ctx, uint32_t obj, const char *method,
                       struct blob_attr *msg, struct ubus_request *req);
void ubus_invoke_path_async(struct ubus_context *ctx, const char *path, const char *method,
                       struct blob_attr *msg, struct ubus_request *req);

/* make an object visible to remote connections */
int ubus_publish(struct ubus_context *ctx, struct ubus_object *obj);


