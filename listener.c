#include "libubus.h"

static struct ubus_context *ctx;
struct blob_buf b;

static const struct ubus_signature test_object_sig[] = {
	UBUS_METHOD_START("hello"),
	  UBUS_ARRAY("test"),
		UBUS_TABLE_START(NULL),
		  UBUS_FIELD(INT32, "id"),
		  UBUS_FIELD(STRING, "msg"),
		UBUS_TABLE_END(),
	UBUS_METHOD_END(),
};

static struct ubus_object_type test_object_type =
	UBUS_OBJECT_TYPE("test", test_object_sig);

static int test_hello(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "message", "Hello, world!\n");
	ubus_send_reply(ctx, req, b.head);
	return 0;
}

static const struct ubus_method test_methods[] = {
	{ .name = "hello", .handler = test_hello },
};

static struct ubus_object test_object = {
	.name = "test",
	.type = &test_object_type,
	.methods = test_methods,
	.n_methods = ARRAY_SIZE(test_methods),
};

static struct ubus_object test_object2 = {
	.name = "test2",
	.type = &test_object_type,
	.methods = test_methods,
	.n_methods = ARRAY_SIZE(test_methods),
};

int main(int argc, char **argv)
{
	int ret;

	ctx = ubus_connect(NULL);
	if (!ctx) {
		fprintf(stderr, "Failed to connect to ubus\n");
		return -1;
	}

	fprintf(stderr, "Connected as ID 0x%08x\n", ctx->local_id);

	fprintf(stderr, "Publishing object\n");
	ret = ubus_publish(ctx, &test_object);
	if (ret)
		fprintf(stderr, "Failed to publish object: %s\n", ubus_strerror(ret));
	else {
		fprintf(stderr, "Object ID: %08x\n", test_object.id);
		fprintf(stderr, "Object Type ID: %08x\n", test_object.type->id);
	}

	fprintf(stderr, "Publishing object\n");
	ret = ubus_publish(ctx, &test_object2);
	if (ret)
		fprintf(stderr, "Failed to publish object: %s\n", ubus_strerror(ret));
	else {
		fprintf(stderr, "Object ID: %08x\n", test_object2.id);
		fprintf(stderr, "Object Type ID: %08x\n", test_object2.type->id);
	}
	uloop_init();
	uloop_fd_add(&ctx->sock, ULOOP_READ | ULOOP_EDGE_TRIGGER);
	uloop_run();

	ubus_free(ctx);
	return 0;
}
