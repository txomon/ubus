/*
 * Copyright (C) 2011 Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <unistd.h>

#include <libubox/blobmsg_json.h>
#include "libubus.h"

static struct ubus_context *ctx;
static struct ubus_subscriber test_event;
static struct blob_buf b;

/*
	Enum created to have policy ordered with names
*/
enum {
	HELLO_ID,
	HELLO_MSG,
	__HELLO_MAX
};

/*
	Policy stuff, what elements we will return in the JSON
*/
static const struct blobmsg_policy hello_policy[] = {
	[HELLO_ID] = { .name = "id", .type = BLOBMSG_TYPE_INT32 },
	[HELLO_MSG] = { .name = "msg", .type = BLOBMSG_TYPE_STRING },
};

/*
	The request???
*/
struct hello_request {
	struct ubus_request_data req;
	struct uloop_timeout timeout;
	char data[];
};

/*

*/
static void test_hello_reply(struct uloop_timeout *t)
{
	fprintf(stderr, "test_hello_reply Start\n");
	struct hello_request *req = container_of(t, struct hello_request, timeout);

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "message", req->data);
	ubus_send_reply(ctx, &req->req, b.head);
	ubus_complete_deferred_request(ctx, &req->req, 0);
	free(req);
	fprintf(stderr, "test_hello_reply End\n");
}

/**
	The hello callback is this one.

	@param ctx - The context??
	@param obj - The...??
	@param req -
	@param method - The name of the method that wants to be called
	@param msg -
*/
static int test_hello(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	struct hello_request *hreq;
	struct blob_attr *tb[__HELLO_MAX];
	const char *format = "%s received a message: %s";
	const char *msgstr = "(unknown)";

	fprintf(stderr, "test_hello Start\n");
	blobmsg_parse(hello_policy, ARRAY_SIZE(hello_policy), tb, blob_data(msg), blob_len(msg));

	if (tb[HELLO_MSG])
		msgstr = blobmsg_data(tb[HELLO_MSG]);

	hreq = calloc(1, sizeof(*hreq) + strlen(format) + strlen(obj->name) + strlen(msgstr) + 1);
	sprintf(hreq->data, format, obj->name, msgstr);
	ubus_defer_request(ctx, req, &hreq->req);
	hreq->timeout.cb = test_hello_reply;
	uloop_timeout_set(&hreq->timeout, 1000);

	fprintf(stderr, "test_hello End\n");
	return 0;
}

enum {
	WATCH_ID,
	WATCH_COUNTER,
	__WATCH_MAX
};

static const struct blobmsg_policy watch_policy[__WATCH_MAX] = {
	[WATCH_ID] = { .name = "id", .type = BLOBMSG_TYPE_INT32 },
	[WATCH_COUNTER] = { .name = "counter", .type = BLOBMSG_TYPE_INT32 },
};

static void
test_handle_remove(struct ubus_context *ctx, struct ubus_subscriber *s,
                   uint32_t id)
{
	fprintf(stderr, "test_handle_remove Start\n");
	fprintf(stderr, "Object %08x went away\n", id);
	fprintf(stderr, "test_handle_remove End\n");
}

/*
	When a method is called, displays method and params
*/
static int
test_notify(struct ubus_context *ctx, struct ubus_object *obj,
	    struct ubus_request_data *req, const char *method,
	    struct blob_attr *msg)
{
#if 0
	char *str;

	str = blobmsg_format_json(msg, true);
	fprintf(stderr, "Received notification '%s': %s\n", method, str);
	free(str);
#endif
	fprintf(stderr, "test_notify Start\n");
	fprintf(stderr, "test_notify End\n");
	return 0;
}

static int test_watch(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	fprintf(stderr, "test_watch Start\n");
	struct blob_attr *tb[__WATCH_MAX];
	int ret;

	blobmsg_parse(watch_policy, __WATCH_MAX, tb, blob_data(msg), blob_len(msg));
	if (!tb[WATCH_ID])
		return UBUS_STATUS_INVALID_ARGUMENT;

	test_event.remove_cb = test_handle_remove; // Action on remove
	test_event.cb = test_notify; // Say which is the objective for calls
	ret = ubus_subscribe(ctx, &test_event, blobmsg_get_u32(tb[WATCH_ID]));
	fprintf(stderr, "Watching object %08x: %s\n", blobmsg_get_u32(tb[WATCH_ID]), ubus_strerror(ret));
	fprintf(stderr, "test_watch End\n");
	return ret;
}

static const struct ubus_method test_methods[] = {
	UBUS_METHOD("hello", test_hello, hello_policy),
	UBUS_METHOD("watch", test_watch, watch_policy),
};

static struct ubus_object_type test_object_type =
	UBUS_OBJECT_TYPE("test", test_methods);

static struct ubus_object test_object = {
	.name = "test",
	.type = &test_object_type,
	.methods = test_methods,
	.n_methods = ARRAY_SIZE(test_methods),
};

static void server_main(void)
{
	fprintf(stderr, "server_main Start\n");
	int ret;

	ret = ubus_add_object(ctx, &test_object);
	if (ret)
		fprintf(stderr, "Failed to add object: %s\n", ubus_strerror(ret));

	ret = ubus_register_subscriber(ctx, &test_event);
	if (ret)
		fprintf(stderr, "Failed to add watch handler: %s\n", ubus_strerror(ret));

	uloop_run();
	fprintf(stderr, "server_main End\n");
}

int main(int argc, char **argv)
{
	const char *ubus_socket = NULL;
	int ch;

	while ((ch = getopt(argc, argv, "cs:")) != -1) {
		switch (ch) {
		case 's':
			ubus_socket = optarg;
			break;
		default:
			break;
		}
	}

	argc -= optind;
	argv += optind;

	uloop_init();

	ctx = ubus_connect(ubus_socket);
	if (!ctx) {
		fprintf(stderr, "Failed to connect to ubus\n");
		return -1;
	}

	ubus_add_uloop(ctx);

	server_main();

	ubus_free(ctx);
	uloop_done();

	return 0;
}
