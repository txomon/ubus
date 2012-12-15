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

#include <sys/time.h>
#include <unistd.h>

#include "libubus.h"

static struct ubus_context *ctx;
static struct blob_buf b;

static void test_client_subscribe_cb(struct ubus_context *ctx, struct ubus_object *obj)
{
	fprintf(stderr, "Subscribers active: %d\n", obj->has_subscribers);
}

static struct ubus_object test_client_object = {
	.subscribe_cb = test_client_subscribe_cb,
};

static void test_client_notify_cb(struct uloop_timeout *timeout)
{
	static int counter = 0;
	int err;
	struct timeval tv1, tv2;
	int max = 1000;
	long delta;
	int i = 0;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "counter", counter++);

	gettimeofday(&tv1, NULL);
	for (i = 0; i < max; i++)
		err = ubus_notify(ctx, &test_client_object, "ping", b.head, 1000);
	gettimeofday(&tv2, NULL);
	if (err)
		fprintf(stderr, "Notify failed: %s\n", ubus_strerror(err));

	delta = (tv2.tv_sec - tv1.tv_sec) * 1000000 + (tv2.tv_usec - tv1.tv_usec);
	fprintf(stderr, "Avg time per iteration: %ld usec\n", delta / max);

	uloop_timeout_set(timeout, 1000);
}

static struct uloop_timeout notify_timer = {
	.cb = test_client_notify_cb,
};

static void client_main(void)
{
	uint32_t id;
	int ret;

	ret = ubus_add_object(ctx, &test_client_object);
	if (ret) {
		fprintf(stderr, "Failed to add_object object: %s\n", ubus_strerror(ret));
		return;
	}

	if (ubus_lookup_id(ctx, "test", &id)) {
		fprintf(stderr, "Failed to look up test object\n");
		return;
	}

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "id", test_client_object.id);
	ubus_invoke(ctx, id, "watch", b.head, NULL, 0, 3000);
	test_client_notify_cb(&notify_timer);
	uloop_run();
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

	client_main();

	ubus_free(ctx);
	uloop_done();

	return 0;
}
