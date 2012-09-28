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

static struct blob_buf b;
static int timeout = 30;
static bool simple_output = false;
static int verbose = 0;

static const char *format_type(void *priv, struct blob_attr *attr)
{
	static const char * const attr_types[] = {
		[BLOBMSG_TYPE_INT8] = "\"Boolean\"",
		[BLOBMSG_TYPE_INT32] = "\"Integer\"",
		[BLOBMSG_TYPE_STRING] = "\"String\"",
		[BLOBMSG_TYPE_ARRAY] = "\"Array\"",
		[BLOBMSG_TYPE_TABLE] = "\"Table\"",
	};
	const char *type = NULL;
	int typeid;

	if (blob_id(attr) != BLOBMSG_TYPE_INT32)
		return NULL;

	typeid = blobmsg_get_u32(attr);
	if (typeid < ARRAY_SIZE(attr_types))
		type = attr_types[typeid];
	if (!type)
		type = "\"(unknown)\"";

	return type;
}

static void receive_list_result(struct ubus_context *ctx, struct ubus_object_data *obj, void *priv)
{
	struct blob_attr *cur;
	char *s;
	int rem;

	if (simple_output || !verbose) {
		printf("%s\n", obj->path);
		return;
	}

	printf("'%s' @%08x\n", obj->path, obj->id);

	if (!obj->signature)
		return;

	blob_for_each_attr(cur, obj->signature, rem) {
		s = blobmsg_format_json_with_cb(cur, false, format_type, NULL, -1);
		printf("\t%s\n", s);
		free(s);
	}
}

static void receive_call_result_data(struct ubus_request *req, int type, struct blob_attr *msg)
{
	char *str;
	if (!msg)
		return;

	str = blobmsg_format_json_indent(msg, true, simple_output ? -1 : 0);
	printf("%s\n", str);
	free(str);
}

static void receive_event(struct ubus_context *ctx, struct ubus_event_handler *ev,
			  const char *type, struct blob_attr *msg)
{
	char *str;

	str = blobmsg_format_json(msg, true);
	printf("{ \"%s\": %s }\n", type, str);
	free(str);
}

static int ubus_cli_list(struct ubus_context *ctx, int argc, char **argv)
{
	const char *path = NULL;

	if (argc > 1)
		return -2;

	if (argc == 1)
		path = argv[0];

	return ubus_lookup(ctx, path, receive_list_result, NULL);
}

static int ubus_cli_call(struct ubus_context *ctx, int argc, char **argv)
{
	uint32_t id;
	int ret;

	if (argc < 2 || argc > 3)
		return -2;

	blob_buf_init(&b, 0);
	if (argc == 3 && !blobmsg_add_json_from_string(&b, argv[2])) {
		if (!simple_output)
			fprintf(stderr, "Failed to parse message data\n");
		return -1;
	}

	ret = ubus_lookup_id(ctx, argv[0], &id);
	if (ret)
		return ret;

	return ubus_invoke(ctx, id, argv[1], b.head, receive_call_result_data, NULL, timeout * 1000);
}

static int ubus_cli_listen(struct ubus_context *ctx, int argc, char **argv)
{
	static struct ubus_event_handler listener;
	const char *event;
	int ret = 0;

	memset(&listener, 0, sizeof(listener));
	listener.cb = receive_event;

	if (argc > 0) {
		event = argv[0];
	} else {
		event = "*";
		argc = 1;
	}

	do {
		ret = ubus_register_event_handler(ctx, &listener, event);
		if (ret)
			break;

		argv++;
		argc--;
		if (argc <= 0)
			break;

		event = argv[0];
	} while (1);

	if (ret) {
		if (!simple_output)
			fprintf(stderr, "Error while registering for event '%s': %s\n",
				event, ubus_strerror(ret));
		return -1;
	}

	uloop_init();
	ubus_add_uloop(ctx);
	uloop_run();
	uloop_done();

	return 0;
}

static int ubus_cli_send(struct ubus_context *ctx, int argc, char **argv)
{
	if (argc < 1 || argc > 2)
		return -2;

	blob_buf_init(&b, 0);

	if (argc == 2 && !blobmsg_add_json_from_string(&b, argv[1])) {
		if (!simple_output)
			fprintf(stderr, "Failed to parse message data\n");
		return -1;
	}

	return ubus_send_event(ctx, argv[0], b.head);
}

static int usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [<options>] <command> [arguments...]\n"
		"Options:\n"
		" -s <socket>:		Set the unix domain socket to connect to\n"
		" -t <timeout>:		Set the timeout (in seconds) for a command to complete\n"
		" -S:			Use simplified output (for scripts)\n"
		" -v:			More verbose output\n"
		"\n"
		"Commands:\n"
		" - list [<path>]			List objects\n"
		" - call <path> <method> [<message>]	Call an object method\n"
		" - listen [<path>...]			Listen for events\n"
		" - send <type> [<message>]		Send an event\n"
		"\n", prog);
	return 1;
}


struct {
	const char *name;
	int (*cb)(struct ubus_context *ctx, int argc, char **argv);
} commands[] = {
	{ "list", ubus_cli_list },
	{ "call", ubus_cli_call },
	{ "listen", ubus_cli_listen },
	{ "send", ubus_cli_send },
};

int main(int argc, char **argv)
{
	const char *progname, *ubus_socket = NULL;
	static struct ubus_context *ctx;
	char *cmd;
	int ret = 0;
	int i, ch;

	progname = argv[0];

	while ((ch = getopt(argc, argv, "vs:t:S")) != -1) {
		switch (ch) {
		case 's':
			ubus_socket = optarg;
			break;
		case 't':
			timeout = atoi(optarg);
			break;
		case 'S':
			simple_output = true;
			break;
		case 'v':
			verbose++;
			break;
		default:
			return usage(progname);
		}
	}

	argc -= optind;
	argv += optind;

	cmd = argv[0];
	if (argc < 1)
		return usage(progname);

	ctx = ubus_connect(ubus_socket);
	if (!ctx) {
		if (!simple_output)
			fprintf(stderr, "Failed to connect to ubus\n");
		return -1;
	}

	argv++;
	argc--;

	ret = -2;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(commands[i].name, cmd) != 0)
			continue;

		ret = commands[i].cb(ctx, argc, argv);
		break;
	}

	if (ret > 0 && !simple_output)
		fprintf(stderr, "Command failed: %s\n", ubus_strerror(ret));
	else if (ret == -2)
		usage(progname);

	ubus_free(ctx);
	return ret;
}
