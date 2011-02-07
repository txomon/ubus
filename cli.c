#include <unistd.h>

#include <libubox/blobmsg_json.h>
#include "libubus.h"

static struct blob_buf b;

static const char * const attr_types[] = {
	[BLOBMSG_TYPE_INT32] = "\"Integer\"",
	[BLOBMSG_TYPE_STRING] = "\"String\"",
};

static const char *format_type(void *priv, struct blob_attr *attr)
{
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

static void receive_lookup(struct ubus_context *ctx, struct ubus_object_data *obj, void *priv)
{
	struct blob_attr *cur;
	char *s;
	int rem;

	fprintf(stderr, "'%s' @%08x\n", obj->path, obj->id);

	if (!obj->signature)
		return;

	blob_for_each_attr(cur, obj->signature, rem) {
		s = blobmsg_format_json_with_cb(cur, false, format_type, NULL);
		fprintf(stderr, "\t%s\n", s);
		free(s);
	}
}

static void receive_data(struct ubus_request *req, int type, struct blob_attr *msg)
{
	char *str;
	if (!msg)
		return;

	str = blobmsg_format_json(msg, true);
	fprintf(stderr, "%s\n", str);
	free(str);
}


static void receive_event(struct ubus_context *ctx, struct ubus_event_handler *ev,
			  const char *type, struct blob_attr *msg)
{
	char *str;

	str = blobmsg_format_json(msg, true);
	printf("\"%s\": %s\n", type, str);
	free(str);
}

static int ubus_cli_listen(struct ubus_context *ctx, int argc, char **argv)
{
	static struct ubus_event_handler listener;
	const char *event;
	int ret = 0;

	memset(&listener, 0, sizeof(listener));
	listener.cb = receive_event;

	if (!argc) {
		event = "*";
		ret = ubus_register_event_handler(ctx, &listener, NULL);
	}

	for (;argc;argv++, argc--) {
		event = argv[0];
		ret = ubus_register_event_handler(ctx, &listener, argv[0]);
		if (ret)
			break;
	}

	if (ret) {
		fprintf(stderr, "Error while registering for event '%s': %s\n",
			event, ubus_strerror(ret));
	}

	uloop_init();
	ubus_add_uloop(ctx);
	uloop_run();
	uloop_done();

	return 0;
}

static int ubus_cli_send(struct ubus_context *ctx, int argc, char **argv)
{
	blob_buf_init(&b, 0);
	if (argc == 2 && !blobmsg_add_json_from_string(&b, argv[1])) {
		fprintf(stderr, "Failed to parse message data\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	return ubus_send_event(ctx, argv[0], b.head);
}

static int usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [<options>] <command> [arguments...]\n"
		"Options:\n"
		" -s <socket>:		Set the unix domain socket to connect to\n"
		"\n"
		"Commands:\n"
		" - list [<path>]			List objects\n"
		" - call <path> <method> [<message>]	Call an object method\n"
		" - listen [<path>...]			Listen for events\n"
		" - send <type> [<message>]		Send an event\n"
		"\n", prog);
	return 1;
}

int main(int argc, char **argv)
{
	const char *progname, *ubus_socket = NULL;
	static struct ubus_context *ctx;
	char *cmd;
	int ret = 0;
	int ch;

	progname = argv[0];

	while ((ch = getopt(argc, argv, "s:")) != -1) {
		switch (ch) {
		case 's':
			ubus_socket = optarg;
			break;
		default:
			return usage(progname);
		}
	}

	argc -= optind;
	argv += optind;

	ctx = ubus_connect(ubus_socket);
	if (!ctx) {
		fprintf(stderr, "Failed to connect to ubus\n");
		return -1;
	}

	cmd = argv[0];
	if (argc < 1)
		return usage(progname);

	argv++;
	argc--;

	if (!strcmp(cmd, "list")) {
		const char *path = NULL;

		if (argc == 1)
			path = argv[0];

		ret = ubus_lookup(ctx, path, receive_lookup, NULL);
	} else if (!strcmp(cmd, "call")) {
		uint32_t id;

		if (argc < 2 || argc > 3)
			return usage(progname);

		blob_buf_init(&b, 0);
		if (argc == 3 && !blobmsg_add_json_from_string(&b, argv[2])) {
			fprintf(stderr, "Failed to parse message data\n");
			goto out;
		}

		ret = ubus_lookup_id(ctx, argv[0], &id);
		if (!ret)
			ret = ubus_invoke(ctx, id, argv[1], b.head, receive_data, NULL);
	} else if (!strcmp(cmd, "listen")) {
		ret = ubus_cli_listen(ctx, argc, argv);
	} else if (!strcmp(cmd, "send")) {
		if (argc < 1 || argc > 2)
			return usage(progname);
		ret = ubus_cli_send(ctx, argc, argv);
	} else {
		return usage(progname);
	}

	if (ret)
		fprintf(stderr, "Failed: %s\n", ubus_strerror(ret));

out:
	ubus_free(ctx);
	return ret;
}
