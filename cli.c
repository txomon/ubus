#include <libubox/blobmsg_json.h>
#include "libubus.h"

static struct blob_buf b;

static void receive_lookup(struct ubus_context *ctx, struct ubus_object_data *obj, void *priv)
{
	struct blob_attr *cur;
	char *s;
	int rem;

	fprintf(stderr, "'%s' @%08x\n", obj->path, obj->id);

	if (!obj->signature)
		return;

	blob_for_each_attr(cur, obj->signature, rem) {
		s = blobmsg_format_json(cur, false);
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


static int usage(char *prog)
{
	fprintf(stderr,
		"Usage: %s <command> [arguments...]\n"
		"Commands:\n"
		" - list [<path>]			List objects\n"
		" - call <path> <method> [<message>]	Call an object method\n"
		" - listen [<path>...]			Listen for events\n"
		"\n", prog);
	return 1;
}

static void receive_event(struct ubus_context *ctx, struct ubus_event_handler *ev,
			  const char *type, struct blob_attr *msg)
{
	char *str;

	if (msg)
		str = blobmsg_format_json(msg, true);
	else
		str = "";

	fprintf(stderr, "\"%s\":{ %s }\n", type, str);
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

int main(int argc, char **argv)
{
	static struct ubus_context *ctx;
	char *cmd;
	int ret = 0;

	ctx = ubus_connect(NULL);
	if (!ctx) {
		fprintf(stderr, "Failed to connect to ubus\n");
		return -1;
	}

	cmd = argv[1];
	if (argc < 2)
		return usage(argv[0]);

	if (!strcmp(cmd, "list")) {
		const char *path = NULL;

		if (argc == 3)
			path = argv[2];

		ret = ubus_lookup(ctx, path, receive_lookup, NULL);
	} else if (!strcmp(cmd, "call")) {
		uint32_t id;

		if (argc < 4 || argc > 5)
			return usage(argv[0]);

		blob_buf_init(&b, 0);
		if (argc == 5 && !blobmsg_add_json_from_string(&b, argv[4])) {
			fprintf(stderr, "Failed to parse message data\n");
			goto out;
		}

		ret = ubus_lookup_id(ctx, argv[2], &id);
		if (!ret)
			ret = ubus_invoke(ctx, id, argv[3], b.head, receive_data, NULL);
	} else if (!strcmp(cmd, "listen")) {
		ret = ubus_cli_listen(ctx, argc - 2, argv + 2);
	} else {
		return usage(argv[0]);
	}

	if (ret)
		fprintf(stderr, "Failed: %s\n", ubus_strerror(ret));

out:
	ubus_free(ctx);
	return ret;
}
