#include "libubus.h"

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
	if (!msg)
		return;

	fprintf(stderr, "%s\n", blobmsg_format_json(msg, true));
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

int main(int argc, char **argv)
{
	static struct ubus_context *ctx;
	char *cmd;
	int ret;

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

		ret = ubus_lookup_id(ctx, argv[2], &id);
		if (!ret)
			ret = ubus_invoke(ctx, id, argv[3], NULL, receive_data, NULL);
	} else if (!strcmp(cmd, "listen")) {
		ret = ubus_invoke(ctx, UBUS_SYSTEM_OBJECT_EVENT, "listen", NULL, receive_data, NULL);
	} else {
		return usage(argv[0]);
	}

	if (ret)
		fprintf(stderr, "Failed: %s\n", ubus_strerror(ret));

	ubus_free(ctx);
	return ret;
}
