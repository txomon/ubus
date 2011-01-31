#include "libubus.h"

static struct blob_buf b;
static struct ubus_context *ctx;
static uint32_t objid;

static void receive_lookup(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr **attr, *cur;
	char *s;
	int rem;

	attr = ubus_parse_msg(msg);
	if (!attr[UBUS_ATTR_OBJID] || !attr[UBUS_ATTR_OBJPATH])
		return;

	fprintf(stderr, "'%s' @%08x\n",
		(char *) blob_data(attr[UBUS_ATTR_OBJPATH]),
		blob_get_int32(attr[UBUS_ATTR_OBJID]));

	if (!attr[UBUS_ATTR_SIGNATURE])
		return;

	blob_for_each_attr(cur, attr[UBUS_ATTR_SIGNATURE], rem) {
		s = blobmsg_format_json(cur, false);
		fprintf(stderr, "\t%s\n", s);
		free(s);
	}
}

static void store_objid(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr **attr;

	attr = ubus_parse_msg(msg);
	if (!attr[UBUS_ATTR_OBJID])
		return;

	objid = blob_get_int32(attr[UBUS_ATTR_OBJID]);
}

static uint32_t get_object(const char *name)
{
	struct ubus_request req;

	blob_buf_init(&b, 0);
	blob_put_string(&b, UBUS_ATTR_OBJPATH, name);
	ubus_start_request(ctx, &req, b.head, UBUS_MSG_LOOKUP, 0);
	req.data_cb = store_objid;
	if (ubus_complete_request(ctx, &req))
		return 0;

	return objid;
}

static int usage(char *prog)
{
	fprintf(stderr,
		"Usage: %s <command> [arguments...]\n"
		"Commands:\n"
		" - list [<path>]			List objects\n"
		" - call <path> <method> [<message>]	Call an object method\n"
		"\n", prog);
	return 1;
}

int main(int argc, char **argv)
{
	struct ubus_request req;
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
		blob_buf_init(&b, 0);

		if (argc == 3)
			blob_put_string(&b, UBUS_ATTR_OBJPATH, argv[2]);

		ubus_start_request(ctx, &req, b.head, UBUS_MSG_LOOKUP, 0);
		req.data_cb = receive_lookup;
	} else if (!strcmp(cmd, "call")) {
		if (argc < 4 || argc > 5)
			return usage(argv[0]);

		if (get_object(argv[2]) == 0) {
			fprintf(stderr, "Object not found\n");
			return 1;
		}

		blob_buf_init(&b, 0);
		blob_put_int32(&b, UBUS_ATTR_OBJID, objid);
		blob_put_string(&b, UBUS_ATTR_METHOD, argv[3]);
		ubus_start_request(ctx, &req, b.head, UBUS_MSG_INVOKE, objid);
	} else {
		return usage(argv[0]);
	}

	ret = ubus_complete_request(ctx, &req);
	if (ret)
		fprintf(stderr, "Failed: %s\n", ubus_strerror(ret));

	ubus_free(ctx);
	return 0;
}
