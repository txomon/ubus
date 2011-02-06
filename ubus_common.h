#ifndef __UBUS_COMMON_H
#define __UBUS_COMMON_H

#define UBUS_UNIX_SOCKET "/var/run/ubus.sock"

#define UBUS_SIGNATURE_METHOD	(BLOBMSG_TYPE_LAST + 1)
#define UBUS_SIGNATURE_END		(BLOBMSG_TYPE_LAST + 2)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#define __init __attribute__((constructor))

#endif
