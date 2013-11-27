# 1 "../libubus.h"
# 1 "<command-line>"
# 1 "../libubus.h"
# 22 "../libubus.h"
# 1 "../ubusmsg.h" 1
# 27 "../ubusmsg.h"
struct ubus_msghdr {
 uint8_t version;
 uint8_t type;
 uint16_t seq;
 uint32_t peer;
};
 struct list_head { ...; };

 struct avl_tree { ...; };
 struct uloop_fd { ...; };
 struct avl_node { ...; };
enum ubus_msg_type {
 UBUS_MSG_HELLO,
 UBUS_MSG_STATUS,
 UBUS_MSG_DATA,
 UBUS_MSG_PING,
 UBUS_MSG_LOOKUP,
 UBUS_MSG_INVOKE,
 UBUS_MSG_ADD_OBJECT,
 UBUS_MSG_REMOVE_OBJECT,
 UBUS_MSG_SUBSCRIBE,
 UBUS_MSG_UNSUBSCRIBE,
 UBUS_MSG_NOTIFY,
 __UBUS_MSG_LAST,
};

enum ubus_msg_attr {
 UBUS_ATTR_UNSPEC,
 UBUS_ATTR_STATUS,
 UBUS_ATTR_OBJPATH,
 UBUS_ATTR_OBJID,
 UBUS_ATTR_METHOD,
 UBUS_ATTR_OBJTYPE,
 UBUS_ATTR_SIGNATURE,
 UBUS_ATTR_DATA,
 UBUS_ATTR_TARGET,
 UBUS_ATTR_ACTIVE,
 UBUS_ATTR_NO_REPLY,
 UBUS_ATTR_SUBSCRIBERS,
 UBUS_ATTR_MAX,
};

enum ubus_msg_status {
 UBUS_STATUS_OK,
 UBUS_STATUS_INVALID_COMMAND,
 UBUS_STATUS_INVALID_ARGUMENT,
 UBUS_STATUS_METHOD_NOT_FOUND,
 UBUS_STATUS_NOT_FOUND,
 UBUS_STATUS_NO_DATA,
 UBUS_STATUS_PERMISSION_DENIED,
 UBUS_STATUS_TIMEOUT,
 UBUS_STATUS_NOT_SUPPORTED,
 UBUS_STATUS_UNKNOWN_ERROR,
 UBUS_STATUS_CONNECTION_FAILED,
 __UBUS_STATUS_LAST
};
# 23 "../libubus.h" 2
# 1 "../ubus_common.h" 1
# 24 "../libubus.h" 2



struct ubus_context;
struct ubus_msg_src;
struct ubus_object;
struct ubus_request;
struct ubus_request_data;
struct ubus_object_data;
struct ubus_event_handler;
struct ubus_subscriber;
struct ubus_notify_request;

static inline struct blob_attr *
ubus_msghdr_data(struct ubus_msghdr *hdr) ;

typedef void (*ubus_lookup_handler_t)(struct ubus_context *ctx,
          struct ubus_object_data *obj,
          void *priv);
typedef int (*ubus_handler_t)(struct ubus_context *ctx, struct ubus_object *obj,
         struct ubus_request_data *req,
         const char *method, struct blob_attr *msg);
typedef void (*ubus_state_handler_t)(struct ubus_context *ctx, struct ubus_object *obj);
typedef void (*ubus_remove_handler_t)(struct ubus_context *ctx,
          struct ubus_subscriber *obj, uint32_t id);
typedef void (*ubus_event_handler_t)(struct ubus_context *ctx, struct ubus_event_handler *ev,
         const char *type, struct blob_attr *msg);
typedef void (*ubus_data_handler_t)(struct ubus_request *req,
        int type, struct blob_attr *msg);
typedef void (*ubus_complete_handler_t)(struct ubus_request *req, int ret);
typedef void (*ubus_notify_complete_handler_t)(struct ubus_notify_request *req,
            int idx, int ret);
# 82 "../libubus.h"
struct ubus_method {
 const char *name;
 ubus_handler_t handler;

 const struct blobmsg_policy *policy;
 int n_policy;
};

struct ubus_object_type {
 const char *name;
 uint32_t id;

 const struct ubus_method *methods;
 int n_methods;
};

struct ubus_object {
 struct avl_node avl;

 const char *name;
 uint32_t id;

 const char *path;
 struct ubus_object_type *type;

 ubus_state_handler_t subscribe_cb;
 bool has_subscribers;

 const struct ubus_method *methods;
 int n_methods;
};

struct ubus_subscriber {
 struct ubus_object obj;

 ubus_handler_t cb;
 ubus_remove_handler_t remove_cb;
};

struct ubus_event_handler {
 struct ubus_object obj;

 ubus_event_handler_t cb;
};

struct ubus_context {
 struct list_head requests;
 struct avl_tree objects;
 struct list_head pending;

 struct uloop_fd sock;

 uint32_t local_id;
 uint16_t request_seq;
 int stack_depth;

 void (*connection_lost)(struct ubus_context *ctx);

 struct {
  struct ubus_msghdr hdr;
  char data[65536];
 } msgbuf;
};

struct ubus_object_data {
 uint32_t id;
 uint32_t type_id;
 const char *path;
 struct blob_attr *signature;
};

struct ubus_request_data {
 uint32_t object;
 uint32_t peer;
 uint16_t seq;
 bool deferred;
};

struct ubus_request {
 struct list_head list;

 struct list_head pending;
 int status_code;
 bool status_msg;
 bool blocked;
 bool cancelled;
 bool notify;

 uint32_t peer;
 uint16_t seq;

 ubus_data_handler_t raw_data_cb;
 ubus_data_handler_t data_cb;
 ubus_complete_handler_t complete_cb;

 struct ubus_context *ctx;
 void *priv;
};

struct ubus_notify_request {
 struct ubus_request req;

 ubus_notify_complete_handler_t status_cb;
 ubus_notify_complete_handler_t complete_cb;

 uint32_t pending;
 uint32_t id[...];
};

struct ubus_context *ubus_connect(const char *path);
int ubus_reconnect(struct ubus_context *ctx, const char *path);
void ubus_free(struct ubus_context *ctx);

const char *ubus_strerror(int error);

static inline void ubus_add_uloop(struct ubus_context *ctx);


static inline void ubus_handle_event(struct ubus_context *ctx);




int ubus_complete_request(struct ubus_context *ctx, struct ubus_request *req,
     int timeout);


void ubus_complete_request_async(struct ubus_context *ctx,
     struct ubus_request *req);


void ubus_abort_request(struct ubus_context *ctx, struct ubus_request *req);



int ubus_lookup(struct ubus_context *ctx, const char *path,
  ubus_lookup_handler_t cb, void *priv);

int ubus_lookup_id(struct ubus_context *ctx, const char *path, uint32_t *id);


int ubus_add_object(struct ubus_context *ctx, struct ubus_object *obj);


int ubus_remove_object(struct ubus_context *ctx, struct ubus_object *obj);


int ubus_register_subscriber(struct ubus_context *ctx, struct ubus_subscriber *obj);

static inline int
ubus_unregister_subscriber(struct ubus_context *ctx, struct ubus_subscriber *obj);

int ubus_subscribe(struct ubus_context *ctx, struct ubus_subscriber *obj, uint32_t id);
int ubus_unsubscribe(struct ubus_context *ctx, struct ubus_subscriber *obj, uint32_t id);




int ubus_invoke(struct ubus_context *ctx, uint32_t obj, const char *method,
  struct blob_attr *msg, ubus_data_handler_t cb, void *priv,
  int timeout);


int ubus_invoke_async(struct ubus_context *ctx, uint32_t obj, const char *method,
        struct blob_attr *msg, struct ubus_request *req);


int ubus_send_reply(struct ubus_context *ctx, struct ubus_request_data *req,
      struct blob_attr *msg);

static inline void ubus_defer_request(struct ubus_context *ctx,
          struct ubus_request_data *req,
          struct ubus_request_data *new_req);

void ubus_complete_deferred_request(struct ubus_context *ctx,
        struct ubus_request_data *req, int ret);





int ubus_notify(struct ubus_context *ctx, struct ubus_object *obj,
  const char *type, struct blob_attr *msg, int timeout);

int ubus_notify_async(struct ubus_context *ctx, struct ubus_object *obj,
        const char *type, struct blob_attr *msg,
        struct ubus_notify_request *req);




int ubus_send_event(struct ubus_context *ctx, const char *id,
      struct blob_attr *data);

int ubus_register_event_handler(struct ubus_context *ctx,
    struct ubus_event_handler *ev,
    const char *pattern);

static inline int ubus_unregister_event_handler(struct ubus_context *ctx,
      struct ubus_event_handler *ev);
