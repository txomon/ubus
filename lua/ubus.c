/*
 * Copyright (C) 2012 Jo-Philipp Wich <jow@openwrt.org>
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
#include <libubus.h>
#include <libubox/blobmsg.h>
#include <lauxlib.h>


#define MODNAME        "ubus"
#define METANAME       MODNAME ".meta"


struct ubus_lua_connection {
	int timeout;
	struct blob_buf buf;
	struct ubus_context *ctx;
};


static int
ubus_lua_parse_blob(lua_State *L, struct blob_attr *attr, bool table);

static int
ubus_lua_parse_blob_array(lua_State *L, struct blob_attr *attr, int len, bool table)
{
	int rv;
	int idx = 1;
	int rem = len;
	struct blob_attr *pos;

	lua_newtable(L);

	__blob_for_each_attr(pos, attr, rem)
	{
		rv = ubus_lua_parse_blob(L, pos, table);

		if (rv > 1)
			lua_rawset(L, -3);
		else if (rv > 0)
			lua_rawseti(L, -2, idx++);
	}

	return 1;
}

static int
ubus_lua_parse_blob(lua_State *L, struct blob_attr *attr, bool table)
{
	int len;
	int off = 0;
	void *data;
	char buf[32];

	if (!blobmsg_check_attr(attr, false))
		return 0;

	if (table && blobmsg_name(attr)[0])
	{
		lua_pushstring(L, blobmsg_name(attr));
		off++;
	}

	data = blobmsg_data(attr);
	len = blobmsg_data_len(attr);

	switch (blob_id(attr))
	{
	case BLOBMSG_TYPE_BOOL:
		lua_pushboolean(L, *(uint8_t *)data);
		break;

	case BLOBMSG_TYPE_INT16:
		lua_pushinteger(L, be16_to_cpu(*(uint16_t *)data));
		break;

	case BLOBMSG_TYPE_INT32:
		lua_pushinteger(L, be32_to_cpu(*(uint32_t *)data));
		break;

	case BLOBMSG_TYPE_INT64:
		/* NB: Lua cannot handle 64bit, format value as string and push that */
		sprintf(buf, "%lld", (long long int) be64_to_cpu(*(uint64_t *)data));
		lua_pushstring(L, buf);
		break;

	case BLOBMSG_TYPE_STRING:
		lua_pushstring(L, data);
		break;

	case BLOBMSG_TYPE_ARRAY:
		ubus_lua_parse_blob_array(L, data, len, false);
		break;

	case BLOBMSG_TYPE_TABLE:
		ubus_lua_parse_blob_array(L, data, len, true);
		break;

	default:
		lua_pushnil(L);
		break;
	}

	return off + 1;
}


static bool
ubus_lua_format_blob_is_array(lua_State *L)
{
	lua_Integer prv = 0;
	lua_Integer cur = 0;

	/* Find out whether table is array-like */
	for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1))
	{
#ifdef LUA_TINT
		if (lua_type(L, -2) != LUA_TNUMBER && lua_type(L, -2) != LUA_TINT)
#else
		if (lua_type(L, -2) != LUA_TNUMBER)
#endif
		{
			lua_pop(L, 1);
			return false;
		}

		cur = lua_tointeger(L, -2);

		if ((cur - 1) != prv)
		{
			lua_pop(L, 1);
			return false;
		}

		prv = cur;
	}

	return true;
}

static int
ubus_lua_format_blob_array(lua_State *L, struct blob_buf *b, bool table);

static int
ubus_lua_format_blob(lua_State *L, struct blob_buf *b, bool table)
{
	void *c;
	bool rv = true;
	const char *key = table ? lua_tostring(L, -2) : NULL;

	switch (lua_type(L, -1))
	{
	case LUA_TBOOLEAN:
		blobmsg_add_u8(b, key, (uint8_t)lua_toboolean(L, -1));
		break;

#ifdef LUA_TINT
	case LUA_TINT:
#endif
	case LUA_TNUMBER:
		blobmsg_add_u32(b, key, (uint32_t)lua_tointeger(L, -1));
		break;

	case LUA_TSTRING:
	case LUA_TUSERDATA:
	case LUA_TLIGHTUSERDATA:
		blobmsg_add_string(b, key, lua_tostring(L, -1));
		break;

	case LUA_TTABLE:
		if (ubus_lua_format_blob_is_array(L))
		{
			c = blobmsg_open_array(b, key);
			rv = ubus_lua_format_blob_array(L, b, false);
			blobmsg_close_array(b, c);
		}
		else
		{
			c = blobmsg_open_table(b, key);
			rv = ubus_lua_format_blob_array(L, b, true);
			blobmsg_close_table(b, c);
		}
		break;

	default:
		rv = false;
		break;
	}

	return rv;
}

static int
ubus_lua_format_blob_array(lua_State *L, struct blob_buf *b, bool table)
{
	for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1))
	{
		if (!ubus_lua_format_blob(L, b, table))
		{
			lua_pop(L, 1);
			return false;
		}
	}

	return true;
}


static int
ubus_lua_connect(lua_State *L)
{
	struct ubus_lua_connection *c;
	const char *sockpath = luaL_optstring(L, 1, NULL);
	int timeout = luaL_optint(L, 2, 30);

	if ((c = lua_newuserdata(L, sizeof(*c))) != NULL &&
		(c->ctx = ubus_connect(sockpath)) != NULL)
	{
		ubus_add_uloop(c->ctx);
		c->timeout = timeout;
		memset(&c->buf, 0, sizeof(c->buf));
		luaL_getmetatable(L, METANAME);
		lua_setmetatable(L, -2);
		return 1;
	}

	/* NB: no errors from ubus_connect() yet */
	lua_pushnil(L);
	lua_pushinteger(L, UBUS_STATUS_UNKNOWN_ERROR);
	return 2;
}


static void
ubus_lua_objects_cb(struct ubus_context *c, struct ubus_object_data *o, void *p)
{
	lua_State *L = (lua_State *)p;

	lua_pushstring(L, o->path);
	lua_rawseti(L, -2, lua_objlen(L, -2) + 1);
}

static int
ubus_lua_objects(lua_State *L)
{
	int rv;
	struct ubus_lua_connection *c = luaL_checkudata(L, 1, METANAME);

	lua_newtable(L);
	rv = ubus_lookup(c->ctx, NULL, ubus_lua_objects_cb, L);

	if (rv != UBUS_STATUS_OK)
	{
		lua_pop(L, 1);
		lua_pushnil(L);
		lua_pushinteger(L, rv);
		return 2;
	}

	return 1;
}


static void
ubus_lua_signatures_cb(struct ubus_context *c, struct ubus_object_data *o, void *p)
{
	lua_State *L = (lua_State *)p;

	if (!o->signature)
		return;

	ubus_lua_parse_blob_array(L, blob_data(o->signature), blob_len(o->signature), true);
}

static int
ubus_lua_signatures(lua_State *L)
{
	int rv;
	struct ubus_lua_connection *c = luaL_checkudata(L, 1, METANAME);
	const char *path = luaL_checkstring(L, 2);

	rv = ubus_lookup(c->ctx, path, ubus_lua_signatures_cb, L);

	if (rv != UBUS_STATUS_OK)
	{
		lua_pop(L, 1);
		lua_pushnil(L);
		lua_pushinteger(L, rv);
		return 2;
	}

	return 1;
}


static void
ubus_lua_call_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	lua_State *L = (lua_State *)req->priv;

	if (!msg)
		lua_pushnil(L);

	ubus_lua_parse_blob_array(L, blob_data(msg), blob_len(msg), true);
}

static int
ubus_lua_call(lua_State *L)
{
	int rv;
	uint32_t id;
	struct ubus_lua_connection *c = luaL_checkudata(L, 1, METANAME);
	const char *path = luaL_checkstring(L, 2);
	const char *func = luaL_checkstring(L, 3);

	luaL_checktype(L, 4, LUA_TTABLE);
	blob_buf_init(&c->buf, 0);

	if (!ubus_lua_format_blob_array(L, &c->buf, true))
	{
		lua_pushnil(L);
		lua_pushinteger(L, UBUS_STATUS_INVALID_ARGUMENT);
		return 2;
	}

	rv = ubus_lookup_id(c->ctx, path, &id);

	if (rv)
	{
		lua_pushnil(L);
		lua_pushinteger(L, rv);
		return 2;
	}

	rv = ubus_invoke(c->ctx, id, func, c->buf.head, ubus_lua_call_cb, L, c->timeout * 1000);

	if (rv != UBUS_STATUS_OK)
	{
		lua_pop(L, 1);
		lua_pushnil(L);
		lua_pushinteger(L, rv);
		return 2;
	}

	return 1;
}


static int
ubus_lua__gc(lua_State *L)
{
	struct ubus_lua_connection *c = luaL_checkudata(L, 1, METANAME);

	if (c->ctx != NULL)
	{
		ubus_free(c->ctx);
		memset(c, 0, sizeof(*c));
	}

	return 0;
}

static const luaL_Reg ubus[] = {
	{ "connect", ubus_lua_connect },
	{ "objects", ubus_lua_objects },
	{ "signatures", ubus_lua_signatures },
	{ "call", ubus_lua_call },
	{ "close", ubus_lua__gc },
	{ "__gc", ubus_lua__gc },
	{ NULL, NULL },
};

/* avoid missing prototype warning */
int luaopen_ubus(lua_State *L);

int
luaopen_ubus(lua_State *L)
{
	/* create metatable */
	luaL_newmetatable(L, METANAME);

	/* metatable.__index = metatable */
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");

	/* fill metatable */
	luaL_register(L, NULL, ubus);
	lua_pop(L, 1);

	/* create module */
	luaL_register(L, MODNAME, ubus);

	return 0;
}
