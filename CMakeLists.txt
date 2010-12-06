cmake_minimum_required(VERSION 2.8)

PROJECT(ubus C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3)
ADD_LIBRARY(ubus STATIC libubus.c)

ADD_EXECUTABLE(ubusd ubusd.c ubusd_id.c ubusd_obj.c ubusd_proto.c)
TARGET_LINK_LIBRARIES(ubusd ubox)

ADD_EXECUTABLE(cli cli.c)
SET_TARGET_PROPERTIES(cli PROPERTIES OUTPUT_NAME ubus)
TARGET_LINK_LIBRARIES(cli ubus ubox)

ADD_EXECUTABLE(listener listener.c)
TARGET_LINK_LIBRARIES(listener ubus ubox)

