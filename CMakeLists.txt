cmake_minimum_required(VERSION 2.6)

PROJECT(ubus C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations)

OPTION(BUILD_LUA "build Lua plugin" ON)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
ENDIF()

ADD_LIBRARY(ubus SHARED libubus.c libubus-io.c libubus-obj.c libubus-sub.c libubus-req.c)
TARGET_LINK_LIBRARIES(ubus ubox)

ADD_EXECUTABLE(ubusd ubusd.c ubusd_id.c ubusd_obj.c ubusd_proto.c ubusd_event.c)
TARGET_LINK_LIBRARIES(ubusd ubox)

ADD_EXECUTABLE(cli cli.c)
SET_TARGET_PROPERTIES(cli PROPERTIES OUTPUT_NAME ubus)
TARGET_LINK_LIBRARIES(cli ubus ubox blobmsg_json json)

SET(CMAKE_INSTALL_PREFIX /usr)

ADD_SUBDIRECTORY(lua)
ADD_SUBDIRECTORY(examples)

INSTALL(TARGETS ubus cli
	LIBRARY DESTINATION lib
	RUNTIME DESTINATION bin
)
INSTALL(TARGETS ubusd
	RUNTIME DESTINATION sbin
)

INSTALL(FILES ubusmsg.h ubus_common.h libubus.h DESTINATION include)
