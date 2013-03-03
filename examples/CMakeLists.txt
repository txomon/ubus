cmake_minimum_required(VERSION 2.6)

ADD_DEFINITIONS(-I..)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/..)

IF (BUILD_EXAMPLES)
	ADD_EXECUTABLE(server server.c)
	TARGET_LINK_LIBRARIES(server ubus ubox blobmsg_json)

	ADD_EXECUTABLE(client client.c)
	TARGET_LINK_LIBRARIES(client ubus ubox)
ENDIF()
