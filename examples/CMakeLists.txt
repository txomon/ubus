cmake_minimum_required(VERSION 2.6)

ADD_DEFINITIONS(-I..)
ADD_EXECUTABLE(ubus-example ubus-example.c)
TARGET_LINK_LIBRARIES(ubus-example ubus ubox)

