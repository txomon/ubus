CONFIGURE_FILE(ubus.socket.in ubus.socket)
CONFIGURE_FILE(ubus.service.in ubus.service)

# Cmakes pkgconfig support is very limited, so for now just hardcode
SET(SYSTEMD_SYSUNIT_DIR "${SYSTEMD_PREFIX}/lib/systemd/system")
INSTALL(FILES ${CMAKE_BINARY_DIR}/systemd/ubus.socket ${CMAKE_BINARY_DIR}/systemd/ubus.service
	DESTINATION ${SYSTEMD_SYSUNIT_DIR})
