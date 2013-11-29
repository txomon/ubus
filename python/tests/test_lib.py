from __future__ import unicode_literals

import ubus
import unittest


class LibraryTest(unittest.TestCase):
    def test_ubus_error_to_string_binding_works(self):
        self.assertEqual(
            ubus.ffi.string(ubus.lib.ubus_strerror(0)),
            b'Success'
            )

    def test_ubus_max_notify_peers_macro(self):
        self.assertEqual(ubus.lib.UBUS_MAX_NOTIFY_PEERS, 16)
