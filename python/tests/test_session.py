from __future__ import unicode_literals

import mock
import unittest

import ubus

class SessionTest(unittest.TestCase):

    def test_create_session(self):
        """Test that connecting to the standard socket fails with a 
        connection error due to access persmissions.
        """
        self.assertRaises(ubus.UbusError, ubus.Session)

    def test_create_session_path_to_socket(self):
        """Test that connecting to the default socket althought specifying
        route also faild due to permission errors.
        """
        self.assertRaises(ubus.UbusError, ubus.Session, "/var/run/ubus.sock")

    def test_create_session_to_writable_socket(self):
        """Test that if we specify a writtable socket, stuff works
        """
        session = ubus.Session("/tmp/socket")
        self.assertIsNotNone(session)
