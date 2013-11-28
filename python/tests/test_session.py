from __future__ import unicode_literals

import mock
import unittest

import ubus

class SessionTest(unittest.TestCase):

    def test_create_session(self):
        self.assertRaises(ubus.Session(""))

    def test_create_session_path_to_socket(self):
        session = ubus.Session("/var/run/ubus.sock")
        self.assertIsNotNone(session)

    def test_create_session_not_to_socket(self):
        session = ubus.Session()
        self.assertIsNotNone(session)
