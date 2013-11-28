from __future__ import unicode_literals

import logging
import os
import weakref

import cffi


__version__ = '0.0.0'


# Log to nowhere by default. For details, see:
# http://docs.python.org/2/howto/logging.html#library-config
logging.getLogger('ubus').addHandler(logging.NullHandler())


_header_file = os.path.join(os.path.dirname(__file__), 'libubus.processed.h')
_header = open(_header_file).read()
ffi = cffi.FFI()
ffi.cdef(_header)
lib = ffi.verify("""
    #include <libubus.h>
    """,
    libraries=[str('ubus'),
               str('ubox'),
               str('blobmsg_json'),
               str('json_script')],
    ext_package='ubus')


# Mapping between keys and objects that should be kept alive as long as the key
# is alive. May be used to keep objects alive when there isn't a more
# convenient place to keep a reference to it. The keys are weakrefs, so entries
# disappear from the dict when the key is garbage collected, potentially
# causing objects associated to the key to be garbage collected as well. For
# further details, refer to the CFFI docs.
weak_key_dict = weakref.WeakKeyDictionary()

# Mapping between simple keys, like ints and bytestrings that can be passed as
# userdata through C context, and Python objects used to call the corresponding
# callback functions in Python context.
callback_dict = {}

# Reference to ubus Session instance. Used to enforce that one and only
# one session exists in each process.
session_instance = None


from ubus.session import *  # noqa
