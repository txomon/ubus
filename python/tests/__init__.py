from __future__ import unicode_literals

import gc
import platform

import cffi

cffi.verifier.cleanup_tmpdir()


def gc_collect():
    """Run enough GC collections to make object finalizers run."""
    if platform.python_implementation() == 'PyPy':
        # Since PyPy use garbage collection instead of reference counting
        # objects are not finalized before the next major GC collection.
        # Currently, the best way we have to ensure a major GC collection has
        # run is to call gc.collect() a number of times.
        [gc.collect() for _ in range(10)]
    else:
        gc.collect()
