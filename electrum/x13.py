from ctypes import *
import sys

import unittest
import binascii

LIB_X13 = None

try:
    if sys.platform in ('windows', 'win32'):
        LIB_X13 = cdll.LoadLibrary('libx13.dll')
    elif sys.platform == 'darwin':
        LIB_X13 = cdll.LoadLibrary('libx13.dylib')
    elif sys.platform == 'linux':
        LIB_X13 = cdll.LoadLibrary('libx13.so')
    else:
        raise Exception
except Exception as e:
        raise RuntimeError('libx13 did not load. It is either not installed or it could not load. Message: ' + str(e))  

def get_pow_hash(value):
    result = create_string_buffer(32)
    LIB_X13.x13_hash(value, result)
    return result

class X13HashTest(unittest.TestCase):

    def test_hashing(self):
        self.assertEqual(get_pow_hash(bytes('a'*80, 'utf-8')).raw.hex(),
                         '024fd1210aef38cff099541eacf1a626995fb680c56d27a5574572cb904519f5')
        self.assertEqual(get_pow_hash(bytes('b'*80, 'utf-8')).raw.hex(),
                         '019234c3b32871bc7fd968b0f4b96278f0ea208d28a3923ee0d6dcd217ba89a0')
        #self.assertEqual(hasher.hash(bytes('700000005d385ba114d079970b29a9418fd0549e7d68a95c7f168621a314201000000000578586d149fd07b22f3a8a347c516de7052f034d2b76ff68e0d6ecff9b77a45489e3fd511732011df0731000', 'utf-8')).raw.hex(), 'test')
