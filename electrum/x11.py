from ctypes import *
import sys
import os

import unittest
import binascii

LIB_X11 = None

try:
    if sys.platform in ('windows', 'win32'):
        file_dir = os.path.dirname(__file__)
        LIB_X11 = cdll.LoadLibrary(file_dir + '\libx11.dll')
    elif sys.platform == 'darwin':
        LIB_X11 = cdll.LoadLibrary('libx11.dylib')
    elif sys.platform == 'linux':
        LIB_X11 = cdll.LoadLibrary('libx11.so')
    else:
        raise Exception
except Exception as e:
        raise RuntimeError('libx11 did not load. It is either not installed or it could not load. Message: ' + str(e))

def get_pow_hash_x11(value):
    result = create_string_buffer(32)
    LIB_X11.x11_hash(value, result)
    return result

class X11HashTest(unittest.TestCase):

    def test_hashing(self):
        print(get_pow_hash_x11(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'utf-8')).raw.hex())
        print(get_pow_hash_x11(bytes('a'*79, 'utf-8')).raw.hex())
        print(get_pow_hash_x11(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'utf-8')).raw.hex())
        print(get_pow_hash_x11(bytes('a'*90, 'utf-8')).raw.hex())
        self.assertEqual(get_pow_hash_x11(bytes('a'*79, 'utf-8')).raw.hex(),
                         '2472e1a45e73061ab866536c8d0ceac8a84809b0f64f08d8fd0ade485c090491')
        self.assertEqual(get_pow_hash_x11(bytes('a'*90, 'utf-8')).raw.hex(),
                         'ea2d4e0a8b1bdab2cb9cfe29e60f66e4c8b7558d23854bb08a1ab56152ead1f1')