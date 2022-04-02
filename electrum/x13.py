from ctypes import *
import sys
import os

import unittest
import binascii

LIB_X13 = None

try:
    if sys.platform in ('windows', 'win32'):
        file_dir = os.path.dirname(__file__)
        LIB_X13 = cdll.LoadLibrary(file_dir + '\libx13.dll')
    elif sys.platform == 'darwin':
        LIB_X13 = cdll.LoadLibrary('libx13.dylib')
    elif sys.platform == 'linux':
        LIB_X13 = cdll.LoadLibrary('libx13.so')
    else:
        raise Exception
except Exception as e:
        raise RuntimeError('libx13 did not load. It is either not installed or it could not load. Message: ' + str(e))  

def get_pow_hash_x13(value):
    result = create_string_buffer(32)
    LIB_X13.x13_hash(value, result)
    return result

class X13HashTest(unittest.TestCase):

    def test_hashing(self):
        print(get_pow_hash_x13(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'utf-8')).raw.hex())
        print(get_pow_hash_x13(bytes('a'*79, 'utf-8')).raw.hex())
        print(get_pow_hash_x13(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'utf-8')).raw.hex())
        print(get_pow_hash_x13(bytes('a'*90, 'utf-8')).raw.hex())
        self.assertEqual(get_pow_hash_x13(bytes('a'*79, 'utf-8')).raw.hex(),
                         'efb3a4dca8092b22a3785b11e105b9b87fac69b575782a82a96ad790786fa3f2')
        self.assertEqual(get_pow_hash_x13(bytes('a'*90, 'utf-8')).raw.hex(),
                         'e202a3eb42ed84f1322025e782d3479adc3c3001226654e020bc0c50e2fc0708')
