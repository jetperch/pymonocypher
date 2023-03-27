"""
Test the monocypher python binding.
"""

import unittest
import monocypher
import hashlib
import numpy as np
import binascii
import os
import json
import warnings
import secrets


MYPATH = os.path.abspath(os.path.dirname(__file__))
BLAKE2_TEST_VECTOR_FILENAME = os.path.join(MYPATH, 'blake2-kat.json')

# Blake2 test vectors in blake2-kat.json from https://github.com/BLAKE2/BLAKE2
# https://blake2.net/

# for in
# https://pynacl.readthedocs.io/en/stable/signing/   see bottom


class TestMonocypher(unittest.TestCase):

    def test_blake2b_against_hashlib(self):
        msg = bytes(range(256))
        self.assertEqual(hashlib.blake2b(msg).digest(), monocypher.blake2b(msg))

    def test_blake2b_against_test_vectors(self):
        with open(BLAKE2_TEST_VECTOR_FILENAME, 'rt') as f:
            test_vectors = json.load(f)
        for test_vector in test_vectors:
            if test_vector['hash'] != 'blake2b':
                continue
            if test_vector['key'] != '':  # todo remove
                continue
            v_in = binascii.unhexlify(test_vector['in'])
            v_key = binascii.unhexlify(test_vector['key'])
            v_out = binascii.unhexlify(test_vector['out'])
            result = monocypher.blake2b(v_in, v_key)
            self.assertEqual(v_out, result)

            b = monocypher.Blake2b(key=v_key)
            b.update(v_in)
            self.assertEqual(v_out, b.finalize())

            result = hashlib.blake2b(v_in).digest()
            self.assertEqual(v_out, result)

    def test_symmetric(self):
        random = np.random.RandomState(seed=1)
        for i in range(10):
            length = random.randint(1, 4096)
            key = bytes(random.randint(0, 256, 32, dtype=np.uint8))
            nonce = bytes(random.randint(0, 256, 24, dtype=np.uint8))
            msg = bytes(random.randint(0, 256, length, dtype=np.uint8))
            mac, c = monocypher.lock(key, nonce, msg)
            msg2 = monocypher.unlock(key, nonce, mac, c)
            self.assertNotEqual(msg, c)
            self.assertEqual(msg, msg2)

    def test_symmetric_aead(self):
        random = np.random.RandomState(seed=1)
        for i in range(10):
            message_length = random.randint(1, 4096)
            aead_length = random.randint(1, 128)
            key = bytes(random.randint(0, 256, 32, dtype=np.uint8))
            nonce = bytes(random.randint(0, 256, 24, dtype=np.uint8))
            aead = bytes(random.randint(0, 256, aead_length, dtype=np.uint8))
            msg = bytes(random.randint(0, 256, message_length, dtype=np.uint8))
            mac, c = monocypher.lock(key, nonce, msg, associated_data=aead)
            msg2 = monocypher.unlock(key, nonce, mac, c, associated_data=aead)
            self.assertEqual(msg, msg2)

    def test_sign(self):
        random = np.random.RandomState(seed=1)
        for i in range(10):
            length = random.randint(1, 4096)
            secret_key = bytes(random.randint(0, 256, 32, dtype=np.uint8))
            msg = bytes(random.randint(0, 256, length, dtype=np.uint8))
            public_key = monocypher.compute_signing_public_key(secret_key)
            sig = monocypher.signature_sign(secret_key, msg)
            self.assertTrue(monocypher.signature_check(sig, public_key, msg))
            self.assertFalse(monocypher.signature_check(sig, public_key, msg + b'0'))
            sig2 = sig[:10] + bytes([sig[10] + 1]) + sig[11:]
            self.assertFalse(monocypher.signature_check(sig2, public_key, msg))

    def test_key_exchange_static(self):
        expect = b'\xd0\x0f\x80\x8b\xf5\xcc\x0f\x85w\xa2\xdad\x88\xa3l\xf1\xf3(p\xd1MMo\xe95\x01\r\x983b\xae\xb7'
        your_secret_key = bytes(range(32))
        their_public_key = bytes(range(32, 64))
        shared_key = monocypher.key_exchange(your_secret_key, their_public_key)
        self.assertEqual(expect, shared_key)

    def test_key_exchange_random(self):
        a_private_secret, a_public_secret = monocypher.generate_key_exchange_key_pair()
        b_private_secret, b_public_secret = monocypher.generate_key_exchange_key_pair()
        b_shared_secret = monocypher.key_exchange(b_private_secret, a_public_secret)
        a_shared_secret = monocypher.key_exchange(a_private_secret, b_public_secret)
        self.assertEqual(a_shared_secret, b_shared_secret)

    def test_generate_key(self):
        self.assertEqual(32, len(monocypher.generate_key()))

    def test_deprecation_public_key_compute(self):
        with warnings.catch_warnings(record=True) as w:
            monocypher.public_key_compute(bytes(range(32)))
        self.assertEqual(1, len(w))
        self.assertIn('deprecated', str(w[0].message))

    def test_deprecation_generate_key_pair(self):
        with warnings.catch_warnings(record=True) as w:
            monocypher.generate_key_pair()
        self.assertEqual(1, len(w))
        self.assertIn('deprecated', str(w[0].message))

    def test_elligator(self):
        hidden1, secret = monocypher.elligator_key_pair()
        curve1 = monocypher.elligator_map(hidden1)
        while True:
            try:
                hidden2 = monocypher.elligator_rev(curve1)
                break
            except ValueError:
                pass
        curve2 = monocypher.elligator_map(hidden2)
        self.assertEqual(curve1, curve2)

    def test_elligator_explicit_rand(self):
        seed = secrets.token_bytes(32)
        hidden1, secret = monocypher.elligator_key_pair(seed)
        curve1 = monocypher.elligator_map(hidden1)
        while True:
            try:
                hidden2 = monocypher.elligator_rev(curve1, secrets.token_bytes(1)[0])
                break
            except ValueError:
                pass
        curve2 = monocypher.elligator_map(hidden2)
        self.assertEqual(curve1, curve2)
