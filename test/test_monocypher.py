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

    def test_IncrementalAuthenticatedEncryption(self):
        random = np.random.RandomState(seed=1)
        for i in range(10):
            message_length = random.randint(1, 4096)
            aead_length = random.randint(1, 128)
            key = bytes(random.randint(0, 256, 32, dtype=np.uint8))
            nonce = bytes(random.randint(0, 256, 24, dtype=np.uint8))
            aead = bytes(random.randint(0, 256, aead_length, dtype=np.uint8))
            msg = bytes(random.randint(0, 256, message_length, dtype=np.uint8))

            sender = monocypher.IncrementalAuthenticatedEncryption(key, nonce)
            receiver = monocypher.IncrementalAuthenticatedEncryption(key, nonce)

            mac, c = sender.lock(msg, associated_data=aead)
            msg2 = receiver.unlock(mac, c, associated_data=aead)
            self.assertEqual(msg, msg2)

            # A second encryption works, but creates a different cipher text
            mac2, c2 = sender.lock(msg, associated_data=aead)
            self.assertNotEqual(c, c2)
            self.assertNotEqual(mac, mac2)

            msg2 = receiver.unlock(mac2, c2, associated_data=aead)
            self.assertEqual(msg, msg2)

    def test_sign(self):
        random = np.random.RandomState(seed=1)
        for i in range(100):
            length = random.randint(1, 4096)
            secret_key, expected_public_key = monocypher.generate_signing_key_pair()
            msg = bytes(random.randint(0, 256, length, dtype=np.uint8))
            public_key = monocypher.compute_signing_public_key(secret_key)
            self.assertEqual(expected_public_key, public_key)
            sig = monocypher.signature_sign(secret_key, msg)
            self.assertTrue(monocypher.signature_check(sig, public_key, msg))
            self.assertFalse(monocypher.signature_check(sig, public_key, msg + b'0'))
            sig2 = sig[:10] + bytes([(sig[10] + 1) & 0xff]) + sig[11:]
            self.assertFalse(monocypher.signature_check(sig2, public_key, msg))

    def test_key_exchange_static(self):
        expect = b'l#\x84\xf2\xc0\xf1:\x8f\xf3\xce\xeeU\x07U@w\x8c\xd9\xf9C\x83\x17\x887\xae$\xf9\xf4\x19\xc1-{'
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

    def test_compute_signing_public_key(self):
        with self.assertRaises(ValueError):
            monocypher.compute_signing_public_key(monocypher.generate_key())

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
