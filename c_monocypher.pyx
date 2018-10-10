"""
Monocypher library Python bindings.

Monocypher is an easy to use, easy to deploy, auditable crypto library
written in portable C.
"""

from libc.stdint cimport uint8_t, uint32_t, uint64_t
from libc.stdlib cimport malloc, free
import binascii
import secrets

cdef extern from "monocypher.h":

    # Chacha20
    ctypedef struct crypto_chacha_ctx:
        uint32_t input[16] # current input, unencrypted
        uint32_t pool [16] # last input, encrypted
        size_t   pool_idx  # pointer to random_pool

    # Poly1305
    ctypedef struct crypto_poly1305_ctx:
        uint32_t r[4]   # constant multiplier (from the secret key)
        uint32_t h[5]   # accumulated hash
        uint32_t c[5]   # chunk of the message
        uint32_t pad[4] # random number added at the end (from the secret key)
        size_t   c_idx  # How many bytes are there in the chunk.

    # Authenticated encryption
    ctypedef struct crypto_lock_ctx:
        crypto_chacha_ctx   chacha
        crypto_poly1305_ctx poly
        uint64_t            ad_size
        uint64_t            message_size
        int                 ad_phase

    ctypedef struct crypto_lock_ctx:
        crypto_chacha_ctx   chacha
        crypto_poly1305_ctx poly
        uint64_t            ad_size
        uint64_t            message_size
        int                 ad_phase

    # Hash (Blake2b)
    ctypedef struct crypto_blake2b_ctx:
        uint64_t hash[8]
        uint64_t input_offset[2]
        uint64_t input[16]
        size_t   input_idx
        size_t   hash_size

    ctypedef struct crypto_sign_ctx:
        crypto_blake2b_ctx hash
        uint8_t buf[96]
        uint8_t pk [32]

    ctypedef struct crypto_check_ctx:
        crypto_blake2b_ctx hash
        uint8_t sig[64]
        uint8_t pk [32]


    # ////////////////////////////
    # /// High level interface ///
    # ////////////////////////////

    # Constant time comparisons
    # -------------------------

    # Return 0 if a and b are equal, -1 otherwise
    cpdef int crypto_verify16(const uint8_t a[16], const uint8_t b[16])
    cpdef int crypto_verify32(const uint8_t a[32], const uint8_t b[32])
    cpdef int crypto_verify64(const uint8_t a[64], const uint8_t b[64])

    # Erase sensitive data
    # --------------------

    # Please erase all copies
    void crypto_wipe(uint8_t *secret, size_t size)


    # Authenticated encryption
    # ------------------------

    # Direct interface
    void crypto_lock(uint8_t        mac[16],
                     uint8_t       *cipher_text,
                     const uint8_t  key[32],
                     const uint8_t  nonce[24],
                     const uint8_t *plain_text, size_t text_size)
    int crypto_unlock(uint8_t       *plain_text,
                      const uint8_t  key[32],
                      const uint8_t  nonce[24],
                      const uint8_t  mac[16],
                      const uint8_t *cipher_text, size_t text_size)

    # Direct interface with additional data
    void crypto_lock_aead(uint8_t        mac[16],
                          uint8_t       *cipher_text,
                          const uint8_t  key[32],
                          const uint8_t  nonce[24],
                          const uint8_t *ad        , size_t ad_size,
                          const uint8_t *plain_text, size_t text_size)
    int crypto_unlock_aead(uint8_t       *plain_text,
                           const uint8_t  key[32],
                           const uint8_t  nonce[24],
                           const uint8_t  mac[16],
                           const uint8_t *ad         , size_t ad_size,
                           const uint8_t *cipher_text, size_t text_size)

    # Incremental interface (encryption)
    void crypto_lock_init(crypto_lock_ctx *ctx,
                          const uint8_t    key[32],
                          const uint8_t    nonce[24])
    void crypto_lock_auth_ad(crypto_lock_ctx *ctx,
                             const uint8_t   *message,
                             size_t           message_size)
    void crypto_lock_auth_message(crypto_lock_ctx *ctx,
                                  const uint8_t *cipher_text, size_t text_size)
    void crypto_lock_update(crypto_lock_ctx *ctx,
                            uint8_t         *cipher_text,
                            const uint8_t   *plain_text,
                            size_t           text_size)
    void crypto_lock_final(crypto_lock_ctx *ctx, uint8_t mac[16])

    # Incremental interface (decryption)
    #define crypto_unlock_init         crypto_lock_init
    #define crypto_unlock_auth_ad      crypto_lock_auth_ad
    #define crypto_unlock_auth_message crypto_lock_auth_message
    void crypto_unlock_update(crypto_lock_ctx *ctx,
                              uint8_t           *plain_text,
                              const uint8_t     *cipher_text,
                              size_t             text_size)
    int crypto_unlock_final(crypto_lock_ctx *ctx, const uint8_t mac[16])


    # General purpose hash (Blake2b)
    # ------------------------------

    # Direct interface
    void crypto_blake2b(uint8_t hash[64],
                        const uint8_t *message, size_t message_size)

    void crypto_blake2b_general(uint8_t       *hash    , size_t hash_size,
                                const uint8_t *key     , size_t key_size, # optional
                                const uint8_t *message , size_t message_size)

    # Incremental interface
    void crypto_blake2b_init  (crypto_blake2b_ctx *ctx)
    void crypto_blake2b_update(crypto_blake2b_ctx *ctx,
                               const uint8_t *message, size_t message_size)
    void crypto_blake2b_final (crypto_blake2b_ctx *ctx, uint8_t *hash)

    void crypto_blake2b_general_init(crypto_blake2b_ctx *ctx, size_t hash_size,
                                     const uint8_t      *key, size_t key_size)


    # Password key derivation (Argon2 i)
    # ----------------------------------
    void crypto_argon2i(uint8_t       *hash,      uint32_t hash_size,     # >= 4
                        void          *work_area, uint32_t nb_blocks,     # >= 8
                        uint32_t       nb_iterations,                     # >= 1
                        const uint8_t *password,  uint32_t password_size,
                        const uint8_t *salt,      uint32_t salt_size)

    void crypto_argon2i_general(uint8_t       *hash,      uint32_t hash_size, # >= 4
                                void          *work_area, uint32_t nb_blocks, # >= 8
                                uint32_t       nb_iterations,                # >= 1
                                const uint8_t *password,  uint32_t password_size,
                                const uint8_t *salt,      uint32_t salt_size,# >= 8
                                const uint8_t *key,       uint32_t key_size,
                                const uint8_t *ad,        uint32_t ad_size)


    # Key exchange (x25519 + HChacha20)
    # ---------------------------------
    #define crypto_key_exchange_public_key crypto_x25519_public_key
    int crypto_key_exchange(uint8_t       shared_key      [32],
                            const uint8_t your_secret_key [32],
                            const uint8_t their_public_key[32])


    # Signatures (EdDSA with curve25519 + Blake2b)
    # --------------------------------------------

    # Generate public key
    cpdef void crypto_sign_public_key(uint8_t        public_key[32],
                                      const uint8_t  secret_key[32])

    # Direct interface
    void crypto_sign(uint8_t        signature [64],
                     const uint8_t  secret_key[32],
                     const uint8_t  public_key[32], # optional, may be 0
                     const uint8_t *message, size_t message_size)
    int crypto_check(const uint8_t  signature [64],
                     const uint8_t  public_key[32],
                     const uint8_t *message, size_t message_size)

    # Incremental interface for signatures (2 passes)
    void crypto_sign_init_first_pass(crypto_sign_ctx *ctx,
                                     const uint8_t  secret_key[32],
                                     const uint8_t  public_key[32])
    void crypto_sign_update(crypto_sign_ctx *ctx,
                            const uint8_t *message, size_t message_size)
    void crypto_sign_init_second_pass(crypto_sign_ctx *ctx)
    # use crypto_sign_update() again.
    void crypto_sign_final(crypto_sign_ctx *ctx, uint8_t signature[64])

    # Incremental interface for verification (1 pass)
    void crypto_check_init  (crypto_check_ctx *ctx,
                             const uint8_t signature[64],
                             const uint8_t public_key[32])
    void crypto_check_update(crypto_check_ctx *ctx,
                             const uint8_t *message, size_t message_size)
    int crypto_check_final  (crypto_check_ctx *ctx)


    # ////////////////////////////
    # /// Low level primitives ///
    # ////////////////////////////

    # For experts only.  You have been warned.


    # Chacha20
    # --------

    # Specialised hash.
    void crypto_chacha20_H(uint8_t       out[32],
                           const uint8_t key[32],
                           const uint8_t in_ [16])

    void crypto_chacha20_init(crypto_chacha_ctx *ctx,
                              const uint8_t      key[32],
                              const uint8_t      nonce[8])

    void crypto_chacha20_x_init(crypto_chacha_ctx *ctx,
                                const uint8_t      key[32],
                                const uint8_t      nonce[24])

    void crypto_chacha20_set_ctr(crypto_chacha_ctx *ctx, uint64_t ctr)

    void crypto_chacha20_encrypt(crypto_chacha_ctx *ctx,
                                 uint8_t           *cipher_text,
                                 const uint8_t     *plain_text,
                                 size_t             text_size)

    void crypto_chacha20_stream(crypto_chacha_ctx *ctx,
                                uint8_t *stream, size_t size)


    # Poly 1305
    # ---------

    # Direct interface
    void crypto_poly1305(uint8_t        mac[16],
                         const uint8_t *message, size_t message_size,
                         const uint8_t  key[32])

    # Incremental interface
    void crypto_poly1305_init  (crypto_poly1305_ctx *ctx, const uint8_t key[32])
    void crypto_poly1305_update(crypto_poly1305_ctx *ctx,
                                const uint8_t *message, size_t message_size)
    void crypto_poly1305_final (crypto_poly1305_ctx *ctx, uint8_t mac[16])


    # X-25519
    # -------
    void crypto_x25519_public_key(uint8_t       public_key[32],
                                  const uint8_t secret_key[32])
    int crypto_x25519(uint8_t       raw_shared_secret[32],
                      const uint8_t your_secret_key  [32],
                      const uint8_t their_public_key [32])


def wipe(data):
    """Wipe a bytes object from memory.

    :param data: The bytes object to clear.

    WARNING: this violates the Python memory model and may result in corrupted
    data.  Ensure that the data to wipe is the only active reference!
    """
    crypto_wipe(data, len(data))


def lock(key, nonce, message, associated_data=None):
    """Perform authenticated encryption.

    :param key: The 32-byte shared session key.
    :param nonce: The 24-byte number, used only once with any given session
        key.
    :param message: The secret message to encrypt.
    :param associated_data: The additional data to authenticate which
        is NOT encrypted.
    :return: the tuple of (MAC, ciphertext).  MAC is the 16-byte message
        authentication code.  ciphertext is the encrypted message.
    """
    mac = bytes(16)
    crypto_text = bytes(len(message))
    if associated_data is not None:
        crypto_lock_aead(mac, crypto_text, key, nonce, associated_data, len(associated_data), message, len(message))
    else:
        crypto_lock(mac, crypto_text, key, nonce, message, len(message))
    return mac, crypto_text


def unlock(key, nonce, mac, message, associated_data=None):
    """Perform authenticated decryption.

    :param key: The 32-byte shared session key.
    :param nonce: The 24-byte number, used only once with any given session
        key.
    :param mac: The 16-byte message authentication code produced by :func:`lock`.
    :param message: The ciphertext encrypted message to decrypt produced by :func:`lock`.
    :param associated_data: The additional data to authenticate which
        is NOT encrypted.
    :return: The secret message or None on authentication failure.
    """
    plain_text = bytearray(len(message))
    if associated_data is not None:
        rv = crypto_unlock_aead(plain_text, key, nonce, mac, associated_data, len(associated_data), message, len(message))
    else:
        rv = crypto_unlock(plain_text, key, nonce, mac, message, len(message))
    if 0 != rv:
        return None
    return plain_text


cdef class Encrypt:
    cdef crypto_lock_ctx _ctx

    """Incrementally encrypt a message with authentication.

    :param key: The 32-byte symmetric key.
    :param nonce: The 24-byte nonce.
    :param associated_data: The optional associated data for AEAD.
    """
    def __cinit__(self, key, nonce, associated_data=None):
        associated_data = b'' if associated_data is None else associated_data
        crypto_lock_init(&self._ctx, key, nonce)
        if associated_data and len(associated_data):
            crypto_lock_auth_ad(&self._ctx, associated_data, len(associated_data))

    def update(self, message):
        """Add new data to the payload.

        :param message: Additional data.
        :return: The encrypted data.
        """
        crypto_text = bytes(len(message))
        crypto_lock_update(&self._ctx, crypto_text, message, len(message))
        return crypto_text

    def finalize(self):
        """Finalize the authenticated encryption.

        :return: The 16-byte message authentication code (MAC).
        """
        mac = bytes(16)
        crypto_lock_final(&self._ctx, mac)
        return mac


cdef class Decrypt:
    cdef crypto_lock_ctx _ctx

    def __init__(self, key, nonce, associated_data=None):
        crypto_lock_init(&self._ctx, key, nonce)
        if associated_data and len(associated_data):
            crypto_lock_auth_ad(&self._ctx, associated_data, len(associated_data))

    def update(self, message):
        plain_text = bytes(len(message))
        crypto_unlock_update(&self._ctx, plain_text, message, len(message))
        return plain_text

    def finalize(self, mac):
        return crypto_unlock_final(&self._ctx, mac)


def chacha20(key, nonce, message):
    """Encrypt/Decrypt a message with ChaCha20.

    :param key: The 32-byte shared secret key.
    :param nonce: The 24-byte or 8-byte nonce.
    :param message: The message to encrypt or decrypt.
    :return: The message XOR'ed with the ChaCha20 stream.
    """
    cdef crypto_chacha_ctx ctx
    if 24 == len(nonce):
        derived_key = bytes(32)
        crypto_chacha20_H(derived_key, key, nonce)
        key = derived_key
        nonce = nonce[16:]
    elif 8 == len(nonce):
        pass
    else:
        raise ValueError('invalid nonce length')
    result = bytes(len(message))
    crypto_chacha20_init(&ctx, key, nonce)
    crypto_chacha20_encrypt(&ctx, result, message, len(message))
    return result


def blake2b(msg, key=None):
    key = b'' if key is None else key
    if isinstance(msg, str):
        msg = msg.encode('utf-8')
    hash = bytes(64)
    crypto_blake2b_general(hash, len(hash), key, len(key), msg, len(msg))
    return hash


cdef class Blake2b:
    cdef crypto_blake2b_ctx _ctx
    cdef int _hash_size

    """Incrementally compute the Blake2b hash.

    :param key: The optional 32-byte key.
    :param hash_size: The resulting hash size.  None (default) is 64.
    """
    def __init__(self, key=None, hash_size=None):
        key = b'' if key is None else key
        self._hash_size = 64 if hash_size is None else hash_size
        crypto_blake2b_general_init(&self._ctx, self._hash_size, key, len(key))

    def update(self, message):
        """Add new data to the hash.

        :param message: Additional data to hash.
        """
        crypto_blake2b_update(&self._ctx, message, len(message))

    def finalize(self):
        """Finalize and return the computed hash.

        :return: The hash.
        """
        hash = bytes(self._hash_size)
        crypto_blake2b_final(&self._ctx, hash)
        return hash


def argon2i_32(nb_blocks, nb_iterations, password, salt, key=None, ad=None):
    key = b'' if key is None else key
    ad = b'' if ad is None else ad
    hash = bytes(32)
    work_area = malloc(nb_blocks * 1024)
    try:
        crypto_argon2i_general(hash, len(hash), work_area,
                               nb_blocks, nb_iterations,
                               password, len(password),
                               salt, len(salt),
                               key, len(key),
                               ad, len(ad))
    finally:
        free(work_area)
    crypto_wipe(password, len(password))
    return hash


def key_exchange(your_secret_key, their_public_key):
    """Compute a shared secret based upon public-key crytography.

    :param your_secret_key: Your private, secret 32-byte key.
    :param their_public_key: Their public 32-byte key.
    :return: A 32-byte shared secret that can will match what is
        computed using their_secret_key and your_public_key.
    """
    p = bytes(32)
    rc = crypto_key_exchange(p, your_secret_key, their_public_key)
    if 0 != rc:
        raise ValueError('key_exchange failed')
    return p


def public_key_compute(secret_key):
    """Generate the public key from the secret key.

    :param secret_key: The 32-byte secret key.
    :return: The 32-byte public key.
    """
    public_key = bytes(32)
    crypto_sign_public_key(public_key, secret_key)
    return public_key


def signature_sign(secret_key, message):
    """Cryptographically sign a messge.

    :param secret_key: Your 32-byte secret key.
    :param message: The message to sign.
    :return: The 64-byte signature of message.

    For a quick description of the signing process, see the bottom of
    https://pynacl.readthedocs.io/en/stable/signing/.
    """
    sig = bytes(64)
    kp = bytes(64)
    crypto_sign_public_key(kp, secret_key)
    crypto_sign(sig, secret_key, kp, message, len(message))
    return sig


def signature_check(signature, public_key, message):
    """Verify the signature.

    :param signature: The 64-byte signature generated by :func:`signature_sign`.
    :param public_key: The public key matching the secret_key provided to
        :func:`signature_sign` that generated the signature.
    :param message: The message to check.
    :return: True if the message verifies correctly.  False if the message
        fails verification.
    """
    return 0 == crypto_check(signature, public_key, message, len(message))


cdef class SignatureVerify:
    cdef crypto_check_ctx _ctx

    """Incrementally verify a message.

    :param signature: The 64-byte signature.
    :param public_key: The 32-byte public key.
    """
    def __cinit__(self, signature, public_key):
        crypto_check_init(&self._ctx, signature, public_key)

    def update(self, message):
        """Add new data to the payload.

        :param message: Additional data.
        """
        crypto_check_update(&self._ctx, message, len(message))

    def finalize(self):
        """Finalize and return the result.

        :return: True on success or False on failure
        """
        return 0 == crypto_check_final(&self._ctx)

# def entropy(message):
#     """Compute the normalized entropy of a message.
#
#     :param message: The bytes object containing the data.
#     :return: The normalized entropy from 0.0 (constant value) to
#         1.0 (statistically random).
#     """
#     # https://en.wikipedia.org/wiki/Entropy_(information_theory)
#     # could have used scipy.stats.entropy, but don't want the dependency
#     msg = np.frombuffer(message, dtype=np.uint8)
#     data = np.bincount(msg, minlength=256)
#     k = data.astype(np.float) / float(len(message))
#     nonzero_k = k[data > 0]
#     e = -np.sum(nonzero_k * np.log2(nonzero_k))
#     e_norm = e / 8.0
#     return e_norm
#
#   def test_entropy(self):
#       msg = b'\x1f\x959c\x91\xfd\xe8\xdd|\xd6\x07\xa5H\x03f\xe7\xe9\xb7' + \
#             b'\xf8\x80V\xc4\x06k\xda\x81\x1eg\xd9\xab\x02\xfe'
#       self.assertEqual(0.625, monocypher.entropy(msg))


def generate_key(length=None, method=None):
    """Generate a random key.

    :param length: The key length.  None (default) is equivalent to 32.
    :param method: The random number generation method which is one of:
        * 'os': Use the platform's random number generator directly
        * 'chacha20': Apply the ChaCha20 cipher to the platform's random
          number generator to increase entropy (does not improve randomness).
        * None: (default) equivalent to 'chacha20'.
    :return: A key that is as secure as the random number generator of
        your platform.  See the Python secrets module for details on the
        randomness (https://docs.python.org/3/library/secrets.html).
    """
    length = 32 if length is None else int(length)
    if method in ['chacha20', None, '', 'default']:
        # Do not entirely trust the platform's random number generator
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(24)
        message = secrets.token_bytes(length)
        key = chacha20(key, nonce, message)
    elif method in ['os', 'secrets']:
        key = secrets.token_bytes(length)
    else:
        raise ValueError('unsupported method: %s' % method)
    return key


def generate_key_pair():
    """Generate and print a new keypair using default settings.

    :return (secret, public).
    """
    secret = generate_key()
    public = public_key_compute(secret)
    print('secret = %s\npublic = %s' % (
        binascii.hexlify(secret),
        binascii.hexlify(public)))
    return secret, public
