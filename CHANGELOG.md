
# CHANGELOG

This file contains the list of changes made to pymonocypher.


## 0.1.3

2019 Sep 28

*   Distinguished between public keys for signing and key exchange.
    Use new functions generate_signing_key_pair and compute_signing_public_key
    for signing.  Use new functions compute_key_exchange_public_key and
    generate_key_exchange_key_pair for key exchange.
*   Deprecated generate_key_pair and public_key_compute which call
    call generate_signing_key_pair and compute_signing_public_key,
    respectively.

Thank you to wamserma and yota-code!


## 0.1.2

2018 Oct 10

*   Fixed setup.py typo that prevented installation.


## 0.1.1

2018 Oct 9

*   Initial public release based upon Monocypher 2.0.5.
