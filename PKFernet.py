import cryptography

from __future__ import absolute_import, division, print_function

import base64
import binascii
import os
import struct
import time

import six

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC


class PKFernet:
    def __init__(self, priv_keyring, public_keyrings):
        ''' loads all private keys and public keys in the keyrings. Keyring is a proxy for real key management system, and it is simply a json blob containing keys in PEM format. @priv_keyring contains all the private keys in the system, while public_keyrings contains all the public keys of the friends with whom you want to share messages. The @public_keyrings should look something similar to the following,
        {
            receiver1_name: receiver1_public_keyring,
            receiver2_name: receiver2_public_keyring,
            ...
        }'''
        # TODO

        pass

    def encrypt(msg, receiver_name, receiver_enc_pub_key_alias, sender_sign_header, adata=‘’, sign_also=True):
        '''Encrypt the message msg, using the receiver’s encryption_pub_key, and generate signature using sender’s sender_sign_priv_key. You have to obtain the keys from the private and public key_rings that you passed during creating this PKFernet object. 
@sender_sign_header looks like “ecdsa_with_sha256.secp224r1.1.sig[.priv]”. The signer has to parse out from this header to obtain signing private key alias and the hashing algorithm to use for signing.
'''
        # TODO
        pass

    def decrypt(ctx, sender_name, verfiy_also=True):
        '''Decrypt the ciphertext ctx, using receiver’s encryption_priv_key and verify signature using sender’s signing_pub_key. Which encryption key to use, and which verification key to use is specified in the ciphertext.'''
        # TODO
        pass

    def export_pub_keys(key_alias_list=[]):
        '''export the public keys into the json format for the keys with the one given in this list of aliases. If key_alias_list is empty it will export all the public keys of the private keys in @priv_keyring.'''
        # TODO
        pass

    def import_pub_keys(receiver_name, receiver_public_keyring):
        '''this will import public keys of a friend (receiver) into its @public_keyrings, public_keyring, should be of a json dictionary containing keyrings indexed by the receiver’s name.'''
        # TODO
        pass