from __future__ import absolute_import, division, print_function

import base64
import binascii
import os
import struct
import time

import six

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC

import json

class PKFernet:
    def __init__(self, priv_keyring, public_keyrings):
        ''' loads all private keys and public keys in the keyrings. Keyring is a proxy for real key management system, and it is simply a json blob containing keys in PEM format. 
        @priv_keyring contains all the private keys in the system
        @public_keyrings contains all the public keys of the friends with whom you want to share messages. The @public_keyrings should look something similar to the following,
        {
            receiver1_name: receiver1_public_keyring,
            receiver2_name: receiver2_public_keyring,
            ...
        }'''
        # TODO
        self.priv_keyring = priv_keyring
        self.public_keyrings = public_keyrings

    def encrypt(self, msg, receiver_name, receiver_enc_pub_key_alias, sender_sign_header, adata='', sign_also=True):
        '''Encrypt the message msg, using the receiver's encryption_pub_key, and generate signature using sender's sender_sign_priv_key. You have to obtain the keys from the private and public key_rings that you passed during creating this PKFernet object. 
        @sender_sign_header looks like "ecdsa_with_sha256.secp224r1.1.sig[.priv]". The signer has to parse out from this header to obtain signing private key alias and the hashing algorithm to use for signing.
        '''
        # TODO

        # Singining_Algorithm:  the concatenation of the first 3 parts of the receiver_enc_pub_key_alias
        sig_algorithm = '.'.join(sender_sign_header.split('.')[:2])

        # Encryption Algorithm:  the concatenation of the first 3 parts of the receiver_enc_pub_key_alias
        enc_algorithm = '.'.join(receiver_enc_pub_key_alias.split('.')[:2])


        # RKsym:  a URL safe base64 encoded string which Fernet2 will use to derive keys. For ECC based keys, this is ephemeral symmetric key which is generated using receiver's public key (Bpk.enc) and sender's ephemeral private key (Rsk). Use cryptography.io function to generate this key. If you are using RSA, then it is a random string of length  at least 32-bytes.
        RKsym = base64.urlsafe_b64encode(os.urandom(32))

        receiver_public_keys = self.import_pub_keys('receiver', self.public_keyrings)

        # Receiver's Encryption Public Key
        receiver_enc_pub_key_string = self.deserialize(receiver_public_keys['rsa.2048.1.enc.pub'])
        receiver_enc_pub_key = serialization.load_pem_public_key(bytes(receiver_enc_pub_key_string, 'utf-8'), backend=default_backend())

        # Receiver's Encryption Public Key
        receiver_sig_pub_key_string = self.deserialize(receiver_public_keys['rsa.2048.1.sig.pub'])
        receiver_sig_pub_key = serialization.load_pem_public_key(bytes(receiver_sig_pub_key_string, 'utf-8'), backend=default_backend())




        # <Rpk>  - This field is used to generate the symmetric key for encryption asymmetrically between the sender and receiver.

        # Rpk = receiver_enc_pub_key.encrypt(
        #     RKsym,
        #     padding.OAEP(
        #       mgf=padding.MGF1(algorithm=hashes.SHA1()),
        #       algorithm = hashes.SHA1()
        #     )
        # )

        # Ciphertext format: <adata> | <Enc_Algorithm> | <Rpk> | <Fernet2_ciphertext>
        # ctx = '|'.join([adata, enc_algorithm, Rpk, Fernet2_ciphertext])
        return ctx

    def decrypt(self, ctx, sender_name, verfiy_also=True):
        '''Decrypt the ciphertext ctx, using receiver's encryption_priv_key and verify signature using sender's signing_pub_key. Which encryption key to use, and which verification key to use is specified in the ciphertext.'''
        # TODO
        pass

    def export_pub_keys(self, key_alias_list=[]):
        '''export the public keys into the json format for the keys with the one given in this list of aliases. If key_alias_list is empty it will export all the public keys of the private keys in @priv_keyring.'''
        # TODO
        pass

    def import_pub_keys(self, receiver_name, receiver_public_keyring):
        '''import public keys of the receiver into its @public_keyrings, public_keyring, should be of a json dictionary containing keyrings indexed by the receiver's name.'''
        with open(receiver_public_keyring, 'r', encoding='utf-8') as f:
            public_keys = json.load(f)[receiver_name]
            # public_pem_data = self.deserialize(json.load(f)[receiver_name])
            # public_key = serialization.load_pem_public_key(public_pem_data, backend=default_backend())
            return public_keys

    def import_priv_key(self, sender_priv_keyring):
        '''import private key of sender'''
        with open(sender_priv_keyring, 'r', encoding='utf-8') as f:
            return json.load(f)

    def deserialize(self, pem_text):
        ''' deserialize the key value in the json keystrings '''
        # For some reason, '\\n' does not work
        pem_text_list = pem_text.split('\n')
        pem_payload_text = ('\n'.join(pem_text_list[1:-2])).replace('-', '+').replace('_', '/')
        pem_text_deserialized = pem_text_list[0] +'\n'+ pem_payload_text +'\n'+pem_text_list[-2]
        return pem_text_deserialized

class Fernet2:
    # TODO Pending clarification
    pass

if __name__ == '__main__':
    msg = "this is a test message"
    pf = PKFernet(priv_keyring = 'sender/sender_priv_keyring.json', public_keyrings='receiver/receiver_pub_keyrings.json')
    c = pf.encrypt(msg, receiver_name='receiver', receiver_enc_pub_key_alias= 'rsa.2048.1.enc.priv', sender_sign_header='rsa.2048.1.sig.priv', adata='', sign_also = True)
    # m = pf.decrypt(ctx, sender_name, verfiy_also=True)

    # my_pub_keys_json_blob = pf.export_pub_keys(key_alias_list=[])
    # pf.import_pub_keys(receiver_name, receiver_public_keyring)

    # assert(msg == m)
