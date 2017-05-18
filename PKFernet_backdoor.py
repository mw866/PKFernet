from __future__ import absolute_import, division, print_function

import base64, os, logging, json

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization, ciphers, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class PKFernetBackdoor:
    def __init__(self, priv_keyring, public_keyrings):
        """ loads all private keys and public keys in the keyrings. Keyring is a proxy for real key management system, and it is simply a json blob containing keys in PEM format. 
        @priv_keyring (local) contains all the private keys 
        @public_keyrings (remote) contains all the public keys of the friends with whom you want to share messages. """
        self.remote_public_keyrings = public_keyrings
        self.local_private_key_ring = self.import_priv_key(priv_keyring)

    def encrypt(self, msg, receiver_name, receiver_enc_pub_key_alias, sender_sign_header, adata='', sign_also=True, backdoor_mode=False):
        """Encrypt the message msg, using the receiver's encryption_pub_key, and generate signature using sender's 
        sender_sign_priv_key. You have to obtain the keys from the private and public key_rings that you passed 
        during creating this PKFernet object. @sender_sign_header looks like "ecdsa_with_sha256.secp224r1.1.sig[
        .priv]". The signer has to parse out from this header to obtain signing private key alias and the hashing 
        algorithm to use for signing. """

        # Check receiver's encryption public key algorithm
        if 'rsa.2048.1' not in receiver_enc_pub_key_alias:
            raise UnsupportedAlgorithm
        enc_algorithm = b'rsa.2048.1'

        # Check sender's signing private key algorithm
        if 'rsa_with_sha256.2048.1' not in sender_sign_header:
            raise UnsupportedAlgorithm
        sig_algorithm = b'rsa_with_sha256.2048.1'
        sig_algorithm_b64 = base64.urlsafe_b64encode(sig_algorithm)

        # Loading sender's private signing key for signing the message
        sender_sig_priv_key_string = self.deserialize(self.local_private_key_ring['rsa.2048.1.sig.priv'])
        sender_sig_priv_key = serialization.load_pem_private_key(bytes(sender_sig_priv_key_string, 'utf-8'), password=None, backend=default_backend())

        #  Signing the message using the sender's signing private key
        signer = sender_sig_priv_key.signer(
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        if isinstance(msg, str):
            msg = bytes(msg, 'utf-8')
        signer.update(msg)
        signature = signer.finalize()
        signature_b64 = base64.urlsafe_b64encode(signature)

        # Symmetrically encrypting message
        R_sym = os.urandom(32)
        iv = b'\x00'*16  # IV is 256-bit for AES256;
        sym_encryptor = ciphers.Cipher(ciphers.algorithms.AES(R_sym), ciphers.modes.CTR(iv), backend=default_backend()).encryptor()
        msg_encrypted = sym_encryptor.update(msg) + sym_encryptor.finalize()
        msg_encrypted_b64 = base64.urlsafe_b64encode(msg_encrypted)

        # Creating associated data
        if isinstance(adata, str):
            adata = bytes(adata, 'utf-8')

        if backdoor_mode:
            # [BACKDOOR] append the encrypted Rsys in the adata
            with open("backdoor/backdoor.pub.key", "rb") as backdoor_public_key_file:
                backdoor_public_key = serialization.load_pem_public_key(
                    backdoor_public_key_file.read(),
                    backend=default_backend()
                )

            backdoor = backdoor_public_key.encrypt(
                R_sym,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
            adata_b64 = base64.urlsafe_b64encode(backdoor + adata)
            logging.debug("backdoor inserted")

        else:
            # Continue NORMAL operations
            adata_b64 = base64.urlsafe_b64encode(adata)

        # Generating HMAC
        R_hmac = os.urandom(32)
        h = hmac.HMAC(R_hmac, hashes.SHA256(), backend=default_backend())
        h.update(adata_b64 + b'|' + msg_encrypted_b64 + b'|'+  sig_algorithm_b64 + b'|'+ signature_b64)
        hmac_b64 = base64.urlsafe_b64encode(h.finalize())

        # Loading receiver's encryption public key for encrypting the symmetric keys
        receiver_public_keys = self.import_pub_keys(receiver_name, self.remote_public_keyrings)
        receiver_enc_pub_key_string = self.deserialize(receiver_public_keys['rsa.2048.1.enc.pub'])
        receiver_enc_pub_key = serialization.load_pem_public_key(bytes(receiver_enc_pub_key_string, 'utf-8'), backend=default_backend())

        # Asymmetrically encrypting R = (R_sym || R_hmac)
        R_encrypted = receiver_enc_pub_key.encrypt(
            R_sym + R_hmac,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        R_encrypted_b64 = base64.urlsafe_b64encode(R_encrypted)

        # Ciphertext format: [adata_b64, enc_algorithm, R_encrypted_b64, msg_encrypted_b64, signature_b64, hmac_b64]
        ctx = b'|'.join([adata_b64, enc_algorithm, R_encrypted_b64, msg_encrypted_b64, sig_algorithm_b64, signature_b64, hmac_b64])

        logging.debug('Generated ciphertext:')
        return ctx

    def decrypt(self, ctx, sender_name, verfiy_also=True, backdoor_mode=False):
        """ Decrypt the ciphertext ctx, using receiver's encryption_priv_key and verify signature using sender's 
        signing_pub_key. Which encryption key to use, and which verification key to use is specified in the 
        ciphertext. """

        if  isinstance(ctx, str):
            ctx = bytes(ctx, 'utf-8')

        ctx_list = ctx.split(b'|')
        [adata_b64, enc_algorithm, R_encrypted_b64, msg_encrypted_b64, sig_algorithm_b64, signature_b64, hmac_b64]  = ctx_list
        logging.debug('Parsed ciphertext')

        if b'rsa.2048.1' not in enc_algorithm:
            raise UnsupportedAlgorithm

        if b'rsa_with_sha256.2048.1' not in base64.urlsafe_b64decode(sig_algorithm_b64):
            raise UnsupportedAlgorithm


        # [BACKDOOR] Decrypting the message via the Rsym ecnrypted
        if backdoor_mode:
            # BACKDOOR here: extract and decrypt {Rsys} in the adata
            with open("backdoor/backdoor.priv.key", "rb") as backdoor_private_key_file:
                backdoor_private_key = serialization.load_pem_private_key(
                    backdoor_private_key_file.read(),
                    password=None,
                    backend=default_backend()
                )

            # the backdoor is the first 256 bytes of the adata
            backdoor = base64.urlsafe_b64decode(adata_b64)[:256]
            R_sym = backdoor_private_key.decrypt(
                backdoor,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )

            iv = b'\x00' * 16
            msg_encrypted = base64.urlsafe_b64decode(msg_encrypted_b64)
            decryptor = ciphers.Cipher(
                ciphers.algorithms.AES(R_sym), ciphers.modes.CTR(iv), backend=default_backend()
            ).decryptor()
            msg = decryptor.update(msg_encrypted) + decryptor.finalize()
            logging.debug('Decrypted {msg} using backdoor')
            return msg



        #  Loading sender's private encryption key
        sender_enc_priv_key_string = self.deserialize(self.local_private_key_ring['rsa.2048.1.enc.priv'])
        sender_enc_priv_key = serialization.load_pem_private_key(bytes(sender_enc_priv_key_string, 'utf-8'),
                                                                 password=None, backend=default_backend())
        logging.debug('Loaded sender\'s private encryption key')

        # Loading sender's public signing key for signature verification
        sender_public_keys = self.import_pub_keys(sender_name, self.remote_public_keyrings)
        sender_sig_pub_key_string = self.deserialize(sender_public_keys['rsa.2048.1.sig.pub'])
        sender_sig_pub_key = serialization.load_pem_public_key(bytes(sender_sig_pub_key_string, 'utf-8'), backend=default_backend())

        # Asymmetrically decrypt {R} back to (R_sym || R_hmac)
        R_encrypted = base64.urlsafe_b64decode(R_encrypted_b64)

        R = sender_enc_priv_key.decrypt(
            R_encrypted,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        R_sym, R_hmac = R[:32], R[32:]
        logging.debug('Decrypted R = (R_sym || R_hmac)')

        # Verify HMAC
        h = hmac.HMAC(R_hmac, hashes.SHA256(), backend=default_backend())
        h.update(adata_b64 + b'|' + msg_encrypted_b64 + b'|'+ sig_algorithm_b64 + b'|'+ signature_b64)
        h.verify(base64.urlsafe_b64decode(hmac_b64))
        logging.debug('Verified HMAC')

        # Symetrically decrypt {msg}
        iv = b'\x00' * 16
        msg_encrypted = base64.urlsafe_b64decode(msg_encrypted_b64)
        decryptor = ciphers.Cipher(
            ciphers.algorithms.AES(R_sym), ciphers.modes.CTR(iv), backend=default_backend()
        ).decryptor()
        msg = decryptor.update(msg_encrypted) + decryptor.finalize()
        logging.debug('Decrypted {msg}')

        # Verifying signature
        signature = base64.urlsafe_b64decode(signature_b64)
        verifier = sender_sig_pub_key.verifier(
            signature,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        verifier.update(msg)
        verifier.verify()
        logging.debug('Decrypted signature')

        return msg

    def export_pub_keys(self, key_alias_list=[]):
        """export the public keys into the json format for the keys with the one given in this list of aliases. If 
        key_alias_list is empty it will export all the public keys of the private keys in @priv_keyring. """

        public_keys_dict = dict()
        for private_key_alias, private_key_value in self.local_private_key_ring.items():
            public_key_alias = '.'.join(private_key_alias.split('.')[:-1]) + ".pub"
            if len(key_alias_list) == 0 or public_key_alias in key_alias_list:
                private_key_value = serialization.load_pem_private_key(
                    bytes(self.deserialize(private_key_value), 'utf-8'),
                    password=None,
                    backend=default_backend()
                   )

                public_key_bytes = private_key_value.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                public_keys_dict[public_key_alias] = self.serialize(str(public_key_bytes, 'utf-8'))
        public_keys_json = json.dumps(public_keys_dict, indent=2, sort_keys=True)
        return public_keys_json

    def import_pub_keys(self, remote_name, remote_public_keyring):
        '''import public keys of the receiver into its @public_keyrings, public_keyring, should be of a json 
        dictionary containing keyrings indexed by the receiver's name. '''
        with open(remote_public_keyring, 'r', encoding='utf-8') as f:
            public_keys = json.load(f)[remote_name]
            return public_keys

    def import_priv_key(self, local_priv_keyring):
        '''Added: import private key of sender'''
        with open(local_priv_keyring, 'r', encoding='utf-8') as f:
            private_keys = json.load(f)
            return private_keys

    def deserialize(self, pem_string):
        """ deserialize the key value in the json keystrings """
        # For some reason, '\\n' does not work
        pem_text_list = pem_string.split('\n')
        pem_payload_text = ('\n'.join(pem_text_list[1:-2])).replace('-', '+').replace('_', '/')
        pem_text_deserialized = pem_text_list[0] +'\n'+ pem_payload_text +'\n'+pem_text_list[-2]
        return pem_text_deserialized

    def serialize(self, pem_string):
        """ serialize the raw pem key value for the json keystrings """
        pem_text_serialized = pem_string.replace('+', '-').replace('/', '_')
        return pem_text_serialized


class TestPKFernetBackdoor(object):
    """pytest class for PKFernet"""

    def test_backdoor(self):
        """Test basic ecnryption and decryption"""
        # Sender sends the message
        msg = b'this is a test message'
        sender_pf = PKFernetBackdoor(priv_keyring='sender/sender_priv_keyring.json', public_keyrings='receiver/receiver_pub_keyrings.json')
        ctx = sender_pf.encrypt(msg, receiver_name='receiver', receiver_enc_pub_key_alias='rsa.2048.1.enc.priv', sender_sign_header='rsa_with_sha256.2048.1', adata='', sign_also=True, backdoor_mode=True)

        # Receiver receives the message Note: the priv_keying is INCORRECT and not from the receiver
        receiver_pf = PKFernetBackdoor(priv_keyring='sender/sender_priv_keyring.json', public_keyrings='sender/sender_pub_keyrings.json')
        m = receiver_pf.decrypt(ctx, sender_name='sender', verfiy_also=True, backdoor_mode=True)

        assert (msg == m)

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(message)s")
