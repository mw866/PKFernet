# PKFernet: Public Key Authenticated and Hybrid Encryption

An application-layer hybrid encryption scheme that allow users to sign and send messages asynchronously with others without a pre-shared secret key.  

Ciper Suite:
* Symertic Encryption: AES-256 CTR MODE
* Asymmetric Encryption: RSA-2048
* Digital Signature: RSA with SHA-256
* HMAC: SHA-256



## Instruction
* Run unit test: `pytest test_xxx.py`
* OpenSSL
    * Generate  public-private key-pair: `openssl genrsa -out <priv.key> 2048`
    * Inspect Private key: `openssl rsa -text -in <priv.key>`
    * Extract Public key: `openssl rsa -in <priv.key> -pubout -out  <pub.key>`  
     

## The non-backdoor version: `PKFernet.py`

### Encryption

1.	message
   *   Sign with private key Ask.sig
2.	message | sig_algorithm | signature
   *   b64 encode sig_algorithm and signature, joined together by chr(124)
3.	message | b64_<sig_algorithm | signature>
   *   symmetric encryption* on message with Rsym, then base64 encode
4.	b64_{message}Rsym | b64_<sig_algorithm | signature>
   *   HMAC on <b64_AD | the above> with RHMAC
5.	b64_{message}Rsym | b64_<sig_algorithm | signature> | b64_HMAC
   *   asymmetricaly encrypt full symmetric key with Bpk.enc and b64 encode result
6.	b64_{R}Bpk.enc | b64_{message}Rsym | b64_<sig_algorithm | signature> | b64_HMAC
   *   attach unencrypted metadata
7.	b64_AD | asym_algo | b64_{R}Bpk.enc | b64_{message}Rsym | b64_<sig_algorithm | signature> | b64_HMAC
   * Final ciphertext

### Decryption (Vice Versa)


**Notes**

* Pipe characters are used throughout
* R → Generate with os.urandom and split in half <Symmetric Key (Rsym) || HMAC Key (RHMAC)>
* Bpk.enc → Receivers public encryption key
* Ask.sig → Senders private signing key

* Symmetric encryption is very similar to what was done for pwfernet:
   *	256-bit AES in Counter Mode, as implemented in cryptography.io primitives.ciphers 
   *	IV is all 0’s (use chr, not ‘0’)
   *	As mentioned above, the key is the first half of what was generated for R


## The backdoor version: `PKFernet_backdoor.py`

The backdoor in  the PKFernet_backdoor.py bypasses the authentication and integrity check by sending over the encrypted R_{sym} that can only by decrypted by the backdoor implementor. Here is how it works:

- During encryption, the backdoor encrypts the R_{sym} using the implementor's public key. And the encrypted R_{sym} is then appended to the adata field.
- During decryption, the backdoor implementor decrypts the  R_{sym} in the adata field using the implementor's private key. And the encrypted message is decrypted using the R_{sym}

The backdoor is enabled by setting  backdoor_mode=True in the encrypt() and decrypt() in the PKFernet_backdoor class. It is also demonstrated in the  pytest script TestPKFernetBackdoor()


## Reference
### cryptography.io
* RSA: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
* Key Serialization: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/
* Fernet Implementation: https://github.com/pyca/cryptography/blob/master/src/cryptography/fernet.py
* Random number generation: https://cryptography.io/en/latest/random-numbers/
* HMAC: https://cryptography.io/en/latest/hazmat/primitives/mac/hmac/

### Python 
* Base64 Encoding/Decoding: https://docs.python.org/3/library/base64.html


## Know Issues
### `TypeError: initializer for ctype 'char[]' must be a bytes or list or tuple, not str`
Solution: Cast string to bytes using `bytes()`.

###  "TypeError: string argument without an encoding"
Solution: Specify encoding in `bytes(str, 'utf-8'')`.

## `ValueError: Unable to load certificate` in `load_pem_x509_certificate`
Solution: 
Not in PEM format.
http://stackoverflow.com/questions/41891701/how-to-extract-public-key-from-a-x509-certificate-in-python

