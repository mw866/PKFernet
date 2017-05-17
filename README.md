# PKFernet

By Chris Wang

An application-layer hybrid encryption scheme that allow users to send messages asynchronously with others without a pre-shared secret key.  

Ciper Suite:
* Symertic Encryption: AES-256 CTR MODE
* Asymmetric Encryption: RSA-2048
* Digital Signature: RSA with SHA-256
* HMAC: SHA-256

## Instruction

* RSA
    * Generate  public-private key-pair: `openssl genrsa -out <priv.key> 2048`
    * Inspect Private key: `openssl rsa -text -in <priv.key>`
    * Extract Public key: `openssl rsa -in <priv.key> -pubout -out  <pub.key>`  
* To Make PEM url-safe for pasting into .json: `cat <priv.key> | tr '+/' '-_' | sed 'N;s/\n/\\n/g'`


## Test Result (pytest-cov)



    Connected to pydev debugger (build 171.4163.6)
     Launching py.test with arguments --cov=. /Users/_/PKFernet/PKFernet.py in /Users/kylin1989/VM/dev/PKFernet
    ============================= test session starts ==============================
    platform darwin -- Python 3.5.2, pytest-3.0.7, py-1.4.33, pluggy-0.4.0
    rootdir: /Users/_/PKFernet, inifile:
    plugins: cov-2.4.0
    collected 2 items
     
    PKFernet.py    . 2017-05-17 17:11:40,042:DEBUG:Parsed ciphertext
    2017-05-17 17:11:40,044:DEBUG:Loaded sender's private encryption key
    2017-05-17 17:11:40,049:DEBUG:Decrypted R = (R_sym || R_hmac)
    2017-05-17 17:11:40,050:DEBUG:Verified HMAC
    2017-05-17 17:11:40,051:DEBUG:Decrypted {msg}
    2017-05-17 17:11:40,052:DEBUG:Decrypted signature
      . 
       
    ---------- coverage: platform darwin, python 3.5.2-final-0 -----------
    Name          Stmts   Miss  Cover
    ---------------------------------
    PKFernet.py     116      3    97%
    
    
    =========================== 2 passed in 0.59 seconds ===========================
      
    Process finished with exit code 0



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

