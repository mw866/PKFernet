# PKFernet

## Instruction

* RSA
    * Generate  private key: `openssl genrsa -out <priv.key>`
    * Inspect Private key: `openssl rsa -text -in <priv.key>`
    * Generate Public key: `openssl rsa -in <priv.key> -pubout -out  <pub.key>`  
* To Make PEM url-safe for pasting into .json: `cat <priv.key> | tr '+/' '-_' | sed 'N;s/\n/\\n/g'`


## Reference
* Python Cryptography's Fernet implementatin: https://github.com/pyca/cryptography/blob/master/src/cryptography/fernet.py
* `sed` command: https://www.gnu.org/software/sed/manual/sed.html
* `tr` command: https://www.gnu.org/software/coreutils/manual/html_node/tr-invocation.html#tr-invocation