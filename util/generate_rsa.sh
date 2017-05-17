#!/usr/bin/env bash
# Gneerate signing key-pair
openssl genrsa -out rsa.2048.1.sig.priv.key 2048
openssl rsa -in rsa.2048.1.sig.priv.key -pubout -out rsa.2048.1.sig.pub.key

# Gneerate encryption key-pair
openssl genrsa -out rsa.2048.1.enc.priv.key 2048
openssl rsa -in rsa.2048.1.enc.priv.key -pubout -out rsa.2048.1.enc.pub.key
