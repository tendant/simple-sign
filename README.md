# simple-sign

A Clojure library designed to ... well, that part is up to you.

## Usage

FIXME

Example on how to generate one RSA keypair.
# Generate aes256 encrypted private key
openssl genrsa -aes256 -out privkey.pem 2048

# Generate public key from previously created private key.
openssl rsa -pubout -in privkey.pem -out pubkey.pem

## License

Copyright © 2018 FIXME

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
