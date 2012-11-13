Cinder-OpenSSL
==============
This is the Crypter CinderBlock, designed for use with the open-source C++ library Cinder: http://libcinder.org

Integrates OpenSSL 1.0.1c

Generating RSA keypair
======================
openssl genrsa -des3 -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
