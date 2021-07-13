#!/bin/sh
set -e 

# Code to make a country CSCA, a DSC and sign a test.

OPENSSL=${OPENSSL:=openssl}

# prime256v1 AKA as MBEDTLS_ECP_DP_SECP256R1, See appendix
# A of https://tools.ietf.org/search/rfc4492.
#
${OPENSSL} ecparam -name prime256v1 -genkey -noout -out csca.key
${OPENSSL} req -x509 \
        -subj '/CN=National CSCA of Friesland/C=FR/' \
        -key csca.key \
        -out csca.pem -nodes \
        -days 3650

${OPENSSL} ecparam -name prime256v1 -genkey -noout -out dsc.key
${OPENSSL} req -new \
        -subj "/CN=DSC of Friesland/C=FR/" \
        -key dsc.key -nodes |
${OPENSSL} x509 -req -CA csca.pem -CAkey csca.key -set_serial $$ \
        -days 1780  \
        -out dsc.pem

# Extract the public key - this is what is in the trust list  
# under each KID as base64
#
echo `openssl x509 -in dsc.pem -noout  -pubkey | openssl pkey -pubin -noout -text | grep '^ '` | sed -e 's/:/ /g' -e 's/^04 //' | xxd -r -p > xy.raw

 # And extract the X and Y from it
#
X=`dd if=xy.raw count=32 bs=1 | xxd -p -c 128`
Y=`dd if=xy.raw count=32 bs=1 skip=32 | xxd -p -c 128`

# Sign the text HelloWorld and output result as Base64
#
SIG=`printf HelloWorld | openssl dgst -sign dsc.key | base64`

# compile
gcc -Wall -o mbed-ecdsa-verify mbed-ecdsa-verify.c  -I/opt/local/include -L/opt/local/lib -lmbedcrypto 

# Run de test
./mbed-ecdsa-verify $X $Y $SIG HelloWorld

echo Ok
