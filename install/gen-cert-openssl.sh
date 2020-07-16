#!/usr/bin/env bash

set -x

[ -d /etc/postfix/cert ] || {
    mkdir -p /etc/postfix/cert
}

cd /etc/postfix/cert || exit

    openssl req -new -out smtp.csr -nodes \
        -batch \
        -config /app/openssl-gen.conf \
        -newkey rsa:2048 \
        -keyout smtp.key \
    && \
     openssl x509 -req -days 3650 \
        -in smtp.csr \
        -signkey smtp.key \
        -extensions v3_req -extfile /app/openssl-gen.conf \
        -out smtp.crt



    openssl req -new -out smtp.ec.csr -nodes \
        -batch \
        -config /app/openssl-gen.conf \
        -newkey ec:<(openssl ecparam -name secp384r1) \
        -keyout smtp.ec.key \
    && \
     openssl x509 -req -days 3650 \
        -in smtp.ec.csr \
        -signkey smtp.ec.key \
        -extensions v3_req -extfile /app/openssl-gen.conf \
        -out smtp.ec.crt


cat {smtp.key,smtp.crt,smtp.ec.key,smtp.ec.crt,} > chains.pem

chown -R root.postfix /etc/postfix/cert/
chmod -R 750 /etc/postfix/cert/
