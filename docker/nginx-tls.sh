#!/bin/sh
set -eu

umask 077
if [ ! -s /etc/nginx/tls/server.key ] || [ ! -s /etc/nginx/tls/server.crt ] ||
    ! openssl x509 -in /etc/nginx/tls/server.crt -noout -checkhost "$PC_EDGE_HOST" ||
    ! openssl x509 -in /etc/nginx/tls/server.crt -noout -checkend 86400; then
    openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
        -keyout /etc/nginx/tls/server.key -out /etc/nginx/tls/server.crt \
        -subj "/CN=$PC_EDGE_HOST" -addext "subjectAltName=DNS:$PC_EDGE_HOST"
fi
