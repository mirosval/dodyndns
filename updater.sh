#!/bin/bash

set -e

[[ -z "$DO_SUBDOMAIN" ]] && (echo "env variable DO_SUBDOMAIN not set" ; exit 1)
[[ -z "$JWT_SECRET" ]] && (echo "env variable JWT_SECRET not set" ; exit 1)
[[ -z "$SERVER" ]] && (echo "env variable SERVER not set" ; exit 1)

base64url() {
    # Don't wrap, make URL-safe, delete trailer.
    openssl enc -A -base64 | tr '+/' '-_' | tr -d '='
}

ip=$(curl -s https://ipv4bot.whatismyipaddress.com)

header='{"alg":"HS512","typ":"JWT"}'
payload="{\"domain\":\"$DO_SUBDOMAIN\",\"ip4\":\"$ip\"}"

header=$(echo -n $header | base64url)
payload=$(echo -n $payload | base64url)
hashed=$(echo -n "$header.$payload" | openssl dgst -sha512 -hmac "$JWT_SECRET" -binary)
signature=$(echo -n $hashed | base64url)
signed=$(echo -n "$header.$payload.$signature")

echo -n $signed | curl -d @- ${SERVER}/update
echo ""

