# Dodyndns

## Digital Ocean DynDNS

A poor man's dynamic dns on top of Digital Ocean domains API.

### What problem does this solve?

If you don't care much about security of your DO Access Tokens, you can simply run a curl command like so:

```bash
curl -v -X PUT "https://api.digitalocean.com/v2/domains/example.com/records/3352896" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $DO_ACCESS_TOKEN" \
    --data @- << EOF
    {
        "data": "$(curl https://ipv4bot.whatismyipaddress.com)"
    }
    EOF
```

However this approach requires an access token with write privileges, and as of this writing Digital Ocean does not support setting fine-grained privileges for access tokens. That means that anybody with your token can do anything in your DO account. 

This project provides a simple proxy service that knows the DO access token and is able to update DNS records without exposing your entire DO account.

In order to secure the communication it is using JWT with pre-shared secret key to sign the payloads.

## Getting Started

### Overview

0. Prerequisites
1. Generate JWT Secret
2. Configure environment constants
3. Build and deploy server
4. Update the DNS record

### Prerequisites

First you need to have your top level domain name servers hosted on Digital Ocean (e.g. `example.com`). For each DynDNS instance, you need to have a subdomain (e.g. `my.example.com`). This is the domain your dynamic IP will be assigned to. This record should be an `A` record that you have already created on Digital Ocean.

### Generate JWT

In order to geenerate `JWT_SECRET` you can use something like:

```shell
$(echo -n openssl rand -base64 64) | head -c 80
```

### Configure Environment

You need to configure the following environment variables:

```shell
export DOCKER_REPO="some_repo"
export DO_DOMAIN_NAME="example.com"
export DO_SUBDOMAIN="subdomain"
export SERVER="localhost:8080"
export JWT_SECRET="some_secret"
```

On the server you need `DO_ACCESS_TOKEN`, `DO_DOMAIN_NAME` and `JWT_SECRET`, you also need `DOCKER_REPO` for deploying.
On the client you need `SERVER` (points to your deployed dodyndns instance), `JWT_SECRET`, this needs to be the same as the one supplied to the deployed dodyndns instance, and `DO_DOMAIN_NAME`, this is the level 2 domain you have registered on DO.

I recommend placing these lines in a file called `.envrc` and then using a tool like [Direnv](https://direnv.net/)

### Build and deploy server

Then, assuming you're logged in to your docker registry and have kubectl set up, you can run:

```shell
make docker push deploy
```

### Update the DNS record

After this you can run the following using chron to update the IP address for your subdomain regularly:

```shell
./updater.sh
```
