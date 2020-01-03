# Dodyndns

## Digital Ocean DynDNS

A poor man's dynamic dns on top of Digital Ocean domains API.

What problem does this solve?

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
