develop:
	cargo watch -c -x 'check' -x 'clippy' -x 'test'

docker:
	docker build -t dodyndns .

push:
	docker push

deploy:
	envsubst < k8s.yaml | kubectl apply -f -

run:
	RUST_LOG=dodyndns=trace cargo watch -c -x 'run'

run-update:
	MY_IP=$(shell curl https://ipv4bot.whatismyipaddress.com) envsubst < payload.json | curl -v -X POST -d @- ${SERVER}/update

list-subdomains:
	curl --header "Authorization: Bearer ${DO_ACCESS_TOKEN}" https://api.digitalocean.com/v2/domains/${DO_DOMAIN_NAME}/records | jq .
