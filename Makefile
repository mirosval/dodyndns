develop:
	cargo watch -c -x 'check' -x 'clippy' -x 'test'

docker:
	docker build -t dodyndns .

push:
	docker tag dodyndns ${DOCKER_REPO}/dodyndns:latest
	docker push ${DOCKER_REPO}/dodyndns:latest

deploy:
	envsubst < k8s.yaml | kubectl apply -f -

run:
	RUST_LOG=dodyndns=trace cargo watch -c -x 'run'

run-update:
	./updater.sh

list-subdomains:
	curl --header "Authorization: Bearer ${DO_ACCESS_TOKEN}" https://api.digitalocean.com/v2/domains/${DO_DOMAIN_NAME}/records | jq .
