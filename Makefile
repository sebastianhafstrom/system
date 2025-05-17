run:
	docker-compose up -d --build

test:
	go test ./... -v