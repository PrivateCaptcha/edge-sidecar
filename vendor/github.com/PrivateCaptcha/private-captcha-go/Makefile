PC_API_KEY ?=

test:
	@env PC_API_KEY=$(PC_API_KEY) go test ./...

vendors:
	go mod tidy
	go mod vendor
