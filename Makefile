build:
	@go build -o bin/Application

run: build
	@./bin/Application

test:
	@go test ./...
