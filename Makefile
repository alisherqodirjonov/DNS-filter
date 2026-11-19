BINARY := dnsfilter

.PHONY: build run port53 test clean

# Build the single binary. The console, migrations, and example config are embedded in it.
build:
	go build -o $(BINARY) ./cmd/dnsfilter

# Build and start. A missing config.json is created from config.example.json.
run: build
	./$(BINARY)

# Build and allow binding ports below 1024, such as 53, without running as root.
# A rebuild drops the permission, so run this again after every build that serves port 53.
port53: build
	sudo setcap cap_net_bind_service=+ep ./$(BINARY)

test:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "run gofmt -w ."; exit 1; }
	go vet ./...
	go test -race ./...

clean:
	rm -f $(BINARY)
