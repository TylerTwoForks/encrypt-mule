.PHONY: run build snapshot

run:
	templ generate
	go run main.go

build:
	templ generate
	go build -o encrypt .

# Build release archives locally without publishing (requires goreleaser).
snapshot:
	goreleaser release --snapshot --clean
