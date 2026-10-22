.PHONY: all build install test clean

all: build

build:
	cd nightfalllx-go && go build -ldflags="-s -w" -o nightfalllx main.go

install: build
	mkdir -p $(HOME)/.local/bin
	cp nightfalllx-go/nightfalllx $(HOME)/.local/bin/nightfalllx
	chmod +x $(HOME)/.local/bin/nightfalllx
	@echo "NightfallLX successfully installed to $(HOME)/.local/bin/nightfalllx"

test:
	cd nightfalllx-go && go test -v ./...
	PYTHONPATH=. pytest
