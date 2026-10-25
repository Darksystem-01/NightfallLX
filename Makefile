.PHONY: all build install test clean

all: build

build:
	go build -ldflags="-s -w" -o nightfalllx main.go

install: build
	@mkdir -p $(DESTDIR)/usr/local/bin 2>/dev/null || mkdir -p $(HOME)/.local/bin
	@cp nightfalllx /usr/local/bin/nightfalllx 2>/dev/null || cp nightfalllx $(HOME)/.local/bin/nightfalllx
	@chmod +x /usr/local/bin/nightfalllx 2>/dev/null || chmod +x $(HOME)/.local/bin/nightfalllx
	@echo "[✓] NightfallLX successfully installed! Run 'nightfalllx --help'"

test:
	go test -v -count=1 ./...

clean:
	rm -f nightfalllx nightfalllx.exe
