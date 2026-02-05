.PHONY: test test-cover failfast profile clean format build

PKG=github.com/betterleaks/betterleaks
COVER=--cover --coverprofile=cover.out

test-cover:
	go test -v ./... --race $(COVER) $(PKG)
	go tool cover -html=cover.out

format:
	go fmt ./...

test: config format
	go test -v ./... --race $(PKG)

failfast: format
	go test -failfast ./...

build: config format
	go mod tidy
	mkdir -p dist
	go build $(LDFLAGS) -o dist/gitleaks compat/gitleaks/main.go

betterleaks: config format
	# go build -o betterleaks cmd/betterleaks/main.go
	go build -tags gore2regex $(LDFLAGS) -o betterleaks cmd/betterleaks/main.go

lint:
	golangci-lint run

clean:
	rm -rf profile dist
	find . -type f -name '*.got.*' -delete
	find . -type f -name '*.out' -delete

profile: build
	./scripts/profile.sh './gitleaks' '.'

internal/config/gitleaks.toml: $(wildcard internal/config/generate/**/*)
	go generate ./...
