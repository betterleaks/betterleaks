.PHONY: test test-cover failfast profile clean format build config newrule

PKG=github.com/betterleaks/betterleaks/v2
VERSION ?= $(shell git describe --tags --match 'v2.*' --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X=github.com/betterleaks/betterleaks/v2/version.Version=$(VERSION)"
COVER=--cover --coverprofile=cover.out

test-cover:
	go test -v ./... --race $(COVER) $(PKG)
	go tool cover -html=cover.out

format:
	go fmt ./...

test: config/betterleaks.toml format
	go test -v --race ./... $(PKG)

failfast: format
	go test -failfast ./...

build:
	go build $(LDFLAGS) -o betterleaks .

lint:
	golangci-lint run

clean:
	rm -rf profile
	find . -type f -name '*.got.*' -delete
	find . -type f -name '*.out' -delete

profile: build
	./scripts/profile.sh './betterleaks' '.'

# Test every rule, then regenerate the default config from rules/.
config:
	go test ./rules/...
	go generate ./rules

# Scaffold a provider's rule file: make newrule NAME=acme
newrule:
	@case "$(NAME)" in ''|*[!abcdefghijklmnopqrstuvwxyz0123456789]*) echo 'usage: make newrule NAME=acme (lowercase letters and digits)' >&2; exit 2;; esac
	@test ! -e rules/$(NAME).go || { echo 'rules/$(NAME).go already exists; add the rule to it' >&2; exit 1; }
	@sed 's/{{name}}/$(NAME)/g' rules/gen/newrule.go.tmpl > rules/$(NAME).go
	@gofmt -w rules/$(NAME).go
	@echo 'Created rules/$(NAME).go. Replace its TODOs, then run:'
	@echo '  go test ./rules -run TestRules/$(NAME)'
	@echo '  make config'

config/betterleaks.toml: $(wildcard rules/*.go rules/generic/*.go rules/gen/*.go rules/gen/config.tmpl internal/rulebuilder/*.go)
	go generate ./rules
