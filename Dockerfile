FROM golang:1.26 AS build
WORKDIR /go/src/github.com/betterleaks/betterleaks/v2
COPY . .
ARG VERSION
RUN VERSION="${VERSION:-$(git describe --tags --match 'v2.*' --always --dirty 2>/dev/null || echo dev)}" && \
CGO_ENABLED=0 go build -o bin/betterleaks -ldflags "-X=github.com/betterleaks/betterleaks/v2/version.Version=${VERSION}"

FROM alpine:3.22
# Betterleaks never runs Git. Git and Bash are for patch pipelines such as the
# pre-commit hook: git diff --cached ... | betterleaks stdin --git-diff
RUN apk add --no-cache bash git
COPY --from=build /go/src/github.com/betterleaks/betterleaks/v2/bin/* /usr/bin/

ENTRYPOINT ["betterleaks"]
