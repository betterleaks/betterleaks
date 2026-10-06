FROM golang:1.25 AS build
WORKDIR /go/src/github.com/betterleaks/betterleaks/v2
COPY . .
ARG VERSION
RUN VERSION="${VERSION:-$(git describe --tags --match 'v2.*' --always --dirty 2>/dev/null || echo dev)}" && \
CGO_ENABLED=0 go build -o bin/betterleaks -ldflags "-X=github.com/betterleaks/betterleaks/v2/version.Version=${VERSION}"

FROM alpine:3.22
RUN apk add --no-cache bash git openssh-client
COPY --from=build /go/src/github.com/betterleaks/betterleaks/v2/bin/* /usr/bin/

RUN git config --global --add safe.directory '*'

ENTRYPOINT ["betterleaks"]
