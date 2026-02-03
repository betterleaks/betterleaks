FROM golang:1.24 AS build
WORKDIR /go/src/github.com/betterleaks/betterleaks
COPY . .
RUN VERSION=$(git describe --tags --abbrev=0) && \
CGO_ENABLED=0 go build -o bin/betterleaks -ldflags "-X=github.com/betterleaks/betterleaks/version.Version=${VERSION}"

FROM alpine:3.22
RUN apk add --no-cache bash git openssh-client
COPY --from=build /go/src/github.com/betterleaks/betterleaks/bin/* /usr/bin/

RUN git config --global --add safe.directory '*'

ENTRYPOINT ["betterleaks"]
