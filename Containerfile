FROM golang:1.25 AS build
WORKDIR /usr/local/src
COPY . .
RUN CGO_ENABLED=0 go build -o ../bin/gitleaks compat/gitleaks/main.go

FROM alpine:3.22
RUN apk add --no-cache bash git openssh-client
COPY --from=build /usr/local/bin/gitleaks /usr/local/bin/gitleaks

RUN git config --global --add safe.directory '*'

ENTRYPOINT ["gitleaks"]
