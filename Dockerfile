FROM golang:1.26-alpine AS build-env

WORKDIR /build

ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux

RUN apk --no-cache add git=~2

COPY main.go go.mod go.sum /build/

RUN go version
RUN go build

FROM alpine:3.22

COPY --from=build-env /build/bind-rate-limit-parse-redis /bind-rate-limit-parse-redis
RUN mkdir -p /badger-data && chown 1000:1000 /badger-data
VOLUME /badger-data
HEALTHCHECK --interval=5s --timeout=3s \
    CMD ps aux | grep 'bind-rate-limit-parse-redis' || exit 1

ENTRYPOINT ["/bind-rate-limit-parse-redis"]