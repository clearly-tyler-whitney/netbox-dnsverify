FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY *.go .

RUN go build -o netbox-dnsverify

FROM alpine:latest

WORKDIR /root/

COPY --from=builder /app/netbox-dnsverify .

ENTRYPOINT ["./netbox-dnsverify"]
