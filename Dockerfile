# Multi-stage build for Cerberus Sentinel
FROM golang:1.26-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/sentinel ./cmd/sentinel

# Minimal runtime with nmap and nmap-scripts
FROM alpine:latest

RUN apk add --no-cache nmap nmap-scripts ca-certificates

WORKDIR /app
COPY --from=builder /bin/sentinel /app/sentinel

EXPOSE 8080
VOLUME ["/app/data"]

ENV CERBERUS_PORT=8080
ENV CERBERUS_HOST=0.0.0.0
ENV CERBERUS_DB_PATH=/app/data/cerberus.db
ENV CERBERUS_SUBNET=172.28.0.0/24
ENV CERBERUS_DISCOVERY_INTERVAL=30m
ENV CERBERUS_VULN_INTERVAL=10m
ENV CERBERUS_UNPRIVILEGED=false

ENTRYPOINT ["/app/sentinel"]

