# Phase 1 API image (SQLite). Phase 6 adds postgres/neo4j/redis targets.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/redops-api ./cmd/server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /out/redops-api /app/redops-api
EXPOSE 8080
ENV REDOPS_DB=/data/redops.db REDOPS_ADDR=:8080
VOLUME ["/data"]
ENTRYPOINT ["/app/redops-api"]
