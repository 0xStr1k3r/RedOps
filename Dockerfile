# RedOps image: single Go build (API + embedded GUI). SQLite by default.
# GUI sources in web/dist are embedded at build time (see Makefile sync-web).
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Embed the GUI (web/dist -> internal/api/webdist) before compiling.
RUN mkdir -p internal/api/webdist && cp web/dist/index.html web/dist/app.js web/dist/styles.css internal/api/webdist/ \
 && CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/redops ./cmd/cli

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /out/redops /app/redops
EXPOSE 8080
ENV REDOPS_DB=/data/redops.db
VOLUME ["/data"]
ENTRYPOINT ["/app/redops", "--db", "/data/redops.db", "serve", "--addr", ":8080"]
