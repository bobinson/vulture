FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go mod tidy && CGO_ENABLED=0 go build -ldflags="-s -w" -o /vulture ./cmd/vulture/

FROM alpine:3.19

RUN apk add --no-cache git ca-certificates

COPY --from=builder /vulture /usr/local/bin/vulture

RUN mkdir -p /data

EXPOSE 8080

ENTRYPOINT ["vulture"]
