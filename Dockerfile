FROM golang:1.23-alpine AS builder
WORKDIR /app

# Install necessary packages for cgo and go-sqlite3
RUN apk add --no-cache gcc musl-dev sqlite-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 go build -o vuln-scanner ./cmd/...

FROM alpine:latest
WORKDIR /root/

RUN apk add --no-cache sqlite

COPY --from=builder /app/vuln-scanner .

EXPOSE 8080

CMD ["./vuln-scanner"]
