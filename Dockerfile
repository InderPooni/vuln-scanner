FROM golang:1.23-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o vuln-scanner ./cmd/...

FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/vuln-scanner .

EXPOSE 8080

CMD ["./vuln-scanner"]
