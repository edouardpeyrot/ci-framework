# Étape build Go
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod init example.com/hello && go mod tidy && go build -o server main.go

# Étape finale
FROM alpine:3.20
WORKDIR /app
COPY --from=builder /app/server .
EXPOSE 8080
CMD ["./server"]
