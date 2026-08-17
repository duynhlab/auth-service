# Build stage
FROM docker.io/library/golang:1.26.6-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/auth-service ./cmd/main.go

# Final stage
FROM alpine:latest

RUN apk --no-cache upgrade && apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/auth-service .

EXPOSE 8080

# ENTRYPOINT (not CMD) so the migrate init container/compose can pass the
# `migrate` subcommand via args while the main container serves with no args.
ENTRYPOINT ["./auth-service"]
