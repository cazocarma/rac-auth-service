FROM golang:1.24-alpine AS builder
WORKDIR /app

# Dependencias
COPY go.mod go.sum ./
RUN go mod download

# Código
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o server ./cmd/server

# Imagen final
FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/server /app/server

# Usa la var que lee tu main.go
ENV SERVICE_PORT=8080
ENV SERVICE_NAME=rac-auth-service

EXPOSE 8080
ENTRYPOINT ["/app/server"]
