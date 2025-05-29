FROM golang:1.23-alpine as builder
COPY go.mod go.sum /app/
WORKDIR /app
RUN go mod download
COPY main.go /app/
RUN go build -o /app/main main.go
FROM alpine:latest
COPY --from=builder /app/main /app/main
WORKDIR /app
CMD ["./main"]
EXPOSE 8080