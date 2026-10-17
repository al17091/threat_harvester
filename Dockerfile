FROM golang:alpine AS builder

WORKDIR /app
RUN apk add --no-cache git ca-certificates tzdata

COPY backend/go.mod backend/go.sum ./backend/
WORKDIR /app/backend
RUN go mod download

COPY backend/ /app/backend/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/harvester ./cmd/harvester

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata curl
WORKDIR /app

COPY --from=builder /app/harvester /usr/local/bin/harvester
COPY --from=builder /app/harvester /app/harvester
COPY config.example.yaml /app/config.example.yaml
COPY config.example.yaml /app/config.yaml

ENV PORT=8000
EXPOSE 8000

ENTRYPOINT ["harvester"]
CMD ["web", "--port", "8000"]
