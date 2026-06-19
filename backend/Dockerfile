FROM golang:1.25-alpine AS builder

RUN apk add --no-cache build-base

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=1 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/cyber-soc-api ./cmd/api

FROM alpine:3.21

RUN apk add --no-cache ca-certificates wget \
    && addgroup -S app \
    && adduser -S -G app app

WORKDIR /app
COPY --from=builder /out/cyber-soc-api /usr/local/bin/cyber-soc-api

USER app
EXPOSE 8000

CMD ["cyber-soc-api"]
