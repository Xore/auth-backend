# Stage 1 — build (needs memory for Go compiler, isolated from runtime)
FROM golang:1.26-alpine AS builder
WORKDIR /src
# Download deps first for layer caching
COPY go.mod go.sum ./
RUN go mod download
# Build a fully static binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /forward-auth .

# Stage 2 — runtime (tiny, no compiler, no OOM risk)
FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata \
  && addgroup -S -g 65532 forwardauth \
  && adduser -S -D -H -u 65532 -G forwardauth forwardauth \
  && mkdir -p /data \
  && chown 65532:65532 /data
COPY --from=builder /forward-auth /usr/local/bin/forward-auth
EXPOSE 4181
VOLUME /data
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/forward-auth", "-healthcheck"]
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/forward-auth"]
