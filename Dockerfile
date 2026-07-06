ARG GO_VERSION=1.26.4

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

FROM alpine:3.22
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=build /out/server /app/server
USER app
EXPOSE 8092
ENTRYPOINT ["/app/server"]

