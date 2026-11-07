FROM golang:1.27.3-alpine AS build
WORKDIR /src
COPY backend/ ./
RUN go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/webapp .

FROM scratch
COPY --from=build --chown=10001:10001 /out/webapp /webapp
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/webapp"]
