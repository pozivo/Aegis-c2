FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/aegis-control .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/aegis-control /aegis-control
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/aegis-control"]
