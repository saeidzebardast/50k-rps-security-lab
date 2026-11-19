FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/vulnerable ./vulnerable \
 && CGO_ENABLED=0 go build -trimpath -o /out/hardened ./hardened

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ /app/
EXPOSE 8080
# Overridden per service in docker-compose.yml
ENTRYPOINT ["/app/vulnerable"]
