# syntax=docker/dockerfile:1

# Build the application from source
FROM golang:1.21 AS build-stage

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /nginx-traffic-stats

# Run the tests in the container
FROM build-stage AS run-test-stage
RUN go test -v ./...

# Deploy the application binary into a lean image
FROM gcr.io/distroless/base-debian11 AS build-release-stage

WORKDIR /

COPY ./config.yaml /etc/nts/config.yaml
COPY --from=build-stage /nginx-traffic-stats /nginx-traffic-stats

EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["/nginx-traffic-stats"]