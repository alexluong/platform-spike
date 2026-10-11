# Go app for stack b (same code as stack a; build context: go/). Differs from
# go/Dockerfile only in the model check stage: fga model test instead of zed validate.
FROM openfga/cli:v0.8.1 AS fgacheck
COPY internal/adapters/openfga/model.fga internal/adapters/openfga/model.fga.yaml /v/
RUN ["fga", "model", "test", "--tests", "/v/model.fga.yaml"]

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/bootstrap ./cmd/bootstrap

FROM alpine:3.22
RUN apk add --no-cache ca-certificates wget
# Pulls in the fga check stage: the build fails if the model assertions fail.
COPY --from=fgacheck /v/model.fga.yaml /etc/openfga-model-test.yaml
COPY --from=build /out/server /out/bootstrap /usr/local/bin/
EXPOSE 8082
CMD ["server"]
