# Go app for stacks a and b: server + bootstrap in one image.
FROM authzed/zed:v1.2.1 AS zedcheck
COPY internal/adapters/spicedb/schema.zed internal/adapters/spicedb/validation.yaml /v/
RUN ["zed", "validate", "/v/validation.yaml"]

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/bootstrap ./cmd/bootstrap

FROM alpine:3.22
RUN apk add --no-cache ca-certificates wget
# Pulls in the zed check stage: the build fails if the schema assertions fail.
COPY --from=zedcheck /v/validation.yaml /etc/spicedb-validation.yaml
COPY --from=build /out/server /out/bootstrap /usr/local/bin/
EXPOSE 8081
CMD ["server"]
