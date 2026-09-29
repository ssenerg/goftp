FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/goftp . && mkdir /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/goftp /usr/local/bin/goftp
# Uploads need /data to be writable by the nonroot user; new volumes copy
# this ownership.
COPY --from=build --chown=65532:65532 /out/data /data
ENV GOFTP_DIR=/data
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["goftp"]
CMD ["serve"]
