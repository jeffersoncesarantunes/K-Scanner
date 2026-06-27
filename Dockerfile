FROM alpine:3.24 AS builder
RUN apk add --no-cache gcc musl-dev make ncurses-dev linux-headers
WORKDIR /src
COPY . ./
RUN make clean && make

FROM scratch
COPY --from=builder /src/kscanner /kscanner
COPY --from=builder /etc/ssl/certs /etc/ssl/certs
USER 65534:65534
ENTRYPOINT ["/kscanner"]
