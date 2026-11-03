FROM alpine:3.24 AS builder
RUN apk add --no-cache gcc clang22 musl-dev make ncurses-dev linux-headers
WORKDIR /src
COPY . ./
RUN make bpf CLANG=clang-22 && make

FROM alpine:3.24
RUN apk add --no-cache ca-certificates libncursesw libbpf binutils coreutils yara
COPY --from=builder /src/kscanner /usr/local/bin/kscanner
COPY --from=builder /src/build/bpf/rwx_monitor.bpf.o /usr/local/share/kscanner/rwx_monitor.bpf.o
RUN sha256sum /usr/local/share/kscanner/rwx_monitor.bpf.o > /usr/local/share/kscanner/rwx_monitor.bpf.o.sha256
ENTRYPOINT ["/usr/local/bin/kscanner"]
