# Cross-compiled binary at a different path? Pass it via --build-arg BIN_PATH
# (and make sure .dockerignore lets it into the build context).

FROM alpine:3.23.5
ARG VERSION
LABEL org.opencontainers.image.version="${VERSION}"

# Path to the locally built static Linux binary, relative to the build context.
ARG BIN_PATH=target/x86_64-unknown-linux-musl/release/kcc

RUN apk add --no-cache ca-certificates

COPY ${BIN_PATH} /usr/local/bin/kcc
RUN chmod +x /usr/local/bin/kcc && \
    adduser -D -H -s /sbin/nologin kcc

USER kcc

ENTRYPOINT ["kcc"]
CMD ["check"]