# Cerbos with the platform policies baked in. `cerbos compile` also runs the policy tests, so a
# failing policy test fails the image build.
FROM ghcr.io/cerbos/cerbos:0.56.0
COPY policies /policies
COPY config.yaml /config.yaml
RUN ["/cerbos", "compile", "/policies"]
CMD ["server", "--config=/config.yaml"]
