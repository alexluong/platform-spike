# Cerbos with the platform policies baked in. `cerbos compile` also runs the policy tests, so a
# failing policy test fails the image build.
# Not /policies: the base image declares VOLUME /policies, and compose carries that anonymous
# volume over on recreate, so a rebuilt image would keep serving the old policies.
FROM ghcr.io/cerbos/cerbos:0.56.0
COPY policies /etc/platform/policies
COPY config.yaml /etc/platform/config.yaml
RUN ["/cerbos", "compile", "/etc/platform/policies"]
CMD ["server", "--config=/etc/platform/config.yaml"]
