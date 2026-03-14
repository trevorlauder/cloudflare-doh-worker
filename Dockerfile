FROM ubuntu:24.04@sha256:d1e2e92c075e5ca139d51a140fff46f84315c0fdce203eab2807c7e495eff4f9

# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl make tini && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

ARG MISE_VERSION=v2026.3.9
ARG TARGETARCH
SHELL ["/bin/bash", "-eo", "pipefail", "-c"]
RUN case "${TARGETARCH}" in \
    arm64) MISE_ARCH="arm64"; MISE_SHA256="f67220c7ec55f500568195cd6afe6a41443108a1db6fe2470e29b980317f46a3" ;; \
    *)     MISE_ARCH="x64";   MISE_SHA256="60ef9c2d9005ed4559cc8b1391056adf2c3b43d1065041640bbee854e5c4c9ee" ;; \
    esac; \
    curl -fsSL "https://github.com/jdx/mise/releases/download/${MISE_VERSION}/mise-${MISE_VERSION}-linux-${MISE_ARCH}" \
    -o /usr/local/bin/mise && \
    echo "${MISE_SHA256}  /usr/local/bin/mise" | sha256sum -c - && \
    chmod +x /usr/local/bin/mise

RUN useradd --create-home --shell /bin/bash app

WORKDIR /usr/src/app
RUN chown app:app /usr/src/app

USER app

COPY --chown=app:app mise.toml .
RUN mise trust && mise install python node uv
ENV PATH="/home/app/.local/share/mise/shims:/home/app/.local/bin:${PATH}"

COPY --chown=app:app pyproject.toml uv.lock ./
RUN uv sync --group dev

COPY --chown=app:app src/ src/
COPY --chown=app:app tests/ tests/
COPY --chown=app:app Makefile ./
COPY --chown=app:app wrangler.toml .
COPY --chown=app:app entrypoint.sh entrypoint.sh

EXPOSE 8787

ENTRYPOINT ["tini", "--"]
CMD ["/usr/src/app/entrypoint.sh"]
