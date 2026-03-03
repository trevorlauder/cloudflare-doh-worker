FROM ubuntu:24.04@sha256:d1e2e92c075e5ca139d51a140fff46f84315c0fdce203eab2807c7e495eff4f9

# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl make tini && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install mise - pinned version with checksum verification
ARG MISE_VERSION=v2026.3.0
ARG TARGETARCH
SHELL ["/bin/bash", "-eo", "pipefail", "-c"]
RUN case "${TARGETARCH}" in \
    arm64) MISE_ARCH="arm64"; MISE_SHA256="8c73a379d49c8919c0d7b8d90adf94aa0a4842a4b070101134239d9db0e45c7f" ;; \
    *)     MISE_ARCH="x64";   MISE_SHA256="e9f864905baab45916159e017243664f02cd1f5072723013496db568c82062a1" ;; \
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
