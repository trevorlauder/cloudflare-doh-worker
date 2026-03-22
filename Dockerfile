FROM ubuntu:24.04@sha256:186072bba1b2f436cbb91ef2567abca677337cfc786c86e107d25b7072feef0c

# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl make tini && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

ARG MISE_VERSION=v2026.3.12
ARG TARGETARCH
SHELL ["/bin/bash", "-eo", "pipefail", "-c"]
RUN case "${TARGETARCH}" in \
    arm64) MISE_ARCH="arm64"; MISE_SHA256="5670f708c843a90fb5244f57b50aa2a4f62fc45d2b1f563bc5ab4e2538b9dd22" ;; \
    *)     MISE_ARCH="x64";   MISE_SHA256="a4edc8d6f9dcf595f64938ecf34b613658c2fe5304466dffa5317ebd1e130acd" ;; \
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
ENV PYTHONDONTWRITEBYTECODE=1

COPY --chown=app:app pyproject.toml uv.lock ./
RUN uv sync --group dev --frozen

COPY --chown=app:app src/ src/
COPY --chown=app:app tests/ tests/
COPY --chown=app:app scripts/ scripts/
COPY --chown=app:app blocklist/ blocklist/
COPY --chown=app:app blocklist_sources.yaml .
COPY --chown=app:app Makefile ./
COPY --chown=app:app wrangler.toml .
COPY --chown=app:app entrypoint.sh entrypoint.sh

RUN echo 'BLOCKLIST_ENABLED = True' > src/config.py \
    && uv run python scripts/build_blocklist.py --skip-download \
    && rm src/config.py

EXPOSE 8787

ENTRYPOINT ["tini", "--"]
CMD ["/usr/src/app/entrypoint.sh"]
