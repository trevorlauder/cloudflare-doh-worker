FROM ubuntu:26.04@sha256:2260313b31c8c011cd2eebe728008efac1b3982be73eb71348ea2648d2c0e09b

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY mise-gpg-key.pub /etc/apt/keyrings/mise-archive-keyring.asc
COPY mise.list /etc/apt/sources.list.d/mise.list

# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential curl make tini mise && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash --uid 1000 app

WORKDIR /usr/src/app
RUN chown app:app /usr/src/app

USER 1000

COPY --chown=app:app mise.toml rust-toolchain.toml package.json package-lock.json ./
RUN mise trust && mise install python node uv rust
ENV PATH="/home/app/.local/share/mise/shims:/home/app/.local/bin:${PATH}"
ENV PYTHONDONTWRITEBYTECODE=1

COPY --chown=app:app pyproject.toml uv.lock ./
RUN uv sync --group dev --frozen

COPY --chown=app:app src/ src/
COPY --chown=app:app tests/ tests/
COPY --chown=app:app scripts/ scripts/
COPY --chown=app:app tools/ tools/
COPY --chown=app:app blocklist_sources.yaml .
COPY --chown=app:app Makefile ./
COPY --chown=app:app wrangler.toml .
COPY --chown=app:app entrypoint.sh entrypoint.sh

RUN echo 'BLOCKLIST_ENABLED = True' > src/config.py \
    && uv run python scripts/build_blocklist.py \
    && rm src/config.py

EXPOSE 8787

ENTRYPOINT ["tini", "--"]
CMD ["/usr/src/app/entrypoint.sh"]
