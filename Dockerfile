FROM ubuntu:26.04@sha256:3131b4cc82a783df6c9df078f86e01819a13594b865c2cad47bd1bca2b7063bb

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY mise-gpg-key.pub /etc/apt/keyrings/mise-archive-keyring.asc
COPY mise.list /etc/apt/sources.list.d/mise.list

# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential curl make tini mise && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app
RUN chown ubuntu:ubuntu /usr/src/app

USER 1000

COPY --chown=ubuntu:ubuntu mise.toml rust-toolchain.toml package.json package-lock.json ./
RUN mise trust && mise install python node uv rust
ENV PATH="/home/ubuntu/.local/share/mise/shims:/home/ubuntu/.local/bin:${PATH}"
ENV PYTHONDONTWRITEBYTECODE=1

COPY --chown=ubuntu:ubuntu pyproject.toml uv.lock ./
RUN uv sync --group dev --frozen

COPY --chown=ubuntu:ubuntu src/ src/
COPY --chown=ubuntu:ubuntu tests/ tests/
COPY --chown=ubuntu:ubuntu scripts/ scripts/
COPY --chown=ubuntu:ubuntu tools/ tools/
COPY --chown=ubuntu:ubuntu blocklist_sources.yaml .
COPY --chown=ubuntu:ubuntu Makefile ./
COPY --chown=ubuntu:ubuntu wrangler.toml .
COPY --chown=ubuntu:ubuntu entrypoint.sh entrypoint.sh

RUN echo 'BLOCKLIST_ENABLED = True' > src/config.py \
    && uv run python scripts/build_blocklist.py \
    && rm src/config.py

EXPOSE 8787

ENTRYPOINT ["tini", "--"]
CMD ["/usr/src/app/entrypoint.sh"]
