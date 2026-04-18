FROM ubuntu:24.04@sha256:c4a8d5503dfb2a3eb8ab5f807da5bc69a85730fb49b5cfca2330194ebcc41c7b

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY mise-gpg-key.pub /etc/apt/keyrings/mise-archive-keyring.asc
COPY mise.list /etc/apt/sources.list.d/mise.list

# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl make tini mise && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

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
