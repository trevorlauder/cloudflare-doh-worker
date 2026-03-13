.PHONY: dev deploy install setup ci test test-ci k3d-create k3d-delete k3d-recreate update-mise-checksums changelog

changelog:
	@GITHUB_TOKEN=$(shell gh auth token) git cliff \
	  $(if $(TAG),$(if $(findstring rc,$(TAG)),,--ignore-tags "rc") --unreleased --tag $(TAG),--latest) \
	  -o CHANGELOG.md

dev:
	uv run pywrangler dev

deploy:
	uv run pywrangler deploy

setup:
	mise install
	uv sync --group dev
	pre-commit install

ci:
	tilt down
	tilt ci
	tilt down

test:
	uv run pytest tests/ -n auto

test-ci:
	uv run pytest tests/ -v

k3d-create:
	k3d registry create doh-registry --port 5001 || true
	k3d cluster create doh \
		--registry-use k3d-doh-registry:5001 \
		--port '443:443/tcp@loadbalancer' \
		--k3s-arg '--disable=traefik@server:*' \
		--wait

k3d-delete:
	k3d cluster delete doh
	k3d registry delete k3d-doh-registry

k3d-recreate:
	$(MAKE) k3d-delete
	$(MAKE) k3d-create

update-mise-checksums:
	@version=$$(grep 'ARG MISE_VERSION=' Dockerfile | head -1 | sed 's/ARG MISE_VERSION=//'); \
	echo "Fetching checksums for mise $$version..."; \
	x64_sha=$$(curl -fsSL "https://github.com/jdx/mise/releases/download/$$version/mise-$$version-linux-x64" | sha256sum | awk '{print $$1}'); \
	arm64_sha=$$(curl -fsSL "https://github.com/jdx/mise/releases/download/$$version/mise-$$version-linux-arm64" | sha256sum | awk '{print $$1}'); \
	echo "  x64:   $$x64_sha"; \
	echo "  arm64: $$arm64_sha"; \
	sed -i '' -E "s/(arm64.*MISE_SHA256=\")[a-f0-9]+/\1$$arm64_sha/" Dockerfile; \
	sed -i '' -E "s/(x64.*MISE_SHA256=\")[a-f0-9]+/\1$$x64_sha/" Dockerfile; \
	echo "Dockerfile updated."
