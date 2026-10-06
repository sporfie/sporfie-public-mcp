# Sporfie Public API MCP server — standalone Streamable HTTP service.
# Build from the repo root: docker buildx build --platform linux/arm64 -t <tag> .
#
# Base images are pinned by version AND digest so a rebuild produces the same image. Bump them
# deliberately (docker buildx imagetools inspect <image:tag> prints the index digest).
ARG PYTHON_IMAGE=python:3.12.14-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.12.13@sha256:b485bd65cc2cf1c9a93b3554012c9c3778cf7b1b5fd3d3096ce9e1226c97e1e6

FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE} AS builder

WORKDIR /app

COPY --from=uv /uv /usr/local/bin/uv

COPY pyproject.toml uv.lock ./
COPY src/ ./src/

RUN uv sync --no-dev --frozen

FROM ${PYTHON_IMAGE} AS runtime

WORKDIR /app

COPY --from=builder --chown=root:root /app/.venv /app/.venv
COPY --from=builder --chown=root:root /app/src/ /app/src/
COPY --from=builder --chown=root:root /app/pyproject.toml /app/

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
# Nothing is written at runtime (the server also runs on a read-only root filesystem).
ENV PYTHONDONTWRITEBYTECODE=1

# Run unprivileged by default. The code stays root-owned, so the process cannot modify it.
RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app
USER 10001:10001

EXPOSE 8080

CMD ["uvicorn", "sporfie_public_server.server:app", "--host", "0.0.0.0", "--port", "8080"]
