# DetectForge: the UI and the `detectforge` command line in one image.
#   docker compose up            → UI at http://localhost:8501
#   docker compose run --rm cli harden-selection --split dev --dry-run
# Secrets come from .env at run time (never baked into the image).

FROM python:3.12-slim-bookworm

# uv, pinned to the version that wrote uv.lock
COPY --from=ghcr.io/astral-sh/uv:0.12.22 /uv /uvx /usr/local/bin/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Dependencies first (cached layer: only rebuilt when the lock file changes)
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --group ui --no-install-project

# Then the project itself, its configuration and the committed data
COPY src ./src
COPY .streamlit ./.streamlit
COPY data/fixtures ./data/fixtures
COPY data/eval ./data/eval
RUN uv sync --locked --no-dev --group ui

# Run as an unprivileged user; runs and the SigmaHQ index live in mounted volumes
RUN useradd --create-home --uid 10001 detectforge \
    && mkdir -p data/runs data/sigmahq \
    && chown -R detectforge:detectforge /app/data
USER detectforge

EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=4)"

CMD ["streamlit", "run", "src/detectforge/ui/app.py", "--server.address=0.0.0.0", "--server.port=8501"]
