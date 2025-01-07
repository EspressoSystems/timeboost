FROM python:3.12-slim-bookworm

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ADD fake-contract /app

WORKDIR /app

RUN uv sync --frozen --no-install-project --no-dev

ENV PATH="/app/.venv/bin:$PATH"

ENTRYPOINT []

CMD["fastapi", "run", "main.py"]
