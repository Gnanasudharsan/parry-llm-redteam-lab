# One image for every lab service; compose picks the entrypoint and PROFILE.
FROM ghcr.io/astral-sh/uv:0.13.7 AS uv
FROM python:3.12-slim
COPY --from=uv /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON=/usr/local/bin/python3.12 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE NOTICE ./
RUN uv sync --locked --no-dev --group lab --no-install-project
COPY parry ./parry
COPY targets ./targets
RUN uv sync --locked --no-dev --group lab && useradd --system --uid 10001 lab
ENV PATH=/app/.venv/bin:$PATH
USER lab
EXPOSE 8000
