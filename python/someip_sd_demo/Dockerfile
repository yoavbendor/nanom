FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml uv.lock ./
COPY src ./src
COPY scripts ./scripts
COPY README.md ./

RUN uv sync --frozen

ENTRYPOINT ["uv", "run"]
