FROM python:3.12-slim

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency files first for layer caching
COPY pyproject.toml uv.lock ./

# Install dependencies (no dev extras, sync from lockfile)
RUN uv sync --frozen --no-dev

# Copy source
COPY src/ ./src/

# Install the project itself
RUN uv pip install --no-deps -e .

EXPOSE 8090

# API keys are passed in at runtime via -e / --env-file
ENV MCP_AUTH_TOKEN=""

ENTRYPOINT ["uv", "run", "tradecraft-mcp", "--transport", "sse", "--host", "0.0.0.0", "--port", "8090"]
