# Pin the Python 3.13 base image by digest for reproducible builds.
FROM python:3.13@sha256:498320f325ad70645e99ff676347987ca9117728784b8273fb6d25cc735ad9c0

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Set working directory
WORKDIR /app

# Install system dependencies if needed for any Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency metadata first for better layer caching
COPY pyproject.toml uv.lock .python-version ./

# Install dependencies into a project-local venv
RUN uv sync --frozen --no-dev --no-install-project

# Copy application code
COPY . .

# Create cache directory structure
RUN mkdir -p cache/cve cache/vex cache/nvd cache/epss cache/kev

# Create instance directory if it doesn't exist
RUN mkdir -p instance

# Expose port 8080 (5000 is blocked by Chrome/Safari)
EXPOSE 8080

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PATH="/app/.venv/bin:$PATH"

# Default command - using uvicorn for FastAPI
# Uvicorn with multiple workers provides excellent performance
CMD ["uvicorn", "fastapi_app:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "4"]
