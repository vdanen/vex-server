# Use Python 3.9 as specified in README
FROM python:3.9

# Set working directory
WORKDIR /app

# Install system dependencies if needed for any Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create cache directory structure
RUN mkdir -p cache/cve cache/vex cache/nvd cache/epss cache/kev

# Create instance directory if it doesn't exist
RUN mkdir -p instance

# Expose port 8080 (5000 is blocked by Chrome/Safari)
EXPOSE 8080

# Set environment variables
ENV FLASK_APP=flask_app.py
ENV PYTHONUNBUFFERED=1

# Default command - can be overridden
# Using gthread worker instead of gevent to avoid build issues
# gthread is built into gunicorn and provides good concurrency
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8080", "--access-logfile", "-", "--timeout", "90", "-k", "gthread", "--threads", "2", "app:create_app()"]

