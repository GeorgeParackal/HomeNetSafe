# syntax=docker/dockerfile:1

FROM python:3.11-slim

# Environment settings
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_NO_CACHE_DIR=on

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl build-essential \
 && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m appuser
WORKDIR /app

# Install dependencies (layer cached)
COPY requirements.txt .
RUN pip install --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir gunicorn

# Copy application files
COPY server.py ./
COPY HomeNetSafe2.0.html feature1.js image.png README.md ./

# Rename “Device Discovery.py” if it exists (handles spaces safely)
RUN if [ -f "Device Discovery.py" ]; then mv "Device Discovery.py" DeviceDiscovery.py; fi

# Ensure SQLite data directory exists and is writable
RUN mkdir -p /app/data && chown -R appuser:appuser /app
ENV DATABASE_URL="sqlite:////app/data/homenetsafe.db"

USER appuser
EXPOSE 5000

# Start Flask app with Gunicorn
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "server:app"]
