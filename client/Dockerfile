FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy client proxy code
COPY client_proxy.py /app/

# Install Python dependencies
RUN pip install --no-cache-dir \
    aiohttp==3.9.1 \
    httpx==0.25.2 \
    aiosqlite==0.19.0 \
    cryptography==41.0.7

# Create data directory
RUN mkdir -p /data

# Expose proxy port and admin port
EXPOSE 3128 9000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9000/admin/health')"

# Run the client proxy
CMD ["python", "client_proxy.py"]