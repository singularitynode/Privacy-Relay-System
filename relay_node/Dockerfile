FROM python:3.11-slim
WORKDIR /app
COPY relay_node.py /app/relay_node.py
RUN pip install --no-cache-dir aiohttp aiosqlite httpx cryptography
EXPOSE 8443
CMD ["python", "relay_node.py"]