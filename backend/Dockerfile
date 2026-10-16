FROM python:3.12-slim AS base
RUN groupadd -r sentinel && useradd -r -g sentinel -d /app -s /usr/sbin/nologin sentinel
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY main.py .
RUN mkdir -p /data && chown -R sentinel:sentinel /app /data
USER sentinel
ENV SENTINEL_DATA_DIR=/data \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health', timeout=2)" || exit 1
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
