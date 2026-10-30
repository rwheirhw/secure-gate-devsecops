FROM python:3.12-slim-bookworm

# Create a non-root service user for container runtime security

RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/false appuser

WORKDIR /app

COPY app.py .

USER appuser

EXPOSE 8000

CMD ["python", "app.py"]