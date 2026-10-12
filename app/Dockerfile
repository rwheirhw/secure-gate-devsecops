FROM python:3.12-slim

# Create a non-root service user for container runtime security
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/false appuser

WORKDIR /app

COPY app.py .

USER 10001:10001

EXPOSE 8000

CMD ["python", "app.py"]