# One image for both roles: central (web / scheduler) and collector (agent).
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client iputils-ping \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 999 --home /var/lib/inspector --create-home inspector
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
LABEL org.opencontainers.image.source="https://github.com/zoeyxia212-glitch/dc-inspector" \
      org.opencontainers.image.licenses="MIT"
COPY inspector ./inspector
COPY config ./config
COPY docker/central/bootstrap.sh /usr/local/bin/bootstrap.sh
RUN chmod 755 /usr/local/bin/bootstrap.sh
ENV PYTHONUNBUFFERED=1 \
    INSPECTOR_DB=/var/lib/inspector/inspector.db \
    INSPECTOR_REPORTS=/var/lib/inspector/reports
USER inspector
EXPOSE 8000
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:8000", "--access-logfile", "-", "inspector.app:create_app()"]
