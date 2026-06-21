# Stage 1: Builder
FROM python:3.11-slim AS builder

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

COPY backend/ ./backend/

# Stage 2: Runtime
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq5 && \
    rm -rf /var/lib/apt/lists/* && \
    addgroup --system sovascan && \
    adduser --system --ingroup sovascan sovascan

COPY --from=builder /install /usr/local
COPY --from=builder /app/backend ./backend

RUN chown -R sovascan:sovascan /app

USER sovascan

EXPOSE 8000

CMD ["uvicorn", "backend.sovascan.server:app", "--host", "0.0.0.0", "--port", "8000"]
