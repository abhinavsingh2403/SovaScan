# ============================================================
# SovaScan Production Dockerfile — Full-Stack (Frontend + Backend)
# ============================================================

# Stage 1: Build React Frontend
FROM node:18-alpine AS frontend-builder

WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# Stage 2: Install Python Backend & Package
FROM python:3.11-slim AS backend-builder

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY backend/requirements-deploy.txt ./backend/
RUN pip install --no-cache-dir --prefix=/install -r ./backend/requirements-deploy.txt

COPY backend/ ./backend/
RUN pip install --no-cache-dir --no-deps --prefix=/install ./backend

# Stage 3: Production Runtime
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends git libpq5 curl && \
    rm -rf /var/lib/apt/lists/* && \
    addgroup --system sovascan && \
    adduser --system --ingroup sovascan sovascan

# Copy installed Python packages & sovascan library
COPY --from=backend-builder /install /usr/local

# Copy backend source files
COPY backend/ ./backend/

# Copy built frontend dist
COPY --from=frontend-builder /build/frontend/dist ./frontend/dist

# Set Python environment
ENV PYTHONPATH=/app/backend:/usr/local/lib/python3.11/site-packages
ENV PYTHONUNBUFFERED=1
ENV PORT=8000

# Fix permissions
RUN chown -R sovascan:sovascan /app

USER sovascan

EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/health || exit 1

# Start Uvicorn bound to dynamic $PORT
CMD ["sh", "-c", "exec python -m uvicorn sovascan.server:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
