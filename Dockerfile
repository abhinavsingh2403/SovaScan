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

# Stage 2: Install Python Backend Dependencies
FROM python:3.11-slim AS backend-builder

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY backend/requirements-deploy.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements-deploy.txt

# Stage 3: Production Runtime
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends git libpq5 curl && \
    rm -rf /var/lib/apt/lists/* && \
    addgroup --system sovascan && \
    adduser --system --ingroup sovascan sovascan

# Copy installed Python packages
COPY --from=backend-builder /install /usr/local

# Copy backend source code
COPY backend/ ./backend/

# Copy built frontend dist into the location server.py expects
COPY --from=frontend-builder /build/frontend/dist ./frontend/dist

# Set Python path to find the sovascan package
ENV PYTHONPATH=/app/backend
ENV PYTHONUNBUFFERED=1
ENV PORT=8000

# Fix permissions for SQLite database creation in /app
RUN chown -R sovascan:sovascan /app

USER sovascan

EXPOSE 8000

# Run uvicorn listening on the dynamically assigned $PORT provided by Render/Cloud hosts
CMD ["sh", "-c", "exec python -m uvicorn sovascan.server:app --host 0.0.0.0 --port ${PORT:-8000}"]
