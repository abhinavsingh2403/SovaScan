FROM ubuntu:latest
USER appuser

# Vulnerability: Running as root (missing USER directive)
# Vulnerability: Using ADD instead of COPY for remote/archive files
ADD https://example.com/archive.tar.gz /tmp/archive.tar.gz

# Vulnerability: apt-get install without --no-install-recommends
RUN apt-get update && apt-get install -y curl python3

WORKDIR /app
COPY . .

CMD ["python3", "config.py"]
