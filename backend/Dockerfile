# ==============================================================================
#  Backend Container
# ==============================================================================
FROM python:3.12-slim

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system tools and security scanners
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        curl \
        wget \
        dnsutils \
        openssl \
        whois \
        netcat-openbsd \
        git \
        ca-certificates \
        procps \
        perl \
        bsdmainutils \
        sudo \
        swaks \
        telnet \
        ike-scan \
    && rm -rf /var/lib/apt/lists/*

# Install testssl.sh
RUN git clone https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
    && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
ENV TESTSSL_INSTALL_DIR=/opt/testssl.sh

# Install dnsrecon (Python DNS enumeration tool)
RUN pip install --no-cache-dir dnsrecon
RUN pip install ssh-audit

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user with passwordless sudo (for nmap raw socket scans)
RUN useradd -m -u 1000 -s /bin/bash appuser \
    && echo "appuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/appuser \
    && chmod 0440 /etc/sudoers.d/appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/docs || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
