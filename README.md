# Omni-Audit: Automated Discovery & Compliance Platform

An automated platform for security scanning, service discovery, and compliance reporting. This platform provides a comprehensive suite of tools to identify security vulnerabilities across various protocols (Web, DNS, Email, SSH, FTP, etc.) and generate detailed remediation reports.

## 🚀 Key Features

- **Automated Discovery**: Uses `Nmap` and service mapping to identify open ports and services on targets.
- **Multi-Engine Scanning**:
  - **Web Engine**: HTTP header analysis, SSL/TLS configuration (via `testssl.sh`), and generic web security checks.
  - **DNS Engine**: CAA records, SPF, DKIM, DMARC, and DNSSEC validation.
  - **Email Engine**: Mail server security, open relay checks, and encryption support.
  - **SSH/FTP/Network Engines**: Protocol-specific security auditing.
- **Asynchronous Task Management**: Powered by **Celery** and **Redis** for efficient, non-blocking scan execution.
- **Remediation Database**: Integrated guidance for fixing identified vulnerabilities based on industry standards.
- **Comprehensive Reporting**: Generate professional reports in **PDF**, **Excel**, and **CSV** formats.
- **Scheduling**: Periodic automated scans using **Celery Beat**.
- **Modern Dashboard**: A responsive **React** frontend for managing scans, viewing results, and system administration.

## 🛠 Tech Stack

- **Backend**: Python 3.12, FastAPI, SQLAlchemy, PostgreSQL.
- **Task Queue**: Celery, Redis, Flower (monitoring).
- **Scanning Tools**: Nmap, testssl.sh, dnsrecon, ssh-audit.
- **Frontend**: React, Vite, Tailwind CSS, Nginx.
- **Orchestration**: Docker, Docker Compose.

## 📋 Prerequisites

- **Docker** (v20.10+)
- **Docker Compose** (v2.0+)

## ⚙️ Installation & Setup

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd compliance-platform
   ```

2. **Configure Environment Variables**:
   Copy the example environment file and update the values as needed.
   ```bash
   cp .env.example .env
   ```

3. **Start the Platform**:
   Use Docker Compose to build and start all services.
   ```bash
   docker compose up --build
   ```

   This command will:
   - Build the backend and frontend images.
   - Start PostgreSQL and Redis containers.
   - Initialize the database using `postgres/init.sql`.
   - Start the FastAPI backend, Celery workers, and the React frontend.

## 🌐 Accessing the Platform

| Service | URL | Description |
| :--- | :--- | :--- |
| **Frontend** | [https://localhost](https://localhost) (or port 3000) | Main user interface |
| **API Docs** | [http://localhost:8000/docs](http://localhost:8000/docs) | Interactive Swagger API documentation |
| **Flower** | [http://localhost:5555](http://localhost:5555) | Celery task monitoring dashboard |

## 📁 Project Structure

```text
.
├── backend/                # FastAPI application, Celery workers, and scanning engines
│   ├── app/                # Core API logic, models, and schemas
│   ├── engines/            # Protocol-specific scanning logic
│   ├── workers/            # Celery worker definitions
│   └── scan_reports/       # Generated scan results and reports
├── frontend/               # React / Vite source code and Nginx configuration
│   ├── src/                # Components, pages, and hooks
│   └── public/             # Static assets
├── postgres/               # Database initialization scripts
└── docker-compose.yml      # Service orchestration
```

## 🛡 Security Note

- The default `SECRET_KEY` and database passwords in `.env.example` should be changed for production deployments.
- The platform uses `sudo` within the backend container for certain `Nmap` raw socket operations; this is configured with passwordless access for the `appuser`.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
