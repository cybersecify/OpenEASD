# OpenEASD - Automated External Attack Surface Detection

**OpenEASD** is an automated security scanning platform designed specifically for startups with lean security resources. The system provides comprehensive external attack surface detection through automated scanning and real-time alerting.

**Company**: Cybersecify  
**Author**: Rathnakara G N

## Project Overview

OpenEASD (Open External Attack Surface Detection) is a comprehensive security scanning solution that helps organizations identify and monitor their external attack surface. Built with modern technologies and designed for scalability, it provides automated vulnerability detection, real-time alerting, and detailed reporting capabilities.

## Key Features

- **Comprehensive Scanning**: DNS analysis, SSL/TLS validation, service detection, and web security assessment
- **Real-time Alerting**: Slack integration for immediate notification of critical findings  
- **Automated Workflows**: Prefect-based orchestration for scheduled and on-demand scans
- **Modern Architecture**: FastAPI REST API, SQLite database, Docker containerization
- **ARM64 Support**: Optimized for Apple Silicon (Mac M1/M2) and ARM64 environments
- **Security Tools Integration**: Subfinder, Naabu, Nmap, Nuclei integration

## Quick Start with Docker

### Prerequisites
- Docker & Docker Compose
- 2GB RAM minimum
- ARM64/AMD64 architecture support

### Running OpenEASD

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd OpenEASD
   ```

2. **Start the services**:
   ```bash
   docker-compose -f docker/docker-compose.yml up -d
   ```

3. **Verify services are running**:
   ```bash
   curl http://localhost:8000/health
   curl http://localhost:4201/api/health
   ```

4. **Access the API**:
   - **OpenEASD API**: http://localhost:8000
   - **API Documentation**: http://localhost:8000/docs
   - **Prefect UI**: http://localhost:4201

## API Usage

### Start a Security Scan
```bash
curl -X POST "http://localhost:8000/scan/start?domain=example.com&scan_type=full"
```

### Check Scan Status  
```bash
curl http://localhost:8000/scan/1/status
```

### Get Scan Results
```bash
curl http://localhost:8000/scan/1/results
```

## Architecture

### Core Components

- **FastAPI Application**: REST API server for scan management
- **Prefect Server**: Workflow orchestration and scheduling  
- **SQLite Database**: Persistent storage for scan data
- **Security Tools**: Containerized security scanning tools

### Directory Structure

```
OpenEASD/
├── src/
│   ├── modules/          # Security scanning modules
│   ├── core/             # Core application logic
│   └── utils/            # Utility functions
├── docker/               # Docker configuration  
├── config/               # Application configuration
├── prefect_flows/        # Prefect workflow definitions
└── tests/                # Test suites
```

## Configuration

The system is configured through `config/default_config.yaml`:

```yaml
# Target domains
target:
  primary_domain: "example.com"
  excluded_subdomains: []

# Alert settings  
alerts:
  slack:
    webhook_url: "${SLACK_WEBHOOK_URL}"
    severity_threshold: "medium"
```

## Development Setup

### Local Development Environment

1. **Activate virtual environment**:
   ```bash
   source /Users/rathnakara/college/venvs/OpenEASD/bin/activate
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run locally**:
   ```bash
   python main.py
   ```

## Security Tools Integration

OpenEASD integrates with industry-standard security tools:

- **Subfinder**: Subdomain enumeration
- **Naabu**: Port scanning  
- **Nmap**: Service fingerprinting
- **Nuclei**: Vulnerability scanning

## Performance Targets

Based on validation testing:
- **Full scan completion**: ~60 minutes
- **Incremental scan**: ~10 minutes  
- **Memory usage**: 800MB peak
- **Scan reliability**: 96%
- **Alert latency**: <4 seconds

## Contributing

This project is developed by **Cybersecify** under the leadership of **Rathnakara G N**.

## License

MIT License - See LICENSE file for details.

## Support

For support and questions:
- **Company**: Cybersecify
- **Author**: Rathnakara G N
- **Email**: contact@cybersecify.com

---

*OpenEASD - Empowering startups with enterprise-grade security scanning*