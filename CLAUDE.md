# CLAUDE.md - OpenEASD Implementation Guide

## Project Overview
**OpenEASD: Automated External Attack Surface Detection for Startups with Lean Security Resources**

**Company**: Cybersecify  
**Author**: Rathnakara G N

This guide provides comprehensive specifications for implementing the OpenEASD system based on Rathnakara G N's capstone project developed at Cybersecify. The system is designed to detect external security vulnerabilities in startup environments through automated scanning and real-time alerting.

## Repository Structure

```
OpenEASD/
├── src/
│   ├── modules/
│   │   ├── apex_domain_security/
│   │   │   ├── __init__.py
│   │   │   ├── dns_analyzer.py          # DNS record validation
│   │   │   ├── ssl_checker.py           # SSL/TLS certificate checks
│   │   │   ├── email_security.py        # SPF/DKIM/DMARC validation
│   │   │   └── cybersquatting.py        # TLD variant detection
│   │   │
│   │   ├── service_detection/
│   │   │   ├── __init__.py
│   │   │   ├── subdomain_enum.py        # Subfinder integration
│   │   │   ├── port_scanner.py          # Naabu integration
│   │   │   ├── service_fingerprint.py   # Nmap integration
│   │   │   └── insecure_protocols.py    # Legacy service detection
│   │   │
│   │   ├── web_security/
│   │   │   ├── __init__.py
│   │   │   ├── nuclei_scanner.py        # Nuclei integration
│   │   │   ├── header_checker.py        # Security headers validation
│   │   │   ├── admin_panel_detect.py    # Admin interface discovery
│   │   │   └── library_scanner.py       # Outdated component detection
│   │   │
│   │   └── alerting/
│   │       ├── __init__.py
│   │       ├── slack_notifier.py        # Real-time Slack alerts
│   │       ├── severity_filter.py       # Alert prioritization
│   │       └── report_generator.py      # Weekly/monthly reports
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── database.py                  # SQLite schema & operations
│   │   ├── orchestrator.py              # Prefect workflow definitions
│   │   ├── config_manager.py            # Configuration handling
│   │   └── delta_detector.py            # Change tracking logic
│   │
│   └── utils/
│       ├── __init__.py
│       ├── tool_wrapper.py              # Docker tool integrations
│       ├── result_parser.py             # Output standardization
│       └── mitre_mapper.py              # ATT&CK framework mapping
│
├── prefect_flows/
│   ├── __init__.py
│   ├── daily_scan_flow.py               # Incremental scanning
│   ├── weekly_scan_flow.py              # Full assessment
│   └── alert_flow.py                    # Real-time alerting
│
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── tools/                           # Tool-specific containers
│       ├── subfinder/
│       ├── naabu/
│       ├── nmap/
│       └── nuclei/
│
├── config/
│   ├── default_config.yaml
│   ├── nuclei_templates.yaml
│   └── severity_mapping.yaml
│
├── tests/
│   ├── unit/
│   │   ├── test_apex_domain.py
│   │   ├── test_service_detection.py
│   │   ├── test_web_security.py
│   │   └── test_alerting.py
│   ├── integration/
│   │   ├── test_full_workflow.py
│   │   └── test_prefect_flows.py
│   └── test_data/
│       └── sample_domains.yaml
│
├── README.md
├── requirements.txt
├── setup.py
└── .gitignore
```

## Core Architecture Components

### 1. Apex Domain Security Module
**Purpose**: Validate root domain security configuration and detect cybersquatting
**MITRE ATT&CK Mapping**: T1596 (Gather Victim Host Information), T1583.001 (Acquire Infrastructure: Domains)

**Key Functions**:
- `dns_record_analysis()` - Validate DNS records (A, AAAA, NS, MX, CNAME)
- `ssl_certificate_validation()` - Check SSL/TLS configuration, expiry, trust chain
- `spf_dmarc_checker()` - Validate email security records
- `tld_cybersquatting_detection()` - Detect domain variants across TLDs
- `domain_reputation_analysis()` - Check domain reputation and blacklists

**Expected Performance**: 95-98% accuracy for DNS/SSL issues, near-perfect accuracy for DNS problems

### 2. Service Detection Module
**Purpose**: Discover subdomains and identify exposed services
**MITRE ATT&CK Mapping**: T1046 (Network Service Scanning), T1049 (System Network Connections Discovery)

**Tool Chain**: Subfinder → Naabu → Nmap
**Key Functions**:
- `subdomain_enumeration()` - Passive subdomain discovery via Subfinder
- `port_scanning()` - TCP port detection via Naabu
- `service_fingerprinting()` - Service identification via Nmap
- `insecure_protocol_detection()` - Identify legacy protocols (FTP, Telnet, MQTT)

**Expected Performance**: 95-98% database exposure detection, 90-95% legacy protocol identification

### 3. Web Security Assessment Module
**Purpose**: Detect web application misconfigurations
**MITRE ATT&CK Mapping**: T1190 (Exploit Public-Facing Application), T1595 (Active Scanning)

**Key Functions**:
- `security_headers_validation()` - Check for missing headers (HSTS, CSP, X-Frame-Options)
- `admin_panel_detection()` - Discover exposed administrative interfaces
- `outdated_library_scanning()` - Identify vulnerable client-side libraries
- `default_credential_checks()` - Test for default authentication

**Expected Performance**: 95-98% security header validation, 85-90% admin panel discovery

### 4. Alerting & Reporting Module
**Purpose**: Real-time notifications and historical reporting
**MITRE ATT&CK Mapping**: Defensive alerting for T1071 (Application Layer Protocol)

**Key Functions**:
- `severity_based_filtering()` - Prioritize alerts by impact level
- `slack_integration()` - Real-time webhook notifications
- `delta_change_detection()` - Identify new exposures since last scan
- `report_generation()` - Weekly/monthly summary reports

**Expected Performance**: 98-99.5% delivery rate, 1-3 second latency

## Technical Specifications

### Performance Targets (From Capstone Validation)
- **Full scan completion**: ~60 minutes
- **Incremental scan**: ~10 minutes
- **Memory usage**: 800MB peak (2GB budget)
- **Scan reliability**: 96%
- **Alert latency**: <4 seconds
- **Incident response improvement**: 96% faster (48-72h → ~2h)

### Hardware Requirements
- **CPU**: 2 cores minimum (ARM64/Apple Silicon supported)
- **RAM**: 2GB minimum
- **Disk**: 5GB free space
- **OS**: macOS (Apple Silicon M1/M2) with Docker Desktop
- **Network**: Internet connectivity for external scanning

### Software Dependencies
- **Python 3.11+**
- **Subfinder** (subdomain enumeration)
- **Naabu** (port scanning)
- **Nmap** (service detection)
- **Nuclei** (vulnerability scanning)
- **Prefect** (workflow orchestration)
- **SQLite** (data storage)
- **Docker** (containerization)

## Database Schema (SQLite)

### Core Tables
```sql
-- Scan sessions
CREATE TABLE scan_sessions (
    id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL,
    scan_type TEXT NOT NULL, -- 'full' or 'incremental'
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    status TEXT NOT NULL -- 'running', 'completed', 'failed'
);

-- Subdomain discoveries
CREATE TABLE subdomains (
    id INTEGER PRIMARY KEY,
    session_id INTEGER,
    subdomain TEXT NOT NULL,
    ip_address TEXT,
    discovered_at TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
);

-- Service findings
CREATE TABLE services (
    id INTEGER PRIMARY KEY,
    session_id INTEGER,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    service_name TEXT,
    version TEXT,
    protocol TEXT,
    risk_level TEXT, -- 'low', 'medium', 'high', 'critical'
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
);

-- Vulnerability findings
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY,
    session_id INTEGER,
    host TEXT NOT NULL,
    vulnerability_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    remediation TEXT,
    mitre_technique TEXT,
    discovered_at TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
);

-- Alert history
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY,
    vulnerability_id INTEGER,
    alert_type TEXT NOT NULL, -- 'slack', 'email'
    sent_at TIMESTAMP,
    status TEXT NOT NULL, -- 'sent', 'failed'
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id)
);
```

## Prefect Workflow Architecture

### Main Workflow
```python
@flow(name="openeasd-security-scan")
def security_scan_flow(domain: str, scan_type: str = "full"):
    # Phase 1: Apex Domain Security
    apex_results = apex_domain_task(domain)
    
    # Phase 2: Subdomain Discovery
    subdomains = subdomain_discovery_task(domain, wait_for=[apex_results])
    
    # Phase 3: Service Detection
    service_results = service_detection_task(subdomains, wait_for=[subdomains])
    
    # Phase 4: Web Security Assessment
    web_results = web_security_task(service_results, wait_for=[service_results])
    
    # Phase 5: Alert Processing
    alert_results = alert_task(
        apex_results, service_results, web_results,
        wait_for=[apex_results, service_results, web_results]
    )
    
    return {
        "apex": apex_results,
        "services": service_results,
        "web": web_results,
        "alerts": alert_results
    }
```

### Scheduling Configuration
```python
# Daily incremental scan
@flow(name="daily-incremental-scan")
def daily_scan(domain: str):
    return security_scan_flow(domain, scan_type="incremental")

# Weekly full scan
@flow(name="weekly-full-scan")
def weekly_scan(domain: str):
    return security_scan_flow(domain, scan_type="full")
```

## Configuration Management

### default_config.yaml
```yaml
# Target configuration
target:
  primary_domain: "example.com"
  excluded_subdomains: []
  scan_depth: 3

# Tool configurations
tools:
  subfinder:
    sources: ["crtsh", "virustotal", "securitytrails"]
    timeout: 300
  naabu:
    top_ports: 1000
    rate: 1000
  nmap:
    timing: 3
    scripts: ["default", "safe"]
  nuclei:
    templates: ["cves", "misconfigurations", "default-logins"]

# Alert settings
alerts:
  slack:
    webhook_url: "${SLACK_WEBHOOK_URL}"
    channel: "#security-alerts"
    severity_threshold: "medium"
  
# Performance settings
performance:
  max_concurrent_scans: 5
  scan_timeout: 3600
  retry_attempts: 3
```

### severity_mapping.yaml
```yaml
severity_levels:
  critical:
    - "exposed_database"
    - "default_credentials" 
    - "admin_panel_no_auth"
  high:
    - "missing_spf_record"
    - "expired_ssl_certificate"
    - "insecure_ftp_service"
  medium:
    - "missing_security_headers"
    - "weak_ssl_configuration"
    - "cybersquatting_domains"
  low:
    - "information_disclosure"
    - "deprecated_protocols"
```

## Docker Configuration

### docker-compose.yml
```yaml
version: '3.8'

services:
  openeasd:
    build: .
    platform: linux/arm64
    environment:
      - DATABASE_URL=sqlite:///data/openeasd.db
      - SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL}
    volumes:
      - ./data:/app/data
      - ./config:/app/config
    depends_on:
      - prefect-server

  prefect-server:
    image: prefecthq/prefect:2.14-python3.11
    platform: linux/arm64
    command: prefect server start --host 0.0.0.0
    ports:
      - "4200:4200"
    environment:
      - PREFECT_API_URL=http://0.0.0.0:4200/api

  subfinder:
    image: projectdiscovery/subfinder:latest
    platform: linux/arm64
    
  naabu:
    image: projectdiscovery/naabu:latest
    platform: linux/arm64
    
  nmap:
    image: instrumentisto/nmap:latest
    platform: linux/arm64
    
  nuclei:
    image: projectdiscovery/nuclei:latest
    platform: linux/arm64
```

## Implementation Phases

### Phase 1: Foundation (Priority 1)
1. **Database schema setup** - SQLite tables and indexes
2. **Configuration management** - YAML-based settings
3. **Basic Docker setup** - Container definitions
4. **Core utilities** - Tool wrappers and result parsers

### Phase 2: Core Modules (Priority 2)
1. **Apex domain security** - DNS, SSL, email security validation
2. **Service detection** - Subfinder, Naabu, Nmap integration
3. **Web security** - Nuclei scanning and header validation
4. **Basic alerting** - Slack integration

### Phase 3: Orchestration (Priority 3)
1. **Prefect workflows** - Task definitions and dependencies
2. **Scheduling system** - Daily/weekly scan automation
3. **Delta detection** - Change tracking between scans
4. **Error handling** - Retry logic and failure recovery

### Phase 4: Production Features (Priority 4)
1. **Comprehensive testing** - Unit and integration tests
2. **Performance optimization** - Parallel processing
3. **Advanced reporting** - Historical trend analysis
4. **Monitoring integration** - Health checks and metrics

## Key Implementation Notes

### Tool Integration Strategy
- **Containerize each tool** for consistent environments
- **Standardize output formats** across all tools
- **Implement timeout handling** for long-running scans
- **Add retry logic** for network failures

### Security Considerations
- **Input validation** for all domain inputs
- **Rate limiting** to avoid IP blocking
- **Secure credential storage** for API keys
- **Non-intrusive scanning** only

### Performance Optimization
- **Parallel subdomain scanning** for large domains
- **Efficient database queries** with proper indexing
- **Memory management** for large result sets
- **Incremental scanning** to reduce overhead

### Error Handling
- **Graceful tool failures** without stopping entire workflow
- **Comprehensive logging** for debugging
- **Alerting on system failures** via Slack
- **Automatic retry** with exponential backoff

## Expected Outcomes

Based on capstone validation:
- **6-8 actionable findings per scan**
- **50% of critical issues resolved within 48 hours**
- **96% improvement in incident response time**
- **35% of findings relate to security header deficiencies**
- **Linear performance scaling** with domain size

## Testing Strategy

### Unit Tests
- **Each module tested independently**
- **Mock external tool dependencies**
- **Validate output formats and data structures**
- **Test error handling and edge cases**

### Integration Tests
- **End-to-end workflow validation**
- **Prefect flow execution testing**
- **Database operations verification**
- **Alert delivery confirmation**

### Performance Tests
- **Scan time benchmarking**
- **Memory usage monitoring**
- **Concurrent scan testing**
- **Large domain handling**

This implementation guide provides comprehensive specifications for building OpenEASD exactly as validated in the capstone research, ensuring production-ready code that meets all documented performance and functionality requirements.