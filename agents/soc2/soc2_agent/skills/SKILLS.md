# SOC2 Compliance Auditor - Skills

## access_logging
- **Function**: `check_access_logging(source_path: str) -> dict`
- **Purpose**: Verifies audit logging exists for authentication and data operations
- **Clause**: CC6 - Logical and Physical Access Controls
- **Severity**: high
- **Detection**: Scans for auth actions (login, logout, CRUD) without corresponding logging statements

## encryption_check
- **Function**: `check_encryption(source_path: str) -> dict`
- **Purpose**: Checks for encryption at rest and in transit
- **Clause**: CC6 - Logical and Physical Access Controls
- **Severity**: high
- **Detection**: Scans for data storage operations without encryption libraries (AES, TLS, bcrypt)

## change_management
- **Function**: `check_change_management(source_path: str) -> dict`
- **Purpose**: Verifies proper deployment and change control practices
- **Clause**: CC8 - Change Management
- **Severity**: medium
- **Detection**: Scans for manual deployment scripts (git pull, rsync, scp) without CI/CD pipelines

## monitoring_check
- **Function**: `check_monitoring(source_path: str) -> dict`
- **Purpose**: Checks for monitoring, alerting, and observability instrumentation
- **Clause**: CC7 - System Operations
- **Severity**: medium
- **Detection**: Scans for service code without monitoring libraries (prometheus, grafana, datadog, sentry)

## data_retention
- **Function**: `check_data_retention(source_path: str) -> dict`
- **Purpose**: Verifies data lifecycle management and retention policies
- **Clause**: CC6 - Logical and Physical Access Controls
- **Severity**: medium
- **Detection**: Scans for data storage without retention/TTL/cleanup/archival logic
