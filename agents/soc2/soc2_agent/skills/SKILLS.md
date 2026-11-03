# SOC2 Compliance Auditor - Skills

## access_logging
- **Function**: `check_access_logging(source_path: str) -> dict`
- **Purpose**: Verifies audit logging exists for authentication and data operations
- **Clause**: CC6 - Logical and Physical Access Controls
- **Severity**: high
- **Detection**: Scans for auth actions (login, logout, CRUD) without corresponding logging statements. Login/logout/auth definitions count unconditionally and are reported at line 1. A `create_`/`update_`/`delete_` definition counts only with an actor in scope and is reported at its `def` line. The actor is a parameter whose name denotes a principal or a request (`user`, `principal`, `actor`, `session`, `request`/`req`, `account`, `identity`, `ctx`/`context`, `caller`, as a whole word of the name, also as `username`/`userid`/plural), or a value the body uses (`self.request.user`, `current_user`, `g.user`, `caller.id`; in a body only `user`, `principal`, `actor`, `request`/`req`, `caller`, as exact words, and never a called name such as `self._request(...)`). Signature and body are read with strings and comments blanked, so a `")"` default does not end the parameter list and a docstring naming a user is no actor

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
- **Detection**: Scans for manual deployment scripts (git pull, rsync, scp) without CI/CD pipelines. rsync/scp count only as whole commands that copy to another host: an operand of remote shape (`[user@]host:path`, `host:` for the remote home directory, `rsync://`, `host::module`), a remote-shell option (`-e`, `--rsh`), or a value concatenated with a string opening with the colon (`host + ":" + dest`) is medium. User and host may be placeholders: shell/make variables (`"$HOST":`, `$(HOST)`), CI and template expressions (`${{ secrets.H }}`, `{{ host }}`) and format slots (`%s`, `{}`). A destination that is one placeholder (`rsync dist/ "$TARGET"`) is low; a local copy, an option value (`--chown=www:www`) or a `key: value` pair is not reported. Backslash-continued lines are read as one command; comments and displayed text (`echo`/`printf`, print/log calls) are not commands

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
