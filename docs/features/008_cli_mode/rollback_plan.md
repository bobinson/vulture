# CLI Mode - Rollback Plan

## Risk Assessment
- **Severity**: None - CLI is an additive binary, does not affect web UI or backend
- **Blast radius**: CLI users only
- **Data loss risk**: None - CLI uses the same API as the web frontend

## Rollback Steps

### 1. Remove CLI Binary
```bash
rm -f $(which vulture-cli)
# Or if installed via go install:
rm -f $GOPATH/bin/vulture-cli
```

### 2. Remove Docker Service (if containerized)
Remove the `vulture-cli` service block from `docker-compose.yml`.

### 3. Remove CLI Source (if needed)
```bash
rm -rf backend/cmd/vulture-cli/
rm -rf backend/pkg/client/
```

### 4. Clean User Config (if needed)
```bash
rm -rf ~/.vulture/
```

## Verification
1. Web UI continues to work without any CLI dependency
2. Backend API endpoints remain fully functional
3. All existing audits and memories are unaffected

## Recovery Time
- Remove binary: 1 minute
- Full source removal: 5 minutes
