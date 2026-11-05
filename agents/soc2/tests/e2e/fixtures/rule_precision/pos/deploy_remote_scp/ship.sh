#!/bin/sh
set -eu
tar -czf app.tar build/
scp app.tar user@host:/srv
