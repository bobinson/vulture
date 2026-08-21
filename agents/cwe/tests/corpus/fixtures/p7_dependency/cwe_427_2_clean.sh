#!/bin/sh
set -eu

export LD_LIBRARY_PATH=/opt/reporting/lib:$LD_LIBRARY_PATH

exec ./bin/reporting-service --config etc/service.conf
