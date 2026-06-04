#!/bin/sh
set -eu
exec go run ./internal/qng/cmd/qngregen "$@"
