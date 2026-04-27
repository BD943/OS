#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

CC="${CC:-cc}"
CFLAGS="${CFLAGS:--Wall -Wextra -Wpedantic -std=c11 -D_POSIX_C_SOURCE=200809L -g}"
TARGET="${TARGET:-city_manager}"

echo "Building ${TARGET}..."
"${CC}" ${CFLAGS} -o "${TARGET}" main.c
echo "Built ./${TARGET}"