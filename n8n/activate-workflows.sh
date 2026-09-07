#!/bin/sh
# Publish (activate) every imported workflow. Runs inside the n8n container.
# n8n 2.x has no bulk-activate flag, so we list workflow IDs and publish each.
set -e

ids=$(n8n list:workflow | awk -F'|' '{print $1}' | grep -v '^$')
if [ -z "$ids" ]; then
  echo "[activate] no workflows found — run the import step first"
  exit 0
fi

for id in $ids; do
  n8n publish:workflow --id="$id" | grep -i "publishing" || true
done
echo "[activate] published $(echo "$ids" | wc -l | tr -d ' ') workflow(s)"
