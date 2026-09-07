#!/bin/sh
# Import (once, if the DB is empty) and activate all Diode Watch workflows.
# Runs inside the n8n container. n8n must be stopped (not importing while the
# live process holds the SQLite DB).
set -e

count=$(n8n list:workflow | grep -v '^$' | wc -l | tr -d ' ')
if [ "$count" -eq 0 ]; then
  echo "[import] no workflows present — importing from /opt/workflows/"
  n8n import:workflow --separate --input=/opt/workflows/
else
  echo "[import] $count workflow(s) already present — skipping import"
fi

sh /opt/workflows/activate-workflows.sh
