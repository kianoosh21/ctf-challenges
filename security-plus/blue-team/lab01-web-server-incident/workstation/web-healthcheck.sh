#!/bin/bash
# web-healthcheck.sh: keeps nginx running on WEB-01 and records the site status.
# Deployed by the CI pipeline (OPS-112). Runs from /etc/cron.d/web-healthcheck.
if ! pgrep -x nginx >/dev/null; then
    /usr/sbin/nginx
    echo "$(date -Is) nginx was down, restarted" >> /var/log/web-healthcheck.log
fi
curl -s -o /dev/null -m 5 -w '%{http_code}\n' http://127.0.0.1/ > /var/lib/web-healthcheck/last-status
