#!/bin/sh
# Services that normally run on WEB-01.
cron
nginx
exec /usr/sbin/sshd -D -e
