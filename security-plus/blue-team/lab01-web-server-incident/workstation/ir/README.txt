WEB-01 incident response notes (maintained by IT Ops)
=====================================================

Role         : public website (nginx), DMZ 10.20.0.10
Gateway      : FW-01 10.20.0.1
DNS          : 10.20.0.53
Monitoring   : MON-01 10.20.0.100 requests http://10.20.0.10/ every 30 s.
               Customers use this site: it must stay up while you work.
Internal     : 10.20.0.0/24 is ours. Staff admin PC 10.20.0.15, CI server
               BUILD-01 10.20.0.5. Anything else is the internet.

Accounts that should exist on WEB-01
  root         administrator. Only root has UID 0.
  @ACCT@       CI deploy account. Deploys the website. It may run
               /usr/local/bin/web-healthcheck.sh with sudo.
  you          your own incident responder account

Authorized SSH keys
  ci@build-01  CI pipeline key, on the @ACCT@ account only.
               No other keys are approved, root has none.

Scheduled jobs that should exist (/etc/cron.d)
  web-healthcheck   every 2 minutes, keeps nginx running
  logs-cleanup      daily, removes old site backups

Known-good baselines from the golden image
  /opt/ir/baseline.sha256    sudo sha256sum -c /opt/ir/baseline.sha256
  /opt/ir/suid-baseline.txt  SUID programs that ship with the image
  /opt/ir/golden/            known-good copies of scripts
