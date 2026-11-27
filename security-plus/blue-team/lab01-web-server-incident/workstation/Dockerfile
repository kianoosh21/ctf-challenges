# WEB-01: the compromised public web server each student investigates.
# The attacker's artifacts are planted at launch with values unique to each student.
FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server sudo nginx cron curl ca-certificates iproute2 iputils-ping iptables tcpdump \
        bind9-dnsutils net-tools procps psmisc lsof less nano vim-tiny file binutils jq tmux \
        bash-completion \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd \
    && rm -f /etc/update-motd.d/* /etc/motd /etc/nginx/sites-enabled/default \
    && sed -i -E 's/^session\s+required\s+pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd /etc/pam.d/cron \
    && sed -i -E 's/^worker_processes .*/worker_processes 1;/' /etc/nginx/nginx.conf \
    && ssh-keygen -A
COPY sshd_config /etc/ssh/sshd_config
COPY motd /etc/motd
COPY motd /etc/skel/TICKET.txt
COPY sudoers-lab /etc/sudoers.d/lab
COPY ws-setup start.sh /usr/local/sbin/
COPY site/ /var/www/html/
COPY nginx-site /etc/nginx/sites-available/corpnet
COPY web-healthcheck.sh /usr/local/bin/web-healthcheck.sh
COPY cron.d/ /etc/cron.d/
COPY ir/ /opt/ir/
RUN chmod 440 /etc/sudoers.d/lab \
    && chmod 755 /usr/local/sbin/ws-setup /usr/local/sbin/start.sh /usr/local/bin/web-healthcheck.sh \
    && chmod 644 /etc/cron.d/* \
    && ln -s /etc/nginx/sites-available/corpnet /etc/nginx/sites-enabled/corpnet \
    && mkdir -p /var/lib/web-healthcheck /var/backups/www /opt/ir/golden \
    && cp /usr/local/bin/web-healthcheck.sh /opt/ir/golden/ \
    && sha256sum /usr/local/bin/* /etc/cron.d/web-healthcheck /etc/cron.d/logs-cleanup /etc/ssh/sshd_config \
         /etc/nginx/nginx.conf /etc/nginx/sites-available/corpnet /etc/sudoers > /opt/ir/baseline.sha256 \
    && find / -xdev -perm -4000 -type f 2>/dev/null | sort > /opt/ir/suid-baseline.txt \
    && chmod -R go-w /opt/ir \
    && touch -d '2026-10-01 09:30:00' /etc/cron.d/web-healthcheck /etc/cron.d/logs-cleanup /usr/local/bin/web-healthcheck.sh \
         /var/www/html/* /etc/nginx/sites-available/corpnet /opt/ir /opt/ir/* /opt/ir/golden/*
CMD ["/usr/local/sbin/start.sh"]
