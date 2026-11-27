FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iputils-ping iputils-arping iputils-tracepath traceroute bind9-dnsutils \
        nmap arp-scan tcpdump curl wget netcat-openbsd inetutils-telnet net-tools mtr-tiny \
        openssh-server sudo nano vim-tiny less w3m tmux bash-completion procps ca-certificates \
        ethtool iptables \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd \
    && rm -f /etc/update-motd.d/* /etc/motd \
    && sed -i -E 's/^session\s+required\s+pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd \
    && ssh-keygen -A
COPY sshd_config /etc/ssh/sshd_config
COPY motd /etc/motd
COPY motd /etc/skel/TICKET.txt
COPY sudoers-lab /etc/sudoers.d/lab
COPY ws-setup /usr/local/sbin/ws-setup
RUN chmod 440 /etc/sudoers.d/lab && chmod 755 /usr/local/sbin/ws-setup
CMD ["/usr/sbin/sshd", "-D", "-e"]
