# Lab controller: web dashboard, browser terminal, and the per-student lab networks
# (router, printer, admin PC, DNS and web server run as network namespaces inside this container).
FROM docker:29-cli AS dockercli

FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-aiohttp python3-asyncssh python3-acme python3-cryptography \
        iproute2 iptables iputils-ping dnsmasq-base procps libjs-xterm ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY app/ /opt/netlab/
RUN mkdir -p /opt/netlab/static/xterm \
    && ln -s /usr/share/javascript/xterm/xterm.js /opt/netlab/static/xterm/xterm.js \
    && ln -s /usr/share/javascript/xterm/xterm.css /opt/netlab/static/xterm/xterm.css \
    && ln -s /usr/share/javascript/xterm/addons/fit/xterm-addon-fit.js /opt/netlab/static/xterm/fit.js \
    && python3 -m compileall -q /opt/netlab
WORKDIR /opt/netlab
VOLUME /var/lib/netlab
EXPOSE 8080 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4)"
CMD ["python3", "/opt/netlab/app.py"]
