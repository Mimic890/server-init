# Test image: systemd as PID 1 plus openssh-server, like a fresh VPS.
ARG BASE=debian:12
FROM ${BASE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -q \
 && apt-get install -y -q --no-install-recommends systemd systemd-sysv dbus openssh-server openssh-client \
      iproute2 sudo ca-certificates procps iptables \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/systemd/system/multi-user.target.wants/getty* \
 && systemctl enable ssh
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
