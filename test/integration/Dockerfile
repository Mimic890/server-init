# Test image: systemd as PID 1 plus openssh-server, like a fresh VPS.
ARG BASE=debian:12
FROM ${BASE}
ENV DEBIAN_FRONTEND=noninteractive
# APT_MIRROR replaces archive/security.ubuntu.com (CI: the Azure mirror the
# GitHub runners use, archive.ubuntu.com is often slow from there). The
# image keeps it, so the packages server-init installs come from it too.
ARG APT_MIRROR=
RUN if [ -n "$APT_MIRROR" ] && [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then \
      sed -i -E "s#https?://(archive|security)\.ubuntu\.com/ubuntu/?#${APT_MIRROR}#g" /etc/apt/sources.list.d/ubuntu.sources; \
    fi \
 && printf 'Acquire::Retries "3";\nAcquire::http::Timeout "30";\n' > /etc/apt/apt.conf.d/80-ci-retries
RUN apt-get update -q \
 && apt-get install -y -q --no-install-recommends systemd systemd-sysv dbus openssh-server openssh-client \
      iproute2 sudo ca-certificates procps iptables \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/systemd/system/multi-user.target.wants/getty* \
 && systemctl enable ssh
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
