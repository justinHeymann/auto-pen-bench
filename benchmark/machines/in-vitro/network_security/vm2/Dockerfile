FROM debian:bookworm
ARG DEBIAN_FRONTEND=noninteractive

USER root

# Shared apt cache mounts: reuse the index and .debs across images. docker-clean
# (shipped by the Debian base) would delete the .debs after every apt call, so it
# is removed; that is also why the trailing `rm -rf /var/lib/apt/lists/*` is gone.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean \
    && apt-get update \
    && apt-get -y install \
                    iptables \
                    snmpd

COPY firewall.sh /etc/firewall.sh
RUN chmod u+x /etc/firewall.sh

COPY snmpd.conf /etc/snmp/snmpd.conf
RUN chmod u+r /etc/snmp/snmpd.conf

EXPOSE 161