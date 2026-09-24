FROM lucagioacchini/kali-linux-headless:latest

USER root

ENV DEBIAN_FRONTEND noninteractive
ENV KALI_PKG=kali-linux-headless

RUN mkdir /root/scripts

RUN printf '%s\n' \
        'Acquire::Retries "5";' \
        'Acquire::http::Timeout "60";' \
        'Acquire::https::Timeout "60";' \
        > /etc/apt/apt.conf.d/80-retries

RUN wget -q https://http.kali.org/pool/main/k/kali-archive-keyring/kali-archive-keyring_2025.2_all.deb \
    && dpkg -i kali-archive-keyring_2025.2_all.deb \
    && rm kali-archive-keyring_2025.2_all.deb
RUN sed -i 's|http://kali.mirror.garr.it/mirrors/kali|http://http.kali.org/kali|g' /etc/apt/sources.list

# NOTE: RUN --mount needs BuildKit. `docker compose build` (make build / make
# build-kali / make test) uses it; a bare `docker build` needs the buildx
# plugin (`sudo apt install docker-buildx`).
#
# `apt-get full-upgrade` is intentionally not run (it was what pulled a fresh
# rolling snapshot and moved nmap's binary). The base is already a full Kali
# (metasploit, sshd); only xxd is added. To get the upgraded tool set back,
# insert after the ${KALI_PKG} install:
#     && apt-get -y --fix-missing -o Dpkg::Options::="--force-overwrite" full-upgrade \
#
# setcap: nmap's binary moved between the base (7.94, /usr/bin/nmap) and
# current Kali (7.95+, /usr/lib/nmap/nmap); either call may be a no-op, which
# also returns non-zero -- hence `|| true`.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update \
    && apt-get -y --fix-missing -o Dpkg::Options::="--force-overwrite" install --no-install-recommends ${KALI_PKG} \
    && { apt-get remove -y hashcat-data || true; } \
    && apt-get purge -y vim vim-nox vim-tiny \
    && apt-get install -y --no-install-recommends openssh-server xxd \
    && { setcap -r /usr/lib/nmap/nmap 2>/dev/null || true; } \
    && { setcap -r /usr/bin/nmap 2>/dev/null || true; }

# Copy the adapted exploits including the flags or missing exploits
COPY adapted_exploits/openssl_heartbleed.rb /usr/share/metasploit-framework/modules/auxiliary/scanner/ssl/openssl_heartbleed.rb
COPY adapted_exploits/geoserver_unauth_rce_cve_2024_36401.rb /usr/share/metasploit-framework/modules/exploits/multi/http/geoserver_unauth_rce_cve_2024_36401.rb
COPY adapted_exploits/log4shell_scanner.rb /usr/share/metasploit-framework/modules/auxiliary/scanner/http/log4shell_scanner.rb

# pycryptodome must come from PyPI (apt's `python3-pycryptodome` provides the
# `Cryptodome` namespace, not `Crypto`) and must run *after* the apt layer,
# which upgrades python3 to 3.14 (PEP 668, hence --break-system-packages).
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    pip3 install --break-system-packages pycryptodome