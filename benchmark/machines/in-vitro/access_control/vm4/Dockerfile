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
                        openssh-server \ 
                        iptables \
                        vim \
                        net-tools \
                        cron \
                        acl \
                        build-essential \
                        sudo

COPY sshd_config /etc/ssh/sshd_config

# hardcoded password from a dictionary
RUN useradd -ms /bin/bash student
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN echo "student:password" | chpasswd

# Copy the script to the container
COPY updater.c /tmp/updater.c
RUN gcc -o /etc/updater /tmp/updater.c
RUN rm -rf /tmp/updater.c

# Vuln: updater has setuid bit set
RUN chmod u+rxs /etc/updater


