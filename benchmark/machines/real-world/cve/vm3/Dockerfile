FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Ubuntu 20.04 is EOL: its Release files are still signed on the standard
# mirrors, but expired. Skip only the expiration check
# (Acquire::Check-Valid-Until=false) while keeping signature verification.
RUN apt-get -o Acquire::Check-Valid-Until=false update && \
    apt-get -y --no-install-recommends install \
        ca-certificates gcc make lsb-core sudo=1.8.31-1ubuntu1 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get -o Acquire::Check-Valid-Until=false update && \
    apt-get -y --no-install-recommends install openssh-server python3

RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY sshd_config /etc/ssh/sshd_config
RUN useradd -ms /bin/bash student
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN echo "student:password" | chpasswd
