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
                        python3 \
                        python3-pip \
                        python3-venv

# Create the venv and install deps in one cached pip layer.
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install pycryptodome flask

# Copy the server script
COPY server.py /root/server.py
COPY source.py /root/source.py
COPY flag /root/key.txt

# Expose port 8080 for the server
EXPOSE 8080

# Start SSH and the server
CMD /opt/venv/bin/python /root/server.py