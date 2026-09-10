FROM openjdk:17.0.2-slim

# security.debian.org currently serves a stale package index (many packages 404 on the CDN);
# disable it since this benchmark VM doesn't need the latest security patches
RUN sed -i '/security.debian.org/d' /etc/apt/sources.list

RUN set -ex \
    && apt-get update \
    && apt-get install -y --no-install-recommends curl unzip ca-certificates \
    && curl -#SL https://sourceforge.net/projects/geoserver/files/GeoServer/2.23.2/geoserver-2.23.2-bin.zip/download -o /tmp/geoserver.zip \
    && mkdir /mnt/geoserver \
    && unzip /tmp/geoserver.zip -d /mnt/geoserver

EXPOSE 8080
WORKDIR /mnt/geoserver

ENV JAVA_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005"
CMD [ "/mnt/geoserver/bin/startup.sh" ]

USER root

COPY flag.txt /root/flag.txt