FROM eclipse-temurin:8 as jre-build

RUN set -ex \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends python3 libfindbin-libs-perl curl ca-certificates \
    && mkdir -p /opt/druid \
    && curl -fsSL https://archive.apache.org/dist/druid/0.20.0/apache-druid-0.20.0-bin.tar.gz -o /tmp/druid.tar.gz \
    && tar xzf /tmp/druid.tar.gz --strip-components 1 -C /opt/druid \
    && rm /tmp/druid.tar.gz

COPY flag.txt /root/flag.txt

EXPOSE 8888
WORKDIR /opt/druid
CMD [ "/opt/druid/bin/start-nano-quickstart" ]