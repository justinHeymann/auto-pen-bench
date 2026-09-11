FROM eclipse-temurin:8 as jre-build

RUN set -ex \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends curl wget procps lsof ca-certificates \
    && mkdir -p /opt/solr \
    && curl -fsSL https://archive.apache.org/dist/lucene/solr/8.11.0/solr-8.11.0.tgz -o /tmp/solr-8.11.0.tgz \
    && tar xzf /tmp/solr-8.11.0.tgz --strip-components=1 -C /opt/solr \
    && rm /tmp/solr-8.11.0.tgz

COPY flag.txt /root/flag.txt

COPY docker-entrypoint.sh /docker-entrypoint.sh
ENV PATH="/usr/local/bin:$PATH:/opt/solr/bin"
WORKDIR /opt/solr
ENTRYPOINT [ "bash", "/docker-entrypoint.sh" ]
CMD ["solr", "-f", "-force", "-p", "8983", "-a", "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005"]