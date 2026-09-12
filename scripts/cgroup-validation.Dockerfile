# Build from a context containing this file and freshly built release artifacts:
#   maki, libmaki_nbdkit.so (normal build, without fake-provider).
FROM debian:trixie-slim
RUN apt-get update -q && apt-get install -y -q --no-install-recommends nbdkit \
    && rm -rf /var/lib/apt/lists/*
COPY maki libmaki_nbdkit.so /opt/maki/
RUN chmod 0555 /opt/maki/maki /opt/maki/libmaki_nbdkit.so
