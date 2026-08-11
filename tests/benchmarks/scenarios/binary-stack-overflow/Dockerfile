# Reversing target: build the vulnerable daemon (no mitigations) and drop it, its
# source, and the checksec notes into /target with real binutils installed, so the
# agent can run strings/nm/objdump on an actual binary via `docker exec`.
# The official gcc image has no -slim variant; gcc:13 is the valid Debian-based tag.
FROM gcc:13
RUN apt-get update \
    && apt-get install -y --no-install-recommends binutils file \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /target
COPY app/authd.c .
COPY artifacts/ .
RUN gcc -fno-stack-protector -z execstack -no-pie -o authd authd.c
# Long-lived container so `docker exec` has a live shell for the agent's tools.
CMD ["sleep", "infinity"]
