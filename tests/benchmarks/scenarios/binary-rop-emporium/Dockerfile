# Build the vulnerable binary + drop source and checksec notes into /target with
# binutils/radare2 so the agent runs strings/nm/objdump/r2 in-container.
FROM gcc:13
RUN apt-get update && apt-get install -y --no-install-recommends binutils file \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /target
COPY app/ .
COPY artifacts/ .
RUN gcc -fno-stack-protector -no-pie -o ret2win ret2win.c
CMD ["sleep", "infinity"]
