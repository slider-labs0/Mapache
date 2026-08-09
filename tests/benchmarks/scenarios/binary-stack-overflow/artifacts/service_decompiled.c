/* Decompiled from ./authd (x86-64 ELF, stripped symbols recovered).
 * A tiny TCP auth daemon: reads a line from the client into a fixed buffer. */

#include <string.h>
#include <unistd.h>
#include <stdio.h>

void handle_client(int fd) {
    char buf[64];
    char raw[512];

    ssize_t n = recv(fd, raw, sizeof(raw) - 1, 0);
    if (n <= 0)
        return;
    raw[n] = '\0';

    /* Copy the received credential line into the local buffer. */
    strcpy(buf, raw);          /* <-- no bounds check: raw can be up to 511 bytes */

    printf("auth attempt: %s\n", buf);
    /* ... credential check omitted ... */
}
