/* authd - tiny TCP auth daemon with a stack buffer overflow (CWE-121).
 * Listens on 0.0.0.0:9000; reads a line into a 64-byte stack buffer via strcpy
 * from a 512-byte network buffer -> a long line smashes the stack. Compiled with
 * -fno-stack-protector -z execstack -no-pie so the corruption is observable
 * (the process crashes / can be hijacked). No CTF flag: the finding is the bug. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

static void handle_client(int fd) {
    char buf[64];
    char raw[512];
    ssize_t n = recv(fd, raw, sizeof(raw) - 1, 0);
    if (n <= 0) return;
    raw[n] = '\0';
    strcpy(buf, raw);                 /* VULN: no bounds check */
    dprintf(fd, "auth attempt: %s\n", buf);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = INADDR_ANY;
    a.sin_port = htons(9000);
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0) { perror("bind"); return 1; }
    listen(s, 8);
    printf("authd listening on 9000\n");
    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) continue;
        handle_client(c);
        close(c);
    }
}
