#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Hidden 'win' function an attacker redirects execution to via ROP.
void ret2win() {
    puts("win: flag contents would print here");
    system("/bin/cat /target/flag.txt 2>/dev/null");
}

void pwnme() {
    char buf[32];
    puts("send your input:");
    gets(buf);            // VULN: unbounded read -> stack overflow (CWE-121)
    printf("got: %s\n", buf);
}

int main() { pwnme(); return 0; }
