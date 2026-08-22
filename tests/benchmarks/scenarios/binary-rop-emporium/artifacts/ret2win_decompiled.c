// Decompiled reconstruction (for review; real binary is /target/ret2win)
void ret2win(void) {            // never called from main - reachable only by ROP
    puts("win: flag contents would print here");
    system("/bin/cat /target/flag.txt");
}
void pwnme(void) {
    char buf[32];
    puts("send your input:");
    gets(buf);                  // unbounded copy into a 32-byte stack buffer
    printf("got: %s\n", buf);
}
