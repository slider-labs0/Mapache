// Decompiled from the MIPS binary /www/cgi-bin/pingtest.cgi (firmware extract)
int handle_request(void) {
    char cmd[128];
    char *host = getenv("QUERY_STRING");   // e.g. host=8.8.8.8 (attacker-controlled)
    // VULN 1: user input flows into a shell command (CWE-78)
    sprintf(cmd, "ping -c 3 %s", host);
    system(cmd);
    char buf[64];
    // VULN 2: unbounded copy of a header into a fixed buffer (CWE-121)
    strcpy(buf, getenv("REMOTE_ADDR"));
    return 0;
}
