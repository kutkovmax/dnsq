#define _POSIX_C_SOURCE 200809L
#include "dns.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int make_query(const char *name, unsigned char *buf, size_t *length) {
    size_t n = strlen(name), pos = 12, start = 0;
    if (!n || n > 253) return -1;
    if (name[n - 1] == '.') --n;
    if (!n) return -1;
    memset(buf, 0, 512);
    buf[0] = 0x12; buf[1] = 0x34;
    buf[2] = 1; buf[5] = 1;
    for (size_t i = 0; i <= n; ++i) {
        if (i != n && name[i] != '.') continue;
        size_t label = i - start;
        if (!label || label > 63 || pos + label + 6 > 512) return -1;
        buf[pos++] = (unsigned char)label;
        memcpy(buf + pos, name + start, label);
        pos += label; start = i + 1;
    }
    buf[pos++] = 0;
    buf[pos++] = 0; buf[pos++] = 1;
    buf[pos++] = 0; buf[pos++] = 1;
    *length = pos;
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        puts("Usage: dnsq DOMAIN (A records, system DNS server)");
        return 0;
    }
    if (argc != 2) {
        fprintf(stderr, "Usage: dnsq DOMAIN\n");
        return 2;
    }
    unsigned char query[512], answer[4096];
    size_t qlen;
    if (make_query(argv[1], query, &qlen)) {
        fprintf(stderr, "dnsq: invalid domain\n");
        return 2;
    }
    FILE *resolv = fopen("/etc/resolv.conf", "r");
    char line[512], server[256] = "";
    if (!resolv) { perror("dnsq: resolv.conf"); return 1; }
    while (fgets(line, sizeof line, resolv)) {
        if (sscanf(line, " nameserver %255s", server) == 1) break;
    }
    fclose(resolv);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(53) };
    if (inet_pton(AF_INET, server, &addr.sin_addr) != 1) {
        fprintf(stderr, "dnsq: no IPv4 DNS server in /etc/resolv.conf\n");
        return 1;
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("dnsq: socket"); return 1; }
    struct timeval timeout = { .tv_sec = 3 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0
        || connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0
        || send(fd, query, qlen, 0) != (ssize_t)qlen) {
        perror("dnsq: send"); close(fd); return 1;
    }
    ssize_t count = recv(fd, answer, sizeof answer, 0);
    close(fd);
    if (count < 0) { perror("dnsq: receive"); return 1; }
    dns_reply reply;
    if (dns_parse(answer, (size_t)count, 0x1234, 1, &reply)) {
        fprintf(stderr, "dnsq: bad DNS reply\n"); return 1;
    }
    if (reply.rcode) { fprintf(stderr, "dnsq: DNS error %u\n", reply.rcode); return 1; }
    for (size_t i = 0; i < reply.count; ++i) puts(reply.records[i].data);
    return 0;
}
