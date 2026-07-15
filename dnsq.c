#define _POSIX_C_SOURCE 200809L
#include "dns.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static void usage(FILE *out) {
    fprintf(out, "Usage: dnsq DOMAIN [-t A|AAAA|MX|NS|CNAME|TXT] [-s SERVER]\n"
                 "SERVER is an IPv4 or IPv6 address; default is /etc/resolv.conf.\n");
}

static int make_query(const char *name, uint16_t type, uint16_t id,
                      unsigned char *buf, size_t *length) {
    size_t n = strlen(name), pos = 12, start = 0;
    if (!n || n > 253) return -1;
    if (name[n - 1] == '.') --n;
    if (!n) return -1;
    memset(buf, 0, 512);
    buf[0] = (unsigned char)(id >> 8); buf[1] = (unsigned char)id;
    buf[2] = 1; buf[5] = 1;
    for (size_t i = 0; i <= n; ++i) {
        if (i != n && name[i] != '.') {
            unsigned char c = (unsigned char)name[i];
            if (c <= 32 || c >= 127) return -1;
            continue;
        }
        size_t label = i - start;
        if (!label || label > 63 || pos + label + 6 > 512) return -1;
        buf[pos++] = (unsigned char)label;
        memcpy(buf + pos, name + start, label);
        pos += label; start = i + 1;
    }
    buf[pos++] = 0;
    buf[pos++] = (unsigned char)(type >> 8); buf[pos++] = (unsigned char)type;
    buf[pos++] = 0; buf[pos++] = 1;
    *length = pos;
    return 0;
}

static int default_server(char *out, size_t cap) {
    FILE *file = fopen("/etc/resolv.conf", "r");
    if (!file) return -1;
    char line[512], value[256];
    int found = -1;
    while (fgets(line, sizeof line, file)) {
        if (sscanf(line, " nameserver %255s", value) == 1) {
            if (strlen(value) < cap) { strcpy(out, value); found = 0; }
            break;
        }
    }
    fclose(file);
    return found;
}

static int server_address(const char *text, struct sockaddr_storage *addr,
                          socklen_t *addrlen) {
    memset(addr, 0, sizeof *addr);
    struct sockaddr_in *v4 = (struct sockaddr_in *)addr;
    if (inet_pton(AF_INET, text, &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET; v4->sin_port = htons(53);
        *addrlen = sizeof *v4; return AF_INET;
    }
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)addr;
    if (inet_pton(AF_INET6, text, &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6; v6->sin6_port = htons(53);
        *addrlen = sizeof *v6; return AF_INET6;
    }
    return -1;
}

int main(int argc, char **argv) {
    const char *domain = NULL, *server = NULL;
    uint16_t type = 1, id;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0) { usage(stdout); return 0; }
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            if (dns_type(argv[++i], &type)) { fprintf(stderr, "dnsq: unsupported type\n"); return 2; }
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            server = argv[++i];
        } else if (argv[i][0] == '-' || domain) {
            usage(stderr); return 2;
        } else domain = argv[i];
    }
    if (!domain) { usage(stderr); return 2; }
    char default_addr[256];
    if (!server) {
        if (default_server(default_addr, sizeof default_addr)) {
            fprintf(stderr, "dnsq: no nameserver in /etc/resolv.conf\n"); return 1;
        }
        server = default_addr;
    }
    if (getrandom(&id, sizeof id, 0) != sizeof id) { perror("dnsq: random"); return 1; }
    unsigned char query[512], answer[4096];
    size_t qlen;
    if (make_query(domain, type, id, query, &qlen)) {
        fprintf(stderr, "dnsq: invalid domain name\n"); return 2;
    }
    struct sockaddr_storage addr;
    socklen_t addrlen;
    int family = server_address(server, &addr, &addrlen);
    if (family < 0) { fprintf(stderr, "dnsq: invalid server address: %s\n", server); return 2; }
    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0) { perror("dnsq: socket"); return 1; }
    struct timeval timeout = { .tv_sec = 3 };
    struct timespec start, stop;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0
        || connect(fd, (struct sockaddr *)&addr, addrlen) < 0
        || clock_gettime(CLOCK_MONOTONIC, &start) < 0
        || send(fd, query, qlen, 0) != (ssize_t)qlen) {
        perror("dnsq: send"); close(fd); return 1;
    }
    ssize_t count = recv(fd, answer, sizeof answer, MSG_TRUNC);
    int saved_errno = errno;
    if (clock_gettime(CLOCK_MONOTONIC, &stop) < 0) { perror("dnsq: clock"); close(fd); return 1; }
    close(fd);
    if (count < 0) {
        errno = saved_errno;
        if (errno == EAGAIN || errno == EWOULDBLOCK) fprintf(stderr, "dnsq: request timed out\n");
        else perror("dnsq: receive");
        return 1;
    }
    if ((size_t)count > sizeof answer) { fprintf(stderr, "dnsq: reply too large\n"); return 1; }
    dns_reply reply;
    if (dns_parse(answer, (size_t)count, id, type, &reply)) {
        fprintf(stderr, "dnsq: invalid or truncated DNS reply\n"); return 1;
    }
    if (reply.rcode) { fprintf(stderr, "dnsq: DNS server returned RCODE %u\n", reply.rcode); return 1; }
    for (size_t i = 0; i < reply.count; ++i) {
        dns_record *r = &reply.records[i];
        printf("%s\t%u\t%s\t%s\n", r->name, r->ttl, dns_type_name(r->type), r->data);
    }
    double ms = (stop.tv_sec - start.tv_sec) * 1000.0
                + (stop.tv_nsec - start.tv_nsec) / 1000000.0;
    printf("Response time: %.2f ms\n", ms);
    return 0;
}
