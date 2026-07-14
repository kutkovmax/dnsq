#ifndef DNSQ_DNS_H
#define DNSQ_DNS_H

#include <stddef.h>
#include <stdint.h>

#define DNSQ_MAX_RECORDS 64

typedef struct {
    char name[256];
    char data[1024];
    uint32_t ttl;
    uint16_t type;
} dns_record;

typedef struct {
    dns_record records[DNSQ_MAX_RECORDS];
    size_t count;
    unsigned rcode;
} dns_reply;

int dns_parse(const uint8_t *buf, size_t len, uint16_t id,
              uint16_t question_type, dns_reply *reply);

#endif
