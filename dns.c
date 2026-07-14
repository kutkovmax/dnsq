#include "dns.h"

#include <arpa/inet.h>
#include <string.h>

static uint16_t read16(const uint8_t *p) {
    return (uint16_t)((unsigned)p[0] << 8 | p[1]);
}

static uint32_t read32(const uint8_t *p) {
    return (uint32_t)read16(p) << 16 | read16(p + 2);
}

/* next points past the encoded name, including a final compression pointer. */
static int read_name(const uint8_t *buf, size_t len, size_t at,
                     size_t *next, char *out, size_t cap) {
    size_t pos = at, used = 0, wire = 1;
    int jumped = 0;
    for (size_t hops = 0; hops < len; ++hops) {
        if (pos >= len) return -1;
        unsigned c = buf[pos++];
        if ((c & 0xc0) == 0xc0) {
            if (pos >= len) return -1;
            size_t target = ((size_t)(c & 0x3f) << 8) | buf[pos++];
            if (target >= pos - 2 || target >= len) return -1;
            if (!jumped) { *next = pos; jumped = 1; }
            pos = target;
            continue;
        }
        if (c & 0xc0) return -1;
        if (!c) {
            if (!jumped) *next = pos;
            if (used >= cap) return -1;
            out[used] = 0;
            return 0;
        }
        wire += c + 1;
        if (wire > 255 || c > len - pos || used + c + (used != 0) >= cap) return -1;
        if (used) out[used++] = '.';
        memcpy(out + used, buf + pos, c);
        used += c;
        pos += c;
    }
    return -1;
}

int dns_parse(const uint8_t *buf, size_t len, uint16_t id,
              uint16_t question_type, dns_reply *reply) {
    if (len < 12 || read16(buf) != id) return -1;
    uint16_t flags = read16(buf + 2);
    if (!(flags & 0x8000) || (flags & 0x7800) || (flags & 0x0200)
        || read16(buf + 4) != 1) return -1;
    memset(reply, 0, sizeof *reply);
    reply->rcode = flags & 15;
    size_t pos = 12;
    char question[256];
    if (read_name(buf, len, pos, &pos, question, sizeof question)
        || len - pos < 4 || read16(buf + pos) != question_type
        || read16(buf + pos + 2) != 1) return -1;
    pos += 4;
    for (unsigned section = 0; section < 3; ++section) {
        unsigned count = read16(buf + 6 + section * 2);
        for (unsigned i = 0; i < count; ++i) {
            char name[256];
            if (read_name(buf, len, pos, &pos, name, sizeof name)
                || len - pos < 10) return -1;
            uint16_t type = read16(buf + pos), klass = read16(buf + pos + 2);
            uint32_t ttl = read32(buf + pos + 4);
            size_t rdlen = read16(buf + pos + 8);
            pos += 10;
            if (rdlen > len - pos) return -1;
            if (section == 0 && klass == 1 && type == 1) {
                if (rdlen != 4 || reply->count == DNSQ_MAX_RECORDS) return -1;
                dns_record *r = &reply->records[reply->count++];
                memcpy(r->name, name, strlen(name) + 1);
                r->type = type;
                r->ttl = ttl;
                if (!inet_ntop(AF_INET, buf + pos, r->data, sizeof r->data)) return -1;
            }
            pos += rdlen;
        }
    }
    return 0;
}
