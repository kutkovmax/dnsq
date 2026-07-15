#include "dns.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

int dns_type(const char *text, uint16_t *type) {
    static const struct { const char *name; uint16_t value; } types[] = {
        {"A", 1}, {"NS", 2}, {"CNAME", 5}, {"MX", 15}, {"TXT", 16}, {"AAAA", 28}
    };
    for (size_t i = 0; i < sizeof types / sizeof *types; ++i) {
        if (strcmp(text, types[i].name) == 0) { *type = types[i].value; return 0; }
    }
    return -1;
}

const char *dns_type_name(uint16_t type) {
    switch (type) {
    case 1: return "A"; case 2: return "NS"; case 5: return "CNAME";
    case 15: return "MX"; case 16: return "TXT"; case 28: return "AAAA";
    default: return "?";
    }
}

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
            if (!used) {
                if (cap < 2) return -1;
                out[0] = '.';
                out[1] = 0;
                return 0;
            }
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

static int record_data(const uint8_t *buf, size_t len, size_t at, size_t end,
                       dns_record *r) {
    size_t next;
    if (r->type == 1 || r->type == 28) {
        if (end - at != (r->type == 1 ? 4u : 16u)) return -1;
        return inet_ntop(r->type == 1 ? AF_INET : AF_INET6, buf + at,
                         r->data, sizeof r->data) ? 0 : -1;
    }
    if (r->type == 2 || r->type == 5) {
        if (read_name(buf, len, at, &next, r->data, sizeof r->data)) return -1;
        return next == end ? 0 : -1;
    }
    if (r->type == 15) {
        char host[256];
        if (end - at < 3 || read_name(buf, len, at + 2, &next, host, sizeof host)
            || next != end) return -1;
        int n = snprintf(r->data, sizeof r->data, "%u %s", read16(buf + at), host);
        return n < 0 || (size_t)n >= sizeof r->data ? -1 : 0;
    }
    if (r->type == 16) {
        size_t used = 0;
        while (at < end) {
            size_t chunk = buf[at++];
            if (chunk > end - at) return -1;
            if (used && used + 1 >= sizeof r->data) return -1;
            if (used) r->data[used++] = ' ';
            for (size_t i = 0; i < chunk; ++i) {
                unsigned char c = buf[at++];
                if (c < 32 || c > 126 || c == '\\' || c == '"') {
                    if (used + 4 >= sizeof r->data) return -1;
                    int n = snprintf(r->data + used, sizeof r->data - used, "\\x%02x", c);
                    if (n != 4) return -1;
                    used += 4;
                } else {
                    if (used + 1 >= sizeof r->data) return -1;
                    r->data[used++] = (char)c;
                }
            }
        }
        r->data[used] = 0;
    }
    return 0;
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
            if (section == 0 && klass == 1 && strcmp(dns_type_name(type), "?") != 0) {
                if (reply->count == DNSQ_MAX_RECORDS) return -1;
                dns_record *r = &reply->records[reply->count++];
                memcpy(r->name, name, strlen(name) + 1);
                r->type = type;
                r->ttl = ttl;
                if (record_data(buf, len, pos, pos + rdlen, r)) return -1;
            }
            pos += rdlen;
        }
    }
    return 0;
}
