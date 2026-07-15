#include "dns.h"

#include <assert.h>
#include <string.h>

static const unsigned char good[] = {
    0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
    1, 'a', 0, 0, 1, 0, 1,
    0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4
};

int main(void) {
    dns_reply reply;
    assert(dns_parse(good, sizeof good, 0x1234, 1, &reply) == 0);
    assert(reply.count == 1 && reply.records[0].ttl == 60);
    assert(strcmp(reply.records[0].data, "1.2.3.4") == 0);
    assert(strcmp(reply.records[0].name, "a") == 0);
    for (size_t n = 0; n < sizeof good; ++n)
        assert(dns_parse(good, n, 0x1234, 1, &reply) != 0);
    assert(dns_parse(good, sizeof good, 0x4321, 1, &reply) != 0);
    unsigned char bad[sizeof good];
    memcpy(bad, good, sizeof bad);
    bad[20] = 19; /* Answer name points to itself. */
    assert(dns_parse(bad, sizeof bad, 0x1234, 1, &reply) != 0);
    bad[20] = 255; /* Pointer outside packet. */
    assert(dns_parse(bad, sizeof bad, 0x1234, 1, &reply) != 0);
    memcpy(bad, good, sizeof bad);
    bad[30] = 5; /* RDATA claims more bytes than remain. */
    assert(dns_parse(bad, sizeof bad, 0x1234, 1, &reply) != 0);
    memcpy(bad, good, sizeof bad);
    bad[2] |= 2; /* UDP response is truncated. */
    assert(dns_parse(bad, sizeof bad, 0x1234, 1, &reply) != 0);
    static const struct {
        unsigned type;
        unsigned char rdata[20];
        size_t size;
        const char *result;
    } cases[] = {
        {28, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 16, "::1"},
        {2, {0xc0, 0x0c}, 2, "a"},
        {5, {0xc0, 0x0c}, 2, "a"},
        {15, {0, 10, 0xc0, 0x0c}, 4, "10 a"},
        {15, {0, 0, 0}, 3, "0 ."},
        {16, {3, 'f', 'o', 'o'}, 4, "foo"}
    };
    for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
        unsigned char packet[sizeof good + 20];
        memcpy(packet, good, sizeof good);
        packet[16] = (unsigned char)cases[i].type;
        packet[22] = (unsigned char)cases[i].type;
        packet[30] = (unsigned char)cases[i].size;
        memcpy(packet + 31, cases[i].rdata, cases[i].size);
        assert(dns_parse(packet, 31 + cases[i].size, 0x1234,
                         (unsigned short)cases[i].type, &reply) == 0);
        assert(reply.count == 1);
        assert(strcmp(reply.records[0].data, cases[i].result) == 0);
    }
    return 0;
}
