#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

#define ET_IP 0x0800
#define ET_ARP 0x0806
#define TCP_P 6
#define UDP_P 17
#define ET_LEN 14

typedef unsigned short u_int16_t;
typedef unsigned int u_int32_t;
typedef unsigned char u_int8_t;

struct ip {
    u_int8_t ip_hl:4;
    u_int8_t ip_v:4;
    u_int8_t ip_tos;
    u_int16_t ip_len;
    u_int16_t ip_id;
    u_int16_t ip_off;
    u_int8_t ip_ttl;
    u_int8_t ip_p;
    u_int16_t ip_sum;
    u_int32_t ip_src, ip_dst;
};

struct tcphdr {
    u_int16_t th_sport;
    u_int16_t th_dport;
    u_int32_t th_seq;
    u_int32_t th_ack;
    u_int8_t th_x2:4;
    u_int8_t th_off:4;
    u_int8_t th_flags;
    u_int16_t th_win;
    u_int16_t th_sum;
    u_int16_t th_urp;
};

struct udphdr {
    u_int16_t uh_sport;
    u_int16_t uh_dport;
    u_int16_t uh_ulen;
    u_int16_t uh_sum;
};

struct ether_header {
    u_int8_t ether_dhost[6];
    u_int8_t ether_shost[6];
    u_int16_t ether_type;
};

void print_payload(const u_char *payload, const int payload_len) {
    for (int i = 0; i < payload_len && i < 10; i++) {
        printf("%02x ", payload[i]);
    }
    printf("\n");
}

void print_mac(const u_int8_t *m) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

void print_ip(u_int32_t ip) {
    printf("%d.%d.%d.%d", 
           (ip >> 24) & 0xff, 
           (ip >> 16) & 0xff, 
           (ip >> 8) & 0xff, 
            ip & 0xff);
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

void usage() {
    printf("syntax: packet-capture <interface>\n");
    printf("sample: packet-capture wlan0\n");
}

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        struct ether_header *eth_header = (struct ether_header *)packet;
        if (ntohs(eth_header->ether_type) == ET_IP) {
            struct ip *iph = (struct ip *)(packet + ET_LEN);
            printf(" %u bytes captured\n", header->caplen);
            printf(" Src IP: ");
            print_ip(iph->ip_src);  // <--- Updated
            printf("\n");
            printf(" Dst IP: ");
            print_ip(iph->ip_dst);  // <--- Updated
            printf("\n");

            if (iph->ip_p == TCP_P) {
                struct tcphdr *tcph = (struct tcphdr *)((u_char *)iph + (iph->ip_hl << 2));
                printf(" Src MAC: ");
                print_mac(eth_header->ether_shost);
                printf("\n Dst MAC: ");
                print_mac(eth_header->ether_dhost);
                printf("\n Src Port: %d\n", ntohs(tcph->th_sport));
                printf(" Dst Port: %d\n", ntohs(tcph->th_dport));
                printf(" TCP Packet\n");

                int payload_offset = ET_LEN + (iph->ip_hl << 2) + (tcph->th_off << 2);
                u_char *payload = (u_char *)(packet + payload_offset);
                int payload_len = ntohs(iph->ip_len) - (iph->ip_hl << 2) - (tcph->th_off << 2);
                printf(" Payload (Hexadecimal): ");
                print_payload(payload, payload_len);

            } else if (iph->ip_p == UDP_P) {
                struct udphdr *udph = (struct udphdr *)((u_char *)iph + (iph->ip_hl << 2));
                printf(" Src MAC: ");
                print_mac(eth_header->ether_shost);
                printf("\n Dst MAC: ");
                print_mac(eth_header->ether_dhost);
                printf("\n Src Port: %d\n", ntohs(udph->uh_sport));
                printf(" Dst Port: %d\n", ntohs(udph->uh_dport));
                printf(" UDP Packet\n");

                int payload_offset = ET_LEN + (iph->ip_hl << 2) + sizeof(struct udphdr);
                u_char *payload = (u_char *)(packet + payload_offset);
                int payload_len = ntohs(udph->uh_ulen) - sizeof(struct udphdr);
                printf(" Payload (Hexadecimal): ");
                print_payload(payload, payload_len);

            }
        } else if (ntohs(eth_header->ether_type) == ET_ARP) {
            printf(" Src MAC: ");
            print_mac(eth_header->ether_shost);
            printf("\n Dst MAC: ");
            print_mac(eth_header->ether_dhost);
            printf("\n This is an ARP packet.\n");
        }
        printf("\n\n");
    }

    pcap_close(pcap);
}
