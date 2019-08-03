//[BOB 8TH] JAEHYEON SEND_ARP header.h CODE
#ifndef HEADER_H
#define HEADER_H

#define ETYPE 0x0608
#define HTYPE 0x0100
#define PTYPE 0x0008
#include <stdint.h>
#include <pcap/pcap.h>

struct etherh { //Ethernet header
    u_char DMAC[6];
    u_char SMAC[6];
    uint16_t Type = ETYPE;
};
struct arph { //ARP header
    uint16_t Htype = HTYPE;
    uint16_t Ptype = PTYPE;
    uint8_t Hlen = 6;
    uint8_t Prolen = 4;
    uint16_t op;
    u_char SenMAC[6];
    uint8_t SenIP[4];
    u_char TarMAC[6];
    uint8_t TarIP[4];
};
struct packet {
    struct etherh eth;
    struct arph arp;
};

#endif // HEADER_H
