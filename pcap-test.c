#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

/*
 *  Ethernet II header
 *  Static header size: 14 bytes
 */
typedef struct
{
    u_int8_t  ether_dhost[6];/* destination ethernet address */
    u_int8_t  ether_shost[6];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
} libnet_ethernet_hdr;


/*
 *  IPv4 header
 *  Internet Protocol, version 4
 *  Static header size: 20 bytes
 */
typedef struct 
{
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */

#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
#endif
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    u_int8_t ip_src[4], ip_dst[4]; /* source and dest address */
}libnet_ipv4_hdr;


/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
typedef struct 
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,        /* data offset */
           th_x2:4;         /* (unused) */
#endif
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR
#define TH_CWR    0x80
#endif
	u_int8_t payload[10];
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
}libnet_tcp_hdr;

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}


void printAddr(libnet_ethernet_hdr *e_ptr, libnet_ipv4_hdr *ipv4_ptr, libnet_tcp_hdr *tcp_ptr){
	uint8_t *mac_src = e_ptr->ether_shost;
	uint8_t *mac_dst = e_ptr->ether_dhost;
	
	uint8_t *ip_src = ipv4_ptr->ip_src;
	uint8_t *ip_dst = ipv4_ptr->ip_dst;

	u_int16_t port_src = tcp_ptr->th_sport;
	u_int16_t port_dst = tcp_ptr->th_dport;

	printf("Ethernet Header Info\n");
	printf("src mac : %02x:%02x:%02x:%02x:%02x:%02x\n", mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
	printf("dst mac : %02x:%02x:%02x:%02x:%02x:%02x\n", mac_dst[0], mac_dst[1], mac_dst[2], mac_dst[3], mac_dst[4], mac_dst[5]);

	printf("IP Header Info\n");
	printf("src ip : %u.%u.%u.%u\n", ip_src[0], ip_src[1], ip_src[2], ip_src[3]);
	printf("dst ip : %u.%u.%u.%u\n", ip_dst[0], ip_dst[1], ip_dst[2], ip_dst[3]);

	printf("TCP Header Info\n");
	printf("src port : %d\n",htons(port_src));
	printf("dst port : %d\n", htons(port_dst));

}

void printData(libnet_tcp_hdr *tcp_ptr, uint8_t len){
	uint8_t data = *tcp_ptr->payload;

	printf("Payload Data (Length: %d) : ", len);

	for(uint8_t i = 0; i<10; i++){
		printf("\\x%02x", tcp_ptr->payload[i]);
	}

	printf("\n");
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
	uint8_t ethernet_len;
	uint8_t ipv4_len;
	uint8_t tcp_len;

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;

		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		libnet_ethernet_hdr* e_ptr = (libnet_ethernet_hdr*) (packet);
		// Type: IPv4(0x0800)
		if(e_ptr->ether_type != 8) {
				continue;
		}
		// destination 6byte, source 6byte, type 2byte
		ethernet_len = 14;

		libnet_ipv4_hdr* ipv4_ptr = (libnet_ipv4_hdr*)(packet + ethernet_len);
		// Protocol: TCP (6)
		if(ipv4_ptr -> ip_p != 6) {
				continue;
		}
		ipv4_len = (ipv4_ptr->ip_hl) * 4;

		libnet_tcp_hdr* tcp_ptr = (libnet_tcp_hdr*) (packet + ethernet_len + ipv4_len);
		tcp_len = (tcp_ptr-> th_flags) * 4;

		printf("%u bytes captured\n", header->caplen);
	
		//To calculate data length we have to subtract ethernet, ipv4, tcp info length from total length
		uint8_t total_data_len = header->caplen - (ethernet_len + ipv4_len + tcp_len);
		
		printAddr(e_ptr, ipv4_ptr, tcp_ptr);
		printData(tcp_ptr, total_data_len);

	}

	pcap_close(pcap);
	return 0;
}
