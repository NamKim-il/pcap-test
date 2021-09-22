#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

#define MAX 16

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

bool check_protocol(const u_char* pkt)
{
	struct libnet_ipv4_hdr* ipv4_hdr = (struct libnet_ipv4_hdr*)(pkt + sizeof(struct libnet_ethernet_hdr));
	
	if(ipv4_hdr->ip_p == IPPROTO_TCP) return true;
	else return false;
}

void print_eth(struct libnet_ethernet_hdr* hdr)
{
	printf("SRC MAC : ");
	for(int i=0; i<ETHER_ADDR_LEN; i++) {
		if(i) printf(":");
	
		printf("%02x", hdr->ether_shost[i]);
		
	}
	printf("\n");
	printf("DST MAC : ");
	for(int i=0; i<ETHER_ADDR_LEN; i++) {
                if(i) printf(":");
                printf("%02x", hdr->ether_dhost[i]);
        }
	printf("\n");
}

void print_ip(struct libnet_ipv4_hdr* hdr) 
{
	printf("SRC IP : %s\n", inet_ntoa(hdr->ip_src));
	printf("DST IP : %s\n", inet_ntoa(hdr->ip_dst));
}

void print_tcp(struct libnet_tcp_hdr* hdr)
{
	printf("SRC PORT : %d\n", ntohs(hdr->th_sport));
	printf("DST PORT : %d\n", ntohs(hdr->th_dport));
}

void print_payload(const u_char* payload, uint16_t size)
{
	printf("payload : ");
	for(int i=0;i<size;i++)	{
		printf("%02x", payload[i]);
	}
	printf("\n\n");
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

		if(!check_protocol(packet)) continue;
		struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*) packet;
		print_eth(eth_hdr);
		struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
		print_ip(ip_hdr);
		struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + ip_hdr->ip_hl*4);
		print_tcp(tcp_hdr);
		
		uint16_t size = ntohs(ip_hdr->ip_len)-((uint16_t)ip_hdr->ip_hl + (uint16_t)tcp_hdr->th_off)*4;
		if(size>MAX) size=MAX;

		const u_char* payload = (u_char*)tcp_hdr + (uint16_t)tcp_hdr->th_off*4;

		print_payload(payload, size);

	}

	pcap_close(pcap);
}
