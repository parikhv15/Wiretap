#ifndef CALLBACK_H_
#define CALLBACK_H_
#define WT_PROTO_TCP 6
#define WT_PROTO_UDP 17
#define WT_PROTO_ICMP 1
#define ICMP_TYPE 256
#define IPV4 4
#define TCP_HDR_LEN 20
#define PROTO 256
using namespace std;

//structure to hold transport layer data
typedef struct tl_tcp {

	string *tcp_ports_s;
	int *tcp_ports_count_s;
	string *tcp_ports_d;
	int *tcp_ports_count_d;
	string *tcp_flags;
	int flag_count;
	string *tcp_options;
	int *tcp_options_count;
	int tcp_port_index_s;
	int tcp_port_index_d;
	int *tcp_flag_index;
	int tcp_option_index;
	string* tl_proto;
	int* tl_p_count;
	unsigned int tl_index_p;
	int udp_port_index_s;
	int udp_port_index_d;
	string *udp_ports_d;
	int *udp_ports_count_d;
	string *udp_ports_s;
	int *udp_ports_count_s;
	string *icmp_type;
	int *icmp_type_count;
	int icmp_type_index;
	string *icmp_code;
	int *icmp_code_count;
	int icmp_code_index;

} wt_tcp;

//structure to hold tcp options data
typedef struct tcp_options{
	uint8_t type;
	uint8_t len;
} tcp_options;

//structure to hold arp data
struct arphdr_u {
	unsigned short int ar_hrd; /* Format of hardware address.  */
	unsigned short int ar_pro; /* Format of protocol address.  */
	unsigned char ar_hln; /* Length of hardware address.  */
	unsigned char ar_pln; /* Length of protocol address.  */
	unsigned short int ar_op; /* ARP opcode (command).  */

	unsigned char __ar_sha[ETH_ALEN]; /* Sender hardware address.  */
	unsigned char __ar_sip[4]; /* Sender IP address.  */
	unsigned char __ar_tha[ETH_ALEN]; /* Target hardware address.  */
	unsigned char __ar_tip[4]; /* Target IP address.  */

};

//structure to hold link layer data
typedef struct linklayer {
	string* ll_source;
	string* ll_dest;
	int* ll_s_count;
	int* ll_d_count;
	unsigned int index_s;
	unsigned int index_d;

} wt_ll;

//structure to hold network layer data
typedef struct networklayer {
	string* nl_source;
	string* nl_dest;
	string* nl_proto;
	string* nl_arp_s;
	string* nl_arp_d;
	int* nl_s_count;
	int* nl_d_count;
	int* nl_p_count;
	int* nl_a_count;
	unsigned int index_p;
	unsigned int index_s;
	unsigned int index_d;
	unsigned int index_arp_s;

} wt_nl;

//structure to hold summary data
typedef struct summary {
	char s_date[50];
	unsigned int cap_duration;
	unsigned int noOfPackets;
	unsigned int min_pkt_size;
	unsigned int max_pkt_size;
	float avg_pkt_size;
	long int ts_start;
} wt_sum;

extern wt_ll linklayer;
extern wt_sum summary;
extern wt_nl networklayer;
extern wt_tcp tl_tcp;

//extern string ll_source[512];
//extern int ll_s_count[512]={0};

void write_to_file(wt_sum sum);
void write_to_file(wt_ll linklayer);
void write_to_file(wt_nl networklayer);
void write_to_file(wt_tcp tl_tcp);

void set_summary(u_char* args, const struct pcap_pkthdr* header,
		const u_char* packet);

void set_llayer(u_char* args, const struct pcap_pkthdr* header,
		const u_char* packet);

void set_netlayer(u_char* args, const struct pcap_pkthdr* header,
		const u_char* packet);

void set_transport_layer(u_char* args, const struct pcap_pkthdr* header,
		const u_char* packet);

#endif /* CALLBACK_H_ */
