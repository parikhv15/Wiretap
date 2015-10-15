#include <iostream>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include <pcap.h>
#include <pcap/bpf.h>
#include <arpa/inet.h>
#include <net/ethernet.h> //for structure ether_header
#include <time.h>
#include <getopt.h>
#include "callback.h"

using namespace std;

wt_sum summary;
wt_ll linklayer;
wt_nl networklayer;
wt_tcp tl_tcp;

typedef struct wt_args {

	char pcap_file[1024];

} wt_args_t;


//Function to print usage on the screen
void usage(FILE * file) {
	fprintf(file, "Wiretap [OPTIONS] [file] \n"
			"\t --help           \t\t Print this help screen\n"
			"\t --open           \t\t Open the pcap file\n");
}

//Function to parse command line arguments
void parse_args(int argc, char ** argv, wt_args *args) {
	char c;
	int optind = 0;
	static struct option options[] = { { "help", no_argument, 0, 'h' }, {
			"open", required_argument, 0, 'o' }, { 0, 0, 0, 0 } };
	if (argc != 3) {
		cout << "Invalid arguments provided" << endl;

		usage(stdout);
		exit(0);
	}

	while ((c = getopt_long(argc, argv, "ho:", options, &optind)) != -1) {

		switch (c) {

		case 'h':
			usage(stdout);
			exit(0);
			break;
		case 'o':
			strcpy(args->pcap_file, argv[2]);
			break;

		default:
			usage(stdout);
			exit(0);
			break;

		}

	}

}

int main(int argc, char** argv) {

	wt_args args;
	pcap_t *handle;
	int datalink = 0;

	//const u_char *packet;
	char pc_err[PCAP_ERRBUF_SIZE];
	parse_args(argc, argv, &args);

	handle = pcap_open_offline(args.pcap_file, pc_err);
	//struct pcap_pkthdr header;

	if (handle == NULL) {
		cout << "Error: " << pc_err << endl;
		exit(1);
	}

	datalink = pcap_datalink(handle);

	if (datalink != DLT_EN10MB) {
		cout << "Ethernet header only Supported" << endl;
		exit(1);
	}

	pcap_loop(handle, -1, set_summary, NULL);
	write_to_file(summary);
	pcap_close(handle);

	handle = pcap_open_offline(args.pcap_file, pc_err);

	if (handle == NULL) {
		cout << "Error: " << pc_err << endl;
		exit(1);
	}

	linklayer.ll_dest = new string[summary.noOfPackets];
	linklayer.ll_source = new string[summary.noOfPackets];
	linklayer.ll_d_count = new int[summary.noOfPackets];
	linklayer.ll_s_count = new int[summary.noOfPackets];

	for (unsigned int i = 0; i < summary.noOfPackets; i++) {
		linklayer.ll_d_count[i] = 0;
		linklayer.ll_s_count[i] = 0;
	}
	linklayer.index_d = 0;
	linklayer.index_s = 0;

	pcap_loop(handle, -1, set_llayer, NULL);
	write_to_file(linklayer);
	pcap_close(handle);

	handle = pcap_open_offline(args.pcap_file, pc_err);

	if (handle == NULL) {
		cout << "Error: " << pc_err << endl;
		exit(1);
	}

	networklayer.nl_proto = new string[summary.noOfPackets];
	networklayer.nl_p_count = new int[summary.noOfPackets];
	networklayer.nl_source = new string[summary.noOfPackets];
	networklayer.nl_s_count = new int[summary.noOfPackets];
	networklayer.nl_dest = new string[summary.noOfPackets];
	networklayer.nl_d_count = new int[summary.noOfPackets];
	networklayer.nl_arp_s = new string[summary.noOfPackets];
	networklayer.nl_a_count = new int[summary.noOfPackets];
	for (unsigned int i = 0; i < summary.noOfPackets; i++) {

	networklayer.nl_p_count[i] = 0;

	networklayer.nl_s_count[i] = 0;

		networklayer.nl_d_count[i] = 0;

	networklayer.nl_a_count[i] = 0;
	}

	networklayer.index_arp_s = 0;
	networklayer.index_d = 0;
	networklayer.index_p = 0;
	networklayer.index_s = 0;
	pcap_loop(handle, -1, set_netlayer, NULL);

	write_to_file(networklayer);
	pcap_close(handle);

	handle = pcap_open_offline(args.pcap_file, pc_err);

	if (handle == NULL) {
		cout << "Error: " << pc_err << endl;
		exit(1);
	}

	//tl_tcp.flags_count = new int[summary.noOfPackets];
	tl_tcp.flag_count = 0;
	tl_tcp.tcp_flags = new string[summary.noOfPackets];
	tl_tcp.tcp_option_index = 0;
	tl_tcp.tcp_options = new string[summary.noOfPackets];
	tl_tcp.tcp_options_count = new int[summary.noOfPackets];
	tl_tcp.tcp_port_index_d = 0;
	tl_tcp.tcp_port_index_s = 0;
	tl_tcp.tcp_ports_count_d = new int[summary.noOfPackets];
	tl_tcp.tcp_ports_count_s = new int[summary.noOfPackets];
	tl_tcp.tcp_ports_d = new string[summary.noOfPackets];
	tl_tcp.tcp_ports_s = new string[summary.noOfPackets];
	tl_tcp.tl_proto = new string[summary.noOfPackets];
	tl_tcp.tl_p_count = new int[summary.noOfPackets];
	tl_tcp.udp_ports_count_d = new int[summary.noOfPackets];
	tl_tcp.udp_ports_count_s = new int[summary.noOfPackets];
	tl_tcp.udp_ports_s = new string[summary.noOfPackets];
	tl_tcp.udp_ports_d = new string[summary.noOfPackets];
	tl_tcp.tcp_flag_index = new int[summary.noOfPackets];
	tl_tcp.tl_index_p = 0;

	tl_tcp.icmp_type = new string[summary.noOfPackets];

	tl_tcp.icmp_type_index = 0;
	;
	tl_tcp.icmp_code = new string[summary.noOfPackets];

	tl_tcp.icmp_code_index = 0;

	tl_tcp.icmp_code_count = new int[summary.noOfPackets];
	tl_tcp.icmp_type_count = new int[summary.noOfPackets];

	for (unsigned int i = 0; i < summary.noOfPackets; i++) {
		tl_tcp.tcp_flag_index[i] = 0;
		//tl_tcp.tcp_options[i]=0;
		tl_tcp.tcp_options_count[i] = 0;
		tl_tcp.tcp_ports_count_d[i] = 0;
		tl_tcp.tcp_ports_count_s[i] = 0;
		tl_tcp.tl_p_count[i] = 0;
		tl_tcp.udp_ports_count_d[i] = 0;
		tl_tcp.udp_ports_count_s[i] = 0;
		tl_tcp.icmp_code_count[i] = 0;
		tl_tcp.icmp_type_count[i] = 0;
	}

	pcap_loop(handle, -1, set_transport_layer, NULL);
	write_to_file(tl_tcp);
	pcap_close(handle);

	cout << "------Packet Analysis Report Generated------" << endl;

	delete[] linklayer.ll_dest;
	delete[] linklayer.ll_source;
	delete[] linklayer.ll_d_count;
	delete[] linklayer.ll_s_count;

	delete[] networklayer.nl_proto;
	delete[] networklayer.nl_p_count;
	delete[] networklayer.nl_source;
	delete[] networklayer.nl_s_count;
	delete[] networklayer.nl_dest;
	delete[] networklayer.nl_d_count;
	delete[] networklayer.nl_arp_s;
	delete[] networklayer.nl_a_count;

	delete[] tl_tcp.tcp_flags;
	delete[] tl_tcp.tcp_options;
	delete[] tl_tcp.tcp_options_count;
	delete[] tl_tcp.tcp_ports_count_d;
	delete[] tl_tcp.tcp_ports_count_s ;
	delete[] tl_tcp.tcp_ports_d;
	delete[] tl_tcp.tcp_ports_s;
	delete[] tl_tcp.tl_proto;
	delete[] tl_tcp.tl_p_count;
	delete[] tl_tcp.udp_ports_count_d;
	delete[] tl_tcp.udp_ports_count_s;
	delete[] tl_tcp.udp_ports_s;
	delete[] tl_tcp.udp_ports_d;
	delete[] tl_tcp.tcp_flag_index;
	delete[] tl_tcp.icmp_type;
	delete[] tl_tcp.icmp_code;
	delete[] tl_tcp.icmp_code_count;
	delete[] tl_tcp.icmp_type_count;

	return 0;
}
