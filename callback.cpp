#include <iostream>
#include <iomanip> // for indentation
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <linux/if_ether.h>
#include <pcap.h>
#include <pcap/bpf.h>
#include <arpa/inet.h>
#include <time.h>
#include "callback.h"
#include <fstream>
#include <sys/socket.h>
#include <arpa/inet.h>

using namespace std;

#define TEMP_LEN 48

tm *time_c;
struct ethhdr *e;
struct iphdr *ip;
struct ip *ip_info;
struct arphdr_u *arp;
struct ether_header *eth;
struct tcphdr *tcp;
struct udphdr *udp;
struct icmphdr *icmp;
struct tcp_info *info;
struct tcp_options *opt;


// Function to set the summary structure
void set_summary(u_char* args, const struct pcap_pkthdr* header,
		const u_char* packet) {

	static int count = 0;
	static int total_size = 0;
	long int ts;
	count++;
	summary.noOfPackets = count;
	//cout << count << "::" << summary.noOfPackets << endl;
	ts = header->ts.tv_sec;
	total_size += header->caplen;
	summary.avg_pkt_size = (float) total_size / (float) count;
	if (count == 1) {
		summary.ts_start = ts;
		summary.min_pkt_size = header->caplen;
		summary.max_pkt_size = header->caplen;
		//summary.s_date = ctime(&summary.ts_start);
		time_c = gmtime(&summary.ts_start);
		time_c->tm_hour = time_c->tm_hour - 4;
		time_c->tm_zone = "EDT";
		strftime(summary.s_date, 50, "%Y-%m-%d %H:%M:%S %Z", time_c);

	} else {
		//ts=header->ts.tv_sec;
		summary.cap_duration = ts - summary.ts_start;

		if (header->caplen > summary.max_pkt_size) {
			summary.max_pkt_size = header->caplen;
		}
		if (header->caplen < summary.min_pkt_size) {
			summary.min_pkt_size = header->caplen;
		}

	}

}

//function to set link layer structure
void set_llayer(u_char* args, const struct pcap_pkthdr* header,
		const u_char* packet) {
	//static int index = 0;
	int flag = 0;
	char s_buf[TEMP_LEN];
	string temp_addr;

	e = (struct ethhdr *) (packet);

	if (linklayer.index_s == 0) {
		//ll_source[index].append((char*) e->h_source);
		sprintf(s_buf, "%02x:%02x:%02x:%02x:%02x:%02x", e->h_source[0],
				e->h_source[1], e->h_source[2], e->h_source[3], e->h_source[4],
				e->h_source[5]);
		linklayer.ll_source[linklayer.index_s].append(s_buf);
		//cout << ll_source[index] << endl;
		linklayer.index_s++;

	} else {
		sprintf(s_buf, "%02x:%02x:%02x:%02x:%02x:%02x", e->h_source[0],
				e->h_source[1], e->h_source[2], e->h_source[3], e->h_source[4],
				e->h_source[5]);
		temp_addr.append(s_buf);
		memset(s_buf, 0, TEMP_LEN);

		for (unsigned int i = 0; i < linklayer.index_s; i++) {
			if (temp_addr.compare(linklayer.ll_source[i]) == 0) {
				linklayer.ll_s_count[i]++;
				//cout <<"i:"<<i<<"count:"<< ll_s_count[i]<<endl;
				//cout << ll_source[i]<<" i: "<<i<<"count: "<< ll_s_count[i]<<endl;
				flag = 1;
			}
		}
		if (flag == 0) {
			sprintf(s_buf, "%02x:%02x:%02x:%02x:%02x:%02x", e->h_source[0],
					e->h_source[1], e->h_source[2], e->h_source[3],
					e->h_source[4], e->h_source[5]);
			linklayer.ll_source[linklayer.index_s].append(s_buf);
			//cout << ll_source[index] << "::" << ll_s_count[index] << endl;
			linklayer.index_s++;
		}
	}
	flag = 0;
	temp_addr.clear();
	memset(s_buf, 0, TEMP_LEN);

	if (linklayer.index_d == 0) {
		//ll_source[index].append((char*) e->h_source);
		sprintf(s_buf, "%02x:%02x:%02x:%02x:%02x:%02x", e->h_dest[0],
				e->h_dest[1], e->h_dest[2], e->h_dest[3], e->h_dest[4],
				e->h_dest[5]);
		linklayer.ll_dest[linklayer.index_d].append(s_buf);
		//cout << ll_source[index] << endl;
		linklayer.index_d++;

	} else {
		sprintf(s_buf, "%02x:%02x:%02x:%02x:%02x:%02x", e->h_dest[0],
				e->h_dest[1], e->h_dest[2], e->h_dest[3], e->h_dest[4],
				e->h_dest[5]);
		temp_addr.append(s_buf);
		memset(s_buf, 0, TEMP_LEN);

		for (unsigned int i = 0; i < linklayer.index_d; i++) {
			if (temp_addr.compare(linklayer.ll_dest[i]) == 0) {
				linklayer.ll_d_count[i]++;

				flag = 1;
			}
		}
		if (flag == 0) {
			sprintf(s_buf, "%02x:%02x:%02x:%02x:%02x:%02x", e->h_dest[0],
					e->h_dest[1], e->h_dest[2], e->h_dest[3], e->h_dest[4],
					e->h_dest[5]);
			linklayer.ll_dest[linklayer.index_d].append(s_buf);

			linklayer.index_d++;
		}
	}

}

//Function to set network layer structure.
void set_netlayer(u_char* args, const struct pcap_pkthdr* header,
		const u_char* packet) {
	//static int index = 0;
	int flag = 0;
	char s_buf[TEMP_LEN];
	string temp_addr;

	eth = (struct ether_header *) (packet);
	e = (struct ethhdr *) (packet);
	ip = (struct iphdr *) (packet + ETHER_HDR_LEN);
	arp = (struct arphdr_u *) (packet + ETHER_HDR_LEN);

	//if (ntohs(e->h_proto) == ETH_P_IP) {
	if (networklayer.index_p == 0) {

		if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
			sprintf(s_buf, "IP");
		} else if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
			sprintf(s_buf, "ARP");
		} else
			sprintf(s_buf, "%d (0x%02x)", ntohs(eth->ether_type),
					ntohs(eth->ether_type));
		//networklayer.nl_proto->append(s_buf);
		networklayer.nl_proto[networklayer.index_p].append(s_buf);
		//cout << networklayer.nl_proto[networklayer.index_p] << endl;
		networklayer.index_p++;

	} else {

		if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
			sprintf(s_buf, "IP");
		} else if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
			sprintf(s_buf, "ARP");
		} else
			sprintf(s_buf, "%d (0x%02x)", ntohs(eth->ether_type),
					ntohs(eth->ether_type));
		temp_addr.append(s_buf);
		memset(s_buf, 0, TEMP_LEN);

		for (unsigned int i = 0; i < networklayer.index_p; i++) {
			if (temp_addr.compare(networklayer.nl_proto[i]) == 0) {
				//cout << networklayer.nl_proto[i] << endl;
				networklayer.nl_p_count[i]++;
				flag = 1;
			}
		}
		if (flag == 0) {
			if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
				sprintf(s_buf, "IP");
			} else if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
				sprintf(s_buf, "ARP");
			} else
				sprintf(s_buf, "%d (0x%02x)", ntohs(eth->ether_type),
						ntohs(eth->ether_type));
			temp_addr.append(s_buf);
			networklayer.nl_proto[networklayer.index_p].append(s_buf);
			//cout << networklayer.nl_proto[networklayer.index_p] << endl;
			networklayer.index_p++;
		}
	}

	flag = 0;
	temp_addr.clear();
	memset(s_buf, 0, TEMP_LEN);
	if (ntohs(e->h_proto) == ETH_P_IP) {
		if (networklayer.index_s == 0) {
			//ll_source[index].append((char*) e->h_source);
			strcpy(s_buf, inet_ntoa(*(struct in_addr *) &ip->saddr));
			networklayer.nl_source[networklayer.index_s].append(s_buf);
			memset(s_buf, 0, TEMP_LEN);
			//cout << ll_source[index] << endl;
			networklayer.index_s++;

		} else {
			strcpy(s_buf, inet_ntoa(*(struct in_addr *) &ip->saddr));
			temp_addr.append(s_buf);
			memset(s_buf, 0, TEMP_LEN);

			for (unsigned int i = 0; i < networklayer.index_s; i++) {
				if (temp_addr.compare(networklayer.nl_source[i]) == 0) {
					networklayer.nl_s_count[i]++;
					flag = 1;
				}
			}
			if (flag == 0) {
				strcpy(s_buf, inet_ntoa(*(struct in_addr *) &ip->saddr));
				networklayer.nl_source[networklayer.index_s].append(s_buf);

				networklayer.index_s++;
			}
		}

		flag = 0;
		temp_addr.clear();
		memset(s_buf, 0, TEMP_LEN);

		if (networklayer.index_d == 0) {
			//ll_source[index].append((char*) e->h_source);
			strcpy(s_buf, inet_ntoa(*(struct in_addr *) &ip->daddr));
			networklayer.nl_dest[networklayer.index_d].append(s_buf);
			memset(s_buf, 0, TEMP_LEN);
			//cout << ll_source[index] << endl;
			networklayer.index_d++;

		} else {
			strcpy(s_buf, inet_ntoa(*(struct in_addr *) &ip->daddr));
			temp_addr.append(s_buf);
			memset(s_buf, 0, TEMP_LEN);

			for (unsigned int i = 0; i < networklayer.index_d; i++) {
				if (temp_addr.compare(networklayer.nl_dest[i]) == 0) {
					networklayer.nl_d_count[i]++;
					flag = 1;
				}
			}
			if (flag == 0) {
				strcpy(s_buf, inet_ntoa(*(struct in_addr *) &ip->daddr));
				networklayer.nl_dest[networklayer.index_d].append(s_buf);

				networklayer.index_d++;
			}
		}
	}
	flag = 0;
	temp_addr.clear();
	memset(s_buf, 0, TEMP_LEN);
	if (ntohs(e->h_proto) == ETH_P_ARP) {
		if (networklayer.index_arp_s == 0) {
			//ll_source[index].append((char*) e->h_source);
			sprintf(s_buf, "%02x:%02x:%02x:%02x:%02x:%02x / %d.%d.%d.%d",
					arp->__ar_sha[0], arp->__ar_sha[1], arp->__ar_sha[2],
					arp->__ar_sha[3], arp->__ar_sha[4], arp->__ar_sha[5],
					arp->__ar_sip[0], arp->__ar_sip[1], arp->__ar_sip[2],
					arp->__ar_sip[3]);
			networklayer.nl_arp_s[networklayer.index_arp_s].append(s_buf);
			memset(s_buf, 0, TEMP_LEN);
			//cout << ll_source[index] << endl;
			networklayer.index_arp_s++;

		} else {
			sprintf(s_buf, "%02x:%02x:%02x:%02x:%02x:%02x / %d.%d.%d.%d",
					arp->__ar_sha[0], arp->__ar_sha[1], arp->__ar_sha[2],
					arp->__ar_sha[3], arp->__ar_sha[4], arp->__ar_sha[5],
					arp->__ar_sip[0], arp->__ar_sip[1], arp->__ar_sip[2],
					arp->__ar_sip[3]);
			temp_addr.append(s_buf);
			memset(s_buf, 0, TEMP_LEN);

			for (unsigned int i = 0; i < networklayer.index_arp_s; i++) {
				if (temp_addr.compare(networklayer.nl_arp_s[i]) == 0) {
					networklayer.nl_a_count[i]++;
					flag = 1;
				}
			}
			if (flag == 0) {
				sprintf(s_buf, "%02x:%02x:%02x:%02x:%02x:%02x / %d.%d.%d.%d",
						arp->__ar_sha[0], arp->__ar_sha[1], arp->__ar_sha[2],
						arp->__ar_sha[3], arp->__ar_sha[4], arp->__ar_sha[5],
						arp->__ar_sip[0], arp->__ar_sip[1], arp->__ar_sip[2],
						arp->__ar_sip[3]);
				networklayer.nl_arp_s[networklayer.index_arp_s].append(s_buf);
				networklayer.index_arp_s++;
			}
		}
	}

}

//Function to hold transport layer structure
void set_transport_layer(u_char* args, const struct pcap_pkthdr* header,
		const u_char* packet) {

	int flag = 0;
	int opt_flag = 0;
	char s_buf[TEMP_LEN];
	int ip_len = 0;
	string temp_port;
	int proto = 0;
	uint8_t *t_opt;
	int iterator = 0;

	eth = (struct ether_header *) (packet);
	e = (struct ethhdr *) (packet);
	ip = (struct iphdr *) (packet + ETHER_HDR_LEN);
	ip_info = (struct ip *) (packet + ETHER_HDR_LEN);

	ip_len = ip_info->ip_hl * 4;
	if (ip_len < 20) {
		return;
	}

	tcp = (struct tcphdr*) (packet + ETHER_HDR_LEN + ip_len);
	if (ip->version == IPV4) {
		proto = ntohs(ip->protocol) / PROTO;
		//cout << "protocol:" << ntohs(ip->protocol) << endl;
		if (tl_tcp.tl_index_p == 0) {
			if (proto == WT_PROTO_TCP) {
				sprintf(s_buf, "TCP");
			} else if (proto == WT_PROTO_UDP) {
				sprintf(s_buf, "UDP");

			} else if (proto == WT_PROTO_ICMP) {
				sprintf(s_buf, "ICMP");
			} else {
				sprintf(s_buf, "%d", proto);
			}
			tl_tcp.tl_proto->append(s_buf);
			tl_tcp.tl_index_p++;

		} else {

			if (proto == WT_PROTO_TCP) {
				sprintf(s_buf, "TCP");
			} else if (proto == WT_PROTO_UDP) {
				sprintf(s_buf, "UDP");

			} else if (proto == WT_PROTO_ICMP) {
				sprintf(s_buf, "ICMP");
			} else {
				sprintf(s_buf, "%d", proto);
			}
			temp_port.append(s_buf);
			memset(s_buf, 0, TEMP_LEN);

			for (unsigned int i = 0; i < tl_tcp.tl_index_p; i++) {
				if (temp_port.compare(tl_tcp.tl_proto[i]) == 0) {
					//cout << networklayer.nl_proto[i] << endl;
					tl_tcp.tl_p_count[i]++;
					flag = 1;
				}
			}
			if (flag == 0) {
				if (proto == WT_PROTO_TCP) {
					sprintf(s_buf, "TCP");
				} else if (proto == WT_PROTO_UDP) {
					sprintf(s_buf, "UDP");

				} else if (proto == WT_PROTO_ICMP) {
					sprintf(s_buf, "ICMP");
				} else {
					sprintf(s_buf, "%d", proto);
				}
				temp_port.append(s_buf);
				tl_tcp.tl_proto[tl_tcp.tl_index_p].append(s_buf);
				//cout << networklayer.nl_proto[networklayer.index_p] << endl;
				tl_tcp.tl_index_p++;
			}
		}

		switch (proto) {

		case SOL_TCP:
			flag = 0;
			temp_port.clear();

			//cout<<"inside case"<<endl;
			if (tl_tcp.tcp_port_index_s == 0) {

				sprintf(s_buf, "%d", ntohs(tcp->source));
				tl_tcp.tcp_ports_s[tl_tcp.tcp_port_index_s].append(s_buf);
				tl_tcp.tcp_port_index_s++;

				memset(s_buf, 0, TEMP_LEN);
			} else {

				sprintf(s_buf, "%d", ntohs(tcp->source));

				temp_port.append(s_buf);

				memset(s_buf, 0, TEMP_LEN);
				for (int i = 0; i < tl_tcp.tcp_port_index_s; i++) {
					if (temp_port.compare(tl_tcp.tcp_ports_s[i]) == 0) {

						tl_tcp.tcp_ports_count_s[i]++;
						flag = 1;
					}
				}
				if (flag == 0) {
					sprintf(s_buf, "%d", ntohs(tcp->source));
					tl_tcp.tcp_ports_s[tl_tcp.tcp_port_index_s].append(s_buf);
					tl_tcp.tcp_port_index_s++;
					memset(s_buf, 0, TEMP_LEN);
				}
			}

			flag = 0;
			temp_port.clear();
			if (tl_tcp.tcp_port_index_d == 0) {

				sprintf(s_buf, "%d", ntohs(tcp->dest));
				tl_tcp.tcp_ports_d[tl_tcp.tcp_port_index_d].append(s_buf);
				tl_tcp.tcp_port_index_d++;

				memset(s_buf, 0, TEMP_LEN);
			} else {

				sprintf(s_buf, "%d", ntohs(tcp->dest));

				temp_port.append(s_buf);

				memset(s_buf, 0, TEMP_LEN);
				for (int i = 0; i < tl_tcp.tcp_port_index_d; i++) {
					if (temp_port.compare(tl_tcp.tcp_ports_d[i]) == 0) {

						tl_tcp.tcp_ports_count_d[i]++;
						flag = 1;
					}
				}
				if (flag == 0) {
					sprintf(s_buf, "%d", ntohs(tcp->dest));
					tl_tcp.tcp_ports_d[tl_tcp.tcp_port_index_d].append(s_buf);
					tl_tcp.tcp_port_index_d++;
					memset(s_buf, 0, TEMP_LEN);
				}
			}
			if (ntohs(tcp->fin))
			{
				tl_tcp.tcp_flag_index[0]++;
				tl_tcp.flag_count++;
            }
			tl_tcp.tcp_flags[0] = "FIN";
			if (ntohs(tcp->syn))
				{
				tl_tcp.tcp_flag_index[1]++;
				tl_tcp.flag_count++;
            }
			tl_tcp.tcp_flags[1] = "SYN";
			if (ntohs(tcp->rst))
				{
				tl_tcp.tcp_flag_index[2]++;
				tl_tcp.flag_count++;
            }
			tl_tcp.tcp_flags[2] = "RST";
			if (ntohs(tcp->psh))
				{
				tl_tcp.tcp_flag_index[3]++;
				tl_tcp.flag_count++;
            }			tl_tcp.tcp_flags[3] = "PSH";
			if (ntohs(tcp->ack))
				{
				tl_tcp.tcp_flag_index[4]++;
				tl_tcp.flag_count++;
            }
			tl_tcp.tcp_flags[4] = "ACK";
			if (ntohs(tcp->urg))
				{
				tl_tcp.tcp_flag_index[5]++;
				tl_tcp.flag_count++;
            }
			tl_tcp.tcp_flags[5] = "URG";

			flag = 0;
			temp_port.clear();
			//cout << ((tcp->doff * 4) - tcp_len) << endl;
			t_opt = (uint8_t *) (packet + sizeof(ethhdr) + sizeof(iphdr)
					+ sizeof(tcphdr));
			while ((tcp->doff * IPV4) - TCP_HDR_LEN > iterator) {
				opt = (struct tcp_options *) t_opt;

				switch (opt->type) {
				case 1:
					//tcp_len += 1;
					if (opt_flag == 1) {
						++t_opt;
						iterator++;
						continue;
					}
					opt_flag = 1;
					++t_opt;
					iterator++;

					break;
				default:
					t_opt += opt->len;
					iterator += opt->len;
					break;

				}

				if (tl_tcp.tcp_option_index == 0) {

					sprintf(s_buf, "%d (0x%x)", opt->type,opt->type);
					tl_tcp.tcp_options[tl_tcp.tcp_option_index].append(s_buf);
					tl_tcp.tcp_option_index++;
					memset(s_buf, 0, TEMP_LEN);
				} else {

					//sprintf(s_buf, "%x", ntohs(opt->type));
					sprintf(s_buf, "%d (0x%x)", opt->type,opt->type);
					temp_port.append(s_buf);
					memset(s_buf, 0, TEMP_LEN);

					for (int i = 0; i < tl_tcp.tcp_option_index; i++) {
						if (temp_port.compare(tl_tcp.tcp_options[i]) == 0) {
							temp_port.clear();
							tl_tcp.tcp_options_count[i]++;
							flag = 1;
						}
					}
					if (flag == 0) {
						sprintf(s_buf, "%d (0x%x)", opt->type,opt->type);
						//sprintf(s_buf, "%x", ntohs(opt->type));
						tl_tcp.tcp_options[tl_tcp.tcp_option_index].append(
								s_buf);
						tl_tcp.tcp_option_index++;
						memset(s_buf, 0, TEMP_LEN);
					}
					flag = 0;
				}
			}
			break;

		case SOL_UDP:
			flag = 0;
			temp_port.clear();
			udp = (struct udphdr*) (packet + ETHER_HDR_LEN + ip_len);
			memset(s_buf, 0, TEMP_LEN);

			if (tl_tcp.udp_port_index_s == 0) {

				sprintf(s_buf, "%d", ntohs(udp->source));
				tl_tcp.udp_ports_s[tl_tcp.udp_port_index_s].append(s_buf);
				tl_tcp.udp_port_index_s++;

				memset(s_buf, 0, TEMP_LEN);
			} else {

				sprintf(s_buf, "%d", ntohs(udp->source));

				temp_port.append(s_buf);

				memset(s_buf, 0, TEMP_LEN);
				for (int i = 0; i < tl_tcp.udp_port_index_s; i++) {
					if (temp_port.compare(tl_tcp.udp_ports_s[i]) == 0) {

						tl_tcp.udp_ports_count_s[i]++;
						flag = 1;
					}
				}
				if (flag == 0) {
					sprintf(s_buf, "%d", ntohs(udp->source));
					tl_tcp.udp_ports_s[tl_tcp.udp_port_index_s].append(s_buf);
					tl_tcp.udp_port_index_s++;
					memset(s_buf, 0, TEMP_LEN);
				}
			}

			flag = 0;
			temp_port.clear();
			if (tl_tcp.udp_port_index_d == 0) {

				sprintf(s_buf, "%d", ntohs(udp->dest));
				tl_tcp.udp_ports_d[tl_tcp.udp_port_index_d].append(s_buf);
				tl_tcp.udp_port_index_d++;

				memset(s_buf, 0, TEMP_LEN);
			} else {

				sprintf(s_buf, "%d", ntohs(udp->dest));

				temp_port.append(s_buf);

				memset(s_buf, 0, TEMP_LEN);
				for (int i = 0; i < tl_tcp.udp_port_index_d; i++) {
					if (temp_port.compare(tl_tcp.udp_ports_d[i]) == 0) {

						tl_tcp.udp_ports_count_d[i]++;
						flag = 1;
					}
				}
				if (flag == 0) {
					sprintf(s_buf, "%d", ntohs(udp->dest));
					tl_tcp.udp_ports_d[tl_tcp.udp_port_index_d].append(s_buf);
					tl_tcp.udp_port_index_d++;
					memset(s_buf, 0, TEMP_LEN);
				}
			}

			break;
		case WT_PROTO_ICMP:
			int type = 0;
			flag = 0;
			temp_port.clear();
			icmp = (struct icmphdr*) (packet + ETHER_HDR_LEN + ip_len);
			memset(s_buf, 0, TEMP_LEN);
			type = ntohs(icmp->type) / ICMP_TYPE;
			if (tl_tcp.icmp_type_index == 0) {

				sprintf(s_buf, "%d", type);
				tl_tcp.icmp_type[tl_tcp.icmp_type_index].append(s_buf);
				tl_tcp.icmp_type_index++;

				memset(s_buf, 0, TEMP_LEN);
			} else {

				sprintf(s_buf, "%d", type);

				temp_port.append(s_buf);

				memset(s_buf, 0, TEMP_LEN);
				for (int i = 0; i < tl_tcp.icmp_type_index; i++) {
					if (temp_port.compare(tl_tcp.icmp_type[i]) == 0) {

						tl_tcp.icmp_type_count[i]++;
						flag = 1;
					}
				}
				if (flag == 0) {
					sprintf(s_buf, "%d", type);
					tl_tcp.icmp_type[tl_tcp.icmp_type_index].append(s_buf);
					tl_tcp.icmp_type_index++;
					memset(s_buf, 0, TEMP_LEN);
				}
			}

			flag = 0;
			temp_port.clear();
			if (tl_tcp.icmp_code_index == 0) {

				sprintf(s_buf, "%d", ntohs(icmp->code));
				tl_tcp.icmp_code[tl_tcp.icmp_code_index].append(s_buf);
				tl_tcp.icmp_code_index++;

				memset(s_buf, 0, TEMP_LEN);
			} else {

				sprintf(s_buf, "%d", ntohs(icmp->code));

				temp_port.append(s_buf);

				memset(s_buf, 0, TEMP_LEN);
				for (int i = 0; i < tl_tcp.icmp_code_index; i++) {
					if (temp_port.compare(tl_tcp.icmp_code[i]) == 0) {

						tl_tcp.icmp_code_count[i]++;
						flag = 1;
					}
				}
				if (flag == 0) {
					sprintf(s_buf, "%d", ntohs(icmp->code));
					tl_tcp.icmp_code[tl_tcp.icmp_code_index].append(s_buf);
					tl_tcp.icmp_code_index++;
					memset(s_buf, 0, TEMP_LEN);
				}
			}
			break;
		}

	}

}

//}

//Functions to write data to txt file

void write_to_file(wt_sum sum) {

	ofstream ofile("wiretap.txt", ios::trunc | ios::out);

	ofile
			<< "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
			<< endl;

	ofile << endl;

	ofile << "=================Packet Capture Summary================" << endl;

	ofile << endl;

	ofile << left << setw(25) << "Capture start date:" << summary.s_date
			<< endl;
	ofile << left << setw(25) << "Capture duration:" << summary.cap_duration
			<< " seconds" << endl;

	ofile << left << setw(25) << "Packets in capture:" << summary.noOfPackets
			<< endl;
	ofile << left << setw(25) << "Minimum packet size:" << summary.min_pkt_size
			<< endl;
	ofile << left << setw(25) << "Maximum packet size:" << summary.max_pkt_size
			<< endl;
	ofile << left << setw(25) << "Average packet size:" << summary.avg_pkt_size
			<< endl;
	ofile << endl;
	ofile << endl;

	ofile.close();

}

void write_to_file(wt_ll linklayer) {

	ofstream ofile("wiretap.txt", ios::app | ios::out);

	ofile << "==============Link Layer=================" << endl;
	ofile << endl;
	ofile << "---------Source ethernet addresses---------" << endl;
	ofile << endl;
	if (linklayer.index_s == 0) {
			ofile << left << setw(25) << "(no results)" << endl;
		} else {
	for (unsigned int i = 0; i < linklayer.index_s; i++) {
		ofile << left << setw(25) << linklayer.ll_source[i]
				<< linklayer.ll_s_count[i] + 1 << endl;
	}
		}
	ofile << endl;

	ofile << "---------Destination ethernet addresses---------" << endl;
	ofile << endl;
	if (linklayer.index_d == 0) {
		ofile << left << setw(25) << "(no results)" << endl;
	} else {
		for (unsigned int i = 0; i < linklayer.index_d; i++) {
			ofile << left << setw(25) << linklayer.ll_dest[i]
					<< linklayer.ll_d_count[i] + 1 << endl;
		}
	}
	ofile << endl;
	ofile.close();
}

void write_to_file(wt_nl networklayer) {

	ofstream ofile("wiretap.txt", ios::app | ios::out);

	ofile << "==============Network Layer=================" << endl;
	ofile << endl;
	ofile << "---------Network layer protocols---------" << endl;
	ofile << endl;
	if (networklayer.index_p == 0) {
		ofile << left << setw(25) << "(no results)" << endl;
	} else {
		for (unsigned int i = 0; i < networklayer.index_p; i++) {
			ofile << left << setw(25) << networklayer.nl_proto[i]
					<< networklayer.nl_p_count[i] + 1 << endl;
		}
	}
	ofile << endl;
	ofile << "---------Source IP addresses---------" << endl;
	ofile << endl;
	if (networklayer.index_s == 0) {
		ofile << left << setw(25) << "(no results)" << endl;
	} else {
		for (unsigned int i = 0; i < networklayer.index_s; i++) {
			ofile << left << setw(25) << networklayer.nl_source[i]
					<< networklayer.nl_s_count[i] + 1 << endl;
		}
	}
	ofile << endl;
	ofile << "---------Destination IP addresses---------" << endl;
	ofile << endl;

	if (networklayer.index_d == 0) {
		ofile << left << setw(25) << "(no results)" << endl;
	} else {
		for (unsigned int i = 0; i < networklayer.index_d; i++) {
			ofile << left << setw(25) << networklayer.nl_dest[i]
					<< networklayer.nl_d_count[i] + 1 << endl;
		}
	}
	ofile << endl;
	ofile << "---------Unique ARP participants---------" << endl;
	ofile << endl;
	for (unsigned int i = 0; i < networklayer.index_arp_s; i++) {
		ofile << left << setw(45) << networklayer.nl_arp_s[i]
				<< networklayer.nl_a_count[i] + 1 << endl;
	}
	ofile << endl;
	ofile.close();
}

void write_to_file(wt_tcp tl_tcp) {

	ofstream ofile("wiretap.txt", ios::app | ios::out);
	ofile << "=========Transport layer=========" << endl;
	ofile << endl;
	ofile << "---------Transport layer protocols---------" << endl;
	ofile << endl;
	if (tl_tcp.tl_index_p == 0) {
		ofile << left << setw(25) << "(no results)" << endl;
	} else {
		for (unsigned int i = 0; i < tl_tcp.tl_index_p; i++) {
			ofile << left << setw(25) << tl_tcp.tl_proto[i]
					<< tl_tcp.tl_p_count[i] + 1 << endl;
		}
	}

	ofile << endl;
	ofile << "=========Transport layer: TCP=========" << endl;
	ofile << endl;
	ofile << "---------Source TCP ports---------" << endl;
	ofile << endl;
	if (tl_tcp.tcp_port_index_s == 0) {
		ofile << left << setw(25) << "(no results)" << endl;
	} else {
		for (int i = 0; i < tl_tcp.tcp_port_index_s; i++) {
			ofile << left << setw(25) << tl_tcp.tcp_ports_s[i]
					<< tl_tcp.tcp_ports_count_s[i] + 1 << endl;
		}
	}

	ofile << "---------Destination TCP ports---------" << endl;

	ofile << endl;
	if (tl_tcp.tcp_port_index_d == 0) {
		ofile << left << setw(25) << "(no results)" << endl;
	} else {
		for (int i = 0; i < tl_tcp.tcp_port_index_d; i++) {
			ofile << left << setw(25) << tl_tcp.tcp_ports_d[i]
					<< tl_tcp.tcp_ports_count_d[i] + 1 << endl;
		}
	}
	ofile << endl;
	ofile << "---------TCP flags---------" << endl;

	ofile << endl;
    if(tl_tcp.flag_count == 0)
        ofile << left << setw(25) << "(no results)" << endl;
    else{
        for (unsigned int i = 0; i < 6; i++) {
            ofile << left << setw(25) << tl_tcp.tcp_flags[i]
                    << tl_tcp.tcp_flag_index[i] << endl;
        }
	}
	ofile << endl;
	ofile << "---------TCP Options---------" << endl;

	ofile << endl;
	if (tl_tcp.tcp_option_index == 0) {
		ofile << left << setw(25) << "(no results)" << endl;
	} else {
		for (int i = 0; i < tl_tcp.tcp_option_index; i++) {
			ofile << left << setw(25) << tl_tcp.tcp_options[i]
					<< tl_tcp.tcp_options_count[i] + 1 << endl;
		}
	}
	ofile << endl;

	ofile << "=========Transport layer: UDP=========" << endl;

	ofile << endl;
	ofile << "---------Source UDP ports---------" << endl;
	ofile << endl;

	if (tl_tcp.udp_port_index_s == 0) {
		ofile << left << setw(25) << "(no results)" << endl;
	} else {

		for (int i = 0; i < tl_tcp.udp_port_index_s; i++) {
			ofile << left << setw(25) << tl_tcp.udp_ports_s[i]
					<< tl_tcp.udp_ports_count_s[i] + 1 << endl;
		}
	}
	ofile << endl;
	ofile << "---------Destination UDP ports---------" << endl;
	ofile << endl;
	if (tl_tcp.udp_port_index_d == 0) {
		ofile << left << setw(25) << "(no results)" << endl;
	} else {
		for (int i = 0; i < tl_tcp.udp_port_index_d; i++) {
			ofile << left << setw(25) << tl_tcp.udp_ports_d[i]
					<< tl_tcp.udp_ports_count_d[i] + 1 << endl;
		}
	}
	ofile << endl;
	ofile << "=========Transport layer: ICMP=========" << endl;
	ofile << endl;
	ofile << "---------ICMP types---------" << endl;
	ofile << endl;
	if (tl_tcp.icmp_type_index == 0) {
		ofile << left << setw(25) << "(no results)" << endl;
	} else {
		for (int i = 0; i < tl_tcp.icmp_type_index; i++) {
			ofile << left << setw(25) << tl_tcp.icmp_type[i]
					<< tl_tcp.icmp_type_count[i] + 1 << endl;
		}
	}

	ofile << endl;
	ofile << endl;
	ofile << "---------ICMP codes---------" << endl;
	ofile << endl;
	if (tl_tcp.icmp_code_index == 0) {
		ofile << left << setw(25) << "(no results)" << endl;
	} else {
		for (int i = 0; i < tl_tcp.icmp_code_index; i++) {
			ofile << left << setw(25) << tl_tcp.icmp_code[i]
					<< tl_tcp.icmp_code_count[i] + 1 << endl;
		}
	}
	ofile << endl;

	ofile.close();

}

