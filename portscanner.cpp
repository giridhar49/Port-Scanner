#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netdb.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <netinet/udp.h>
#include <linux/icmp.h>
#include <math.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <iostream>
#include<iomanip>
#include <time.h>

#define ETHERNET_SIZE 14

#include "args_setup.h"

//Include args setup once all these are working 

//using namespace std;
/////////
string scanNames[] = { "DUMP", "SYN", "NULL", "FIN", "XMAS", "ACK", "UDP" };
string resultNames[] = { "DUMP", "OPEN", "OPEN|FILTERED", "FILTERED", "CLOSED",
		"UNFILTERED" };
map<string, map<int, result_elem> > result_map;

pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;

vector<result_elem> vectorresults;

char localiptemp[30];

///////

//structure using http://sock-raw.org/papers/syn_scanner and
//http://www.tcpipguide.com/free/t_TCPChecksumCalculationandtheTCPPseudoHeader.htm
struct pseudo_header {
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	struct tcphdr tcp;
};

//http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/
//DNS header structure
struct DNS_HEADER {
	unsigned short id; // identification number

	unsigned char rd :1; // recursion desired
	unsigned char tc :1; // truncated message
	unsigned char aa :1; // authoritive answer
	unsigned char opcode :4; // purpose of message
	unsigned char qr :1; // query/response flag

	unsigned char rcode :4; // response code
	unsigned char cd :1; // checking disabled
	unsigned char ad :1; // authenticated data
	unsigned char z :1; // its z! reserved
	unsigned char ra :1; // recursion available

	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
};

struct question {
	unsigned short qtype;
	unsigned short qclass;
};

typedef struct {
	unsigned char *name;
	struct question *ques;
} QUERY;

/*
 * This function retrieves the local ip of the system
 * on which the program is running
 *Reference:
 *http://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
 */

int get_local_ip(char * buffer) {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	const char* google_dns_ip = "8.8.8.8";
	int dns_port = 53;

	struct sockaddr_in serv;

	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr(google_dns_ip);
	serv.sin_port = htons(dns_port);

	int err = connect(sock, (const struct sockaddr*) &serv, sizeof(serv));

	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	err = getsockname(sock, (struct sockaddr*) &name, &namelen);

	const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);

	close(sock);
}

//Reference: http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/
void change_to_dns_format(unsigned char* dns, unsigned char* host) {
	int lock = 0, i;
	strcat((char*) host, ".");

	for (i = 0; i < strlen((char*) host); i++) {
		if (host[i] == '.') {
			*dns++ = i - lock;
			for (; lock < i; lock++) {
				*dns++ = host[lock];
			}
			lock++; //or lock=i+1;
		}
	}
	*dns++ = '\0';
}

/*
 * The following functions sifts through the recieved
 * response packet and contains the heart of
 * Port Scanning
 */
void find_status(const u_char *packet_response, int scan_type,
		u_int32_t source_addr, const char* host, int port) {

	//cout << "Entering find status... for scan type" << scan_type<< endl;
	//cout << "Response is ..." << packet_response << endl;

	//cout.flush();
	result_elem elem;
	elem.host = host;
	elem.port = port;
	elem.scantype = scan_type;

	//cout<<"DDDDD "<< scanNames[scan_type];
	pthread_mutex_lock(&mutex1);
	string scantypename = scanNames[scan_type];
	pthread_mutex_unlock(&mutex1);

	struct sockaddr_in source, dest;
	if (packet_response == NULL) {
		if (scan_type == 1 || scan_type == 5) //Syn and Ack type scan only
				{
			printf(
					"Given TCP port  is FILTERED for host %s and port %d and scantype is %s \n",
					host, port, scantypename.c_str());
			elem.result[scan_type] = 3;
		}

		else {
			if (scan_type == 2 || scan_type == 3 || scan_type == 4) //other scans
					{
				printf(
						"Given TCP port is OPEN FILTERED  for host %s and port %d and scantype is %s \n",
						host, port, scantypename.c_str());
				elem.result[scan_type] = 2;

			}
			if (scan_type == 6) {
				printf(
						"Given UDP port is OPEN FILTERED  for host %s and port %d and scantype is %s \n",
						host, port, scantypename.c_str());
				elem.result[scan_type] = 2;
			}
		}

	}

	else if (packet_response != NULL) {
		//cout << "Packet Response is not null" << endl;
		iphdr* ip_packet;
		ip_packet = (struct iphdr *) (packet_response + ETHERNET_SIZE); //Get the ip packet information
		int ip_size = (ip_packet->ihl) * 4; //No of words (4)

		memset(&source, 0, sizeof(source));
		source.sin_addr.s_addr = ip_packet->saddr;

		memset(&dest, 0, sizeof(dest));
		dest.sin_addr.s_addr = ip_packet->daddr;
		//printf(" IP prto :%d ", ip_packet->protocol);
		//cout << "Now checking packet contents..." << endl;
		//cout << "Packet Protocol: " << ip_packet->protocol << endl;
		//ICMP Packet
		if (ip_packet->protocol == 1) {
			//cout << "Received packet is ICMP" << endl;
			icmphdr* icmp_packet;
			icmp_packet = (struct icmphdr*) (packet_response + ETHERNET_SIZE
					+ ip_size);
			//\0.polprintf("code is %d and type is %d", icmp_packet->code,icmp_packet->type);
			//cout<<"code is "<< icmp_packet->code << "and type is " << icmp_packet->type;
			//cout.flush();
			if ((icmp_packet->code == 1 || icmp_packet->code == 2
					|| icmp_packet->code == 3 || icmp_packet->code == 9
					|| icmp_packet->code == 10 || icmp_packet->code == 13)
					&& icmp_packet->type == 3 && scan_type != 6) {

				printf(
						"Given TCP port is FILTERED  for host %s and port %d and scantype is %s \n",
						host, port, scantypename.c_str());
				elem.result[scan_type] = 3;

			} else if ((icmp_packet->code == 1 || icmp_packet->code == 2
					|| icmp_packet->code == 9 || icmp_packet->code == 10
					|| icmp_packet->code == 13) && icmp_packet->type == 3
					&& scan_type == 6) {
				printf(
						"Given UDP port is FILTERED  for host %s and port %d and scantype is %s \n",
						host, port, scantypename.c_str());
				elem.result[scan_type] = 3;

			} else if (icmp_packet->code == 3 && icmp_packet->type == 3
					&& scan_type == 6) {
				printf(
						"Given UDP port is Closed for host %s and port %d and scantype is %s \n",
						host, port, scantypename.c_str());
				elem.result[scan_type] = 4;  //closed
			}
		}
		//TCP
		else if (ip_packet->protocol == 6) {
			//cout << "Received PAcket is TCP" << endl;
			tcphdr* tcp_packet;
			tcp_packet = (struct tcphdr*) (packet_response + 14 + ip_size);

			//printf(" syn flag is %d \t ack : %d \t rst :%d \t URG: %d ",tcp_packet->syn,tcp_packet->ack,tcp_packet->rst,tcp_packet->urg);
			//Syn scan
			if (scan_type == 1) {
				//cout << "Checking for scan type 1" << endl;
				if ((tcp_packet->syn == 1 && tcp_packet->ack == 1)
						|| tcp_packet->syn == 1) {
					//serv = getservbyport ( htons((int)args), "tcp" );
					printf(
							"Given TCP port open  for host %s and port %d and scantype is %s \n",
							host, port, scantypename.c_str());
					elem.result[scan_type] = 1;

				} else if (tcp_packet->rst == 1) {
					printf(
							"Given TCP port closed  for host %s and port %d and scantype is %s \n",
							host, port, scantypename.c_str());
					elem.result[scan_type] = 4;
				}
			}

			if (scan_type == 2 || scan_type == 3 || scan_type == 4) {
				if (tcp_packet->rst == 1) {
					printf(
							"Given TCP port closed  for host %s and port %d and scantype is %s \n",
							host, port, scantypename.c_str());
					elem.result[scan_type] = 4;
				}
			}
			if (scan_type == 5) {
				if (tcp_packet->rst == 1) {
					printf(
							"Given TCP port unfiltered for host %s and port %d and scantype is %s \n",
							host, port, scantypename.c_str());
					elem.result[scan_type] = 5;
				}
			}

		}
		//UDP packet
		else if (ip_packet->protocol == 17) {
			//cout << "Received PAcket is UDP" << endl;
			udphdr* udp_packet;
			udp_packet = (struct udphdr*) (packet_response + ETHERNET_SIZE
					+ ip_size);
			printf(
					"Given UDP Port Open for host %s and port %d and scantype is %s \n",
					host, port, scantypename.c_str());
			elem.result[scan_type] = 1; //Open

		}

	}

	pthread_mutex_lock(&mutex1);
	vectorresults.push_back(elem);
	pthread_mutex_unlock(&mutex1);

}

/*
 * Reference: http://www.cplusplus.com/forum/general/9403/
 * This function conver int " 4 bytes " into seprated short
 * int where each short int conatins part of the ip.
 * It take cares of order of the bytes also.
 */
void convert_int_to_ip(int ipInt, unsigned short* ipSp) {
	ipSp[0] = ipInt & 0xff;
	ipSp[1] = (ipInt & (0xff << 8)) >> 8;
	ipSp[2] = (ipInt & (0xff << 16)) >> 16;
	ipSp[3] = (ipInt & (0xff << 24)) >> 24;

}

int check_response_icmp(const u_char *packet_response) {
	iphdr* ip_packet;
	ip_packet = (struct iphdr *) (packet_response + ETHERNET_SIZE); //Get the ip packet information
	if (packet_response == NULL || !ip_packet->ihl)
		return 0;
	int ip_size = (ip_packet->ihl) * 4; //No of words (4)

	if (ip_packet->protocol == 1) {
		icmphdr* icmp_packet;
		icmp_packet = (struct icmphdr*) (packet_response + ETHERNET_SIZE
				+ ip_size);
		iphdr *ip2;
		ip2 = (struct iphdr *) (packet_response + ETHERNET_SIZE + ip_size + 8);
		//unsigned short* ipdst= ()malloc (4* sizeof(short));

		//convert_int_to_ip(ip->desAdd,ipdst) ;
		//cout<< ip2->saddr << "d====================="<< inet_addr(localiptemp);

		if (ip2->daddr != inet_addr(localiptemp))
			return 0; //cout<< "GFAJHDFDFJHDGGGGGGGDDGJHJHDGJDGHDJGDHJDGHJDJDGDJGDGDJHD\n";

		//cout << " THe dest inside icmp  %s \n" << ipdst;
		if (((icmp_packet->code == 1 || icmp_packet->code == 2
				|| icmp_packet->code == 3 || icmp_packet->code == 9
				|| icmp_packet->code == 10 || icmp_packet->code == 13)
				&& icmp_packet->type == 3)) {

			return 1;
		}
	} else if (ip_packet->protocol == 6) { //TCP

		return 2;
	} else if (ip_packet->protocol == 17) { //UDP
		return 3;
	}
	return 0;
}

/*
 * This function computes the checksum of the packet.
 * Ref: http://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
 */
unsigned short compute_checksum(unsigned short *ptr, int no_bytes) {
	register long checksum_long;
	unsigned short oddbyte;
	register short checksum_short;

	checksum_long = 0;
	while (no_bytes > 1) {
		checksum_long += *ptr++;
		no_bytes -= 2;
	}
	if (no_bytes == 1) {
		oddbyte = 0;
		*((u_char*) &oddbyte) = *(u_char*) ptr;
		checksum_long += oddbyte;
	}

	checksum_long = (checksum_long >> 16) + (checksum_long & 0xffff);
	checksum_long = checksum_long + (checksum_long >> 16);
	checksum_short = (short) ~checksum_long;

	return (checksum_short);
}

//scan_flag is number that is intialized in setup.h.
//Currently it is syn(1)

int send_packet_udp(const char *host, int port, int scan_flag) {
	pthread_mutex_lock(&mutex1);
	//pcap stuff
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_pkthdr * pheader1 = (pcap_pkthdr *) malloc(sizeof(pcap_pkthdr)); // Be sure to free this
	struct bpf_program filter;	// berkley packet filter
	char filter_exp[256]; // Filter Exp ,Need to append victim ip to it
	sprintf(filter_exp,
			"src host %s and dst host %s and udp port %d or ip proto \\icmp",
			host, localiptemp, port); //query string to capture like wireshark filter expression
	const u_char* packet_response;
	int sockfd;
	u_char* dump_packet_response = NULL;
	dev = "eth0";
	// create handle for the avialable device using find_all_dev
	if ((handle = pcap_open_live(dev, 1518, 0, 4000, errbuf)) == NULL) {
		printf("Could not open device %s: error: %s \n ", dev, errbuf);
		//exit(1);
		//close(sockfd);
		//pcap_close(handle);

		pheader1 = NULL;
		free(pheader1);

		pthread_mutex_unlock(&mutex1);
		return -1;
	}
	//Compile the handle with fileter
	if (pcap_compile(handle, &filter, filter_exp, 0, 0) == -1) {
		printf("\nCompiling handle filter failed %s \n", pcap_geterr(handle));

		printf("\nfilter %s \n", filter_exp);
		//exit(1);
		//close(sockfd);

		pheader1 = NULL;
		free(pheader1);
		pcap_close(handle);

		pthread_mutex_unlock(&mutex1);

		return -1;
	}
	//set the filter expression
	if (pcap_setfilter(handle, &filter) == -1) {
		printf("set filter failed on %s \n", filter_exp);
		//exit(1);
		//close(sockfd);

		pcap_close(handle);

		pthread_mutex_unlock(&mutex1);
		return -1;
	}
	pthread_mutex_unlock(&mutex1);
	//Filling headers based on scan flag and socket related stuff
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	//http://sock-raw.org/papers/syn_scanner
	//IP_HDRINCL to tell the kernel that headers are included in the packet (
	int one = 1;
	const int *val = &one;
	if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
		printf(
				"Error setting IP_HDRINCL. Error number : %d . Error message : %s \n",
				errno, strerror(errno));
		//exit(0);
		pheader1 = NULL;
		free(pheader1);
		pcap_close(handle);
		return -1;
	}
	struct sockaddr_in dest;
	dest.sin_family = AF_INET;
	dest.sin_port = htons(port);
	dest.sin_addr.s_addr = inet_addr(host); //need to change this one//
	char datagram[4096]; //dtaa sent over network
	struct pseudo_header psh;
	int count, attempt; //temp variables to use in this function
	struct sockaddr_in * ip;
	if (port != 53) {
		//Filling Headers
		memset(datagram, 0, 4096);
		struct iphdr* iph = (struct iphdr *) datagram;
		struct udphdr *udph = (struct udphdr *) (datagram + sizeof(struct ip));
		//Ip header
		iph->ihl = 5;
		iph->version = 4;
		iph->tos = 0;
		iph->id = htons(54321); //Id of this packet
		iph->frag_off = htons(16384);
		iph->ttl = 64;
		iph->tot_len = sizeof(struct ip) + sizeof(struct udphdr);
		iph->protocol = IPPROTO_UDP;
		iph->check = 0; //zero currently
		iph->saddr = inet_addr(localiptemp); //Need yo automate 129.79.247.86 blondie(local ip address)
		iph->daddr = dest.sin_addr.s_addr;
		iph->check = compute_checksum((unsigned short *) datagram, iph->tot_len >> 1);

		udph->source = htons(1254);
		udph->dest = htons(port);
		udph->len = htons(sizeof(struct udphdr));
		//udph->len=htons(sizeof(struct udphdr) + sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct question));
		udph->check = htons(0);

		attempt = 0;
		do {
			if (sendto(sockfd, datagram,
					sizeof(struct ip) + sizeof(struct tcphdr), 0,
					(struct sockaddr *) &dest, sizeof(dest)) < 0) {
				printf(
						"Error sending syn packet. Error number : %d . Error message : %s \n",
						errno, strerror(errno));
				//exit(0);
				close(sockfd);
				pcap_close(handle);
				return -1;
			}

			//printf("\n  while loop sent packet");
			attempt++;
			dump_packet_response = NULL;
			//Pcap response start here
			//pthread_mutex_lock( &mutex1 );
			int n = pcap_next_ex(handle, &pheader1, &packet_response);

			if (n > 0) {
				dump_packet_response = (u_char*) malloc(
						sizeof(u_char) * pheader1->len);
				memcpy(dump_packet_response, packet_response, pheader1->len);

			} else {
				packet_response = NULL;
				continue;

			}                     //cout << "   pheader1->len "<< pheader1->len;
								  //cout.flush();
			dump_packet_response = (u_char*) malloc(
					sizeof(u_char) * pheader1->len);
			memcpy(dump_packet_response, packet_response, pheader1->len);

			int check = check_response_icmp(dump_packet_response);
			if (check == 0)
				packet_response = NULL;
			//pthread_mutex_unlock( &mutex1 );
		} while (packet_response == NULL && attempt < 3); // && flag == 0);
		//printf("\n calling find status now:");
		find_status(dump_packet_response, 6, inet_addr(localiptemp), host,
				port);
	}
	if (port == 53) {
		//Filling Headers
		memset(datagram, 0, 4096);
		struct iphdr* iph = (struct iphdr *) datagram;
		//struct udphdr *udph = (struct udphdr *) (datagram + sizeof(struct ip));
		//Ip header
		iph->ihl = 5;
		iph->version = 4;
		iph->tos = 0;
		iph->id = htons(54321); //Id of this packet
		iph->frag_off = htons(16384);
		iph->ttl = 64;
		//iph->tot_len = sizeof(struct ip) + sizeof(struct udphdr);
		iph->protocol = IPPROTO_UDP;
		iph->check = 0; //zero currently
		iph->saddr = inet_addr(localiptemp); //Need yo automate 129.79.247.86 blondie(local ip address)
		iph->daddr = dest.sin_addr.s_addr;
		struct DNS_HEADER *dns = NULL;
		struct question *qinfo = NULL;
		struct udphdr *udph = (struct udphdr *) (datagram + sizeof(struct ip));
		unsigned char *qname;
		udph->source = htons(1254);
		udph->dest = htons(port);
		dns = (struct DNS_HEADER *) &datagram[sizeof(struct ip)
				+ sizeof(struct udphdr)];
		dns->id = (unsigned short) htons(getpid());
		dns->qr = 0;
		dns->opcode = 0;
		dns->aa = 0;
		dns->tc = 0;
		dns->rd = 1;
		dns->ra = 0;
		dns->z = 0;
		dns->ad = 0;
		dns->cd = 0;
		dns->rcode = 0;
		dns->q_count = htons(1); //we have only 1 question
		dns->ans_count = 0;
		dns->auth_count = 0;
		dns->add_count = 0;
		qname = (unsigned char*) &datagram[sizeof(struct DNS_HEADER)
				+ sizeof(struct ip) + sizeof(struct udphdr)];
		iph->tot_len = sizeof(struct ip) + sizeof(struct udphdr)
				+ sizeof(struct DNS_HEADER) + (strlen((const char*) qname) + 1)
				+ sizeof(struct question);
		iph->check = compute_checksum((unsigned short *) datagram, iph->tot_len >> 1);

		//Reference of the following part:
		//http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/
		udph->len = htons(
				sizeof(struct udphdr) + sizeof(struct DNS_HEADER)
						+ (strlen((const char*) qname) + 1)
						+ sizeof(struct question));
		udph->check = htons(0);
		unsigned char dnshost[] = "www.yahoo.com";
		change_to_dns_format(qname, dnshost);
		qinfo = (struct question *) &datagram[sizeof(struct DNS_HEADER)
				+ (strlen((const char*) qname) + 1) + sizeof(struct ip)
				+ sizeof(struct udphdr)]; //fill it
		qinfo->qtype = htons(1); //type of the query , A , MX , CNAME , NS etc
		qinfo->qclass = htons(1);
		attempt = 0;
		do {
			if (sendto(sockfd, datagram,
					sizeof(struct ip) + sizeof(struct tcphdr), 0,
					(struct sockaddr *) &dest, sizeof(dest)) < 0) {
				printf(
						"Error sending syn packet. Error number : %d . Error message : %s \n",
						errno, strerror(errno));
				//exit(0);
				close(sockfd);
				pcap_close(handle);
				return -1;
			}

			//printf("\n  while loop sent packet");
			attempt++;
			dump_packet_response = NULL;
			//Pcap response start here
			//pthread_mutex_lock( &mutex1 );
			int n = pcap_next_ex(handle, &pheader1, &packet_response);

			if (n > 0) {
				dump_packet_response = (u_char*) malloc(
						sizeof(u_char) * pheader1->len);
				memcpy(dump_packet_response, packet_response, pheader1->len);

			} else {
				packet_response = NULL;
				continue;

			}                     //cout << "   pheader1->len "<< pheader1->len;
								  //cout.flush();
			dump_packet_response = (u_char*) malloc(
					sizeof(u_char) * pheader1->len);
			memcpy(dump_packet_response, packet_response, pheader1->len);

			int check = check_response_icmp(dump_packet_response);
			if (check == 0) {
				packet_response = NULL;
				dump_packet_response = NULL;
			}
			//pthread_mutex_unlock( &mutex1 );
		} while (packet_response == NULL && attempt < 3); // && flag == 0);
		//printf("\n calling find status now:");
		find_status(dump_packet_response, 6, inet_addr(localiptemp), host,
				port);

	}
	pheader1 = NULL;
	free(pheader1);
	close(sockfd);
	pcap_close(handle);

	return 1;
}

//scan_flag is number that is intialized in setup.h .Currently it is syn(1)
int send_packet(const char *host, int port, int scan_flag) {

	//char * localiptemp = "192.168.0.11";

	if (scan_flag == 6) {
		// Call UDP Scan
		//printf("\n scanning UDP now");
		int r = send_packet_udp(host, port, 6);
		return r;
	}
	pthread_mutex_lock(&mutex1);

	//pcap stuff
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr pheader;
	pcap_pkthdr * pheader1 = (pcap_pkthdr *) malloc(sizeof(pcap_pkthdr)); // Be sure to free this
	struct bpf_program filter;	// berkley packet filter
	char filter_exp[256]; // Filter Exp ,Need to append victim ip to it
	sprintf(filter_exp,
			"src host %s and dst host %s and tcp port %d or ip proto \\icmp",
			host, localiptemp, port);

	const u_char* packet_response;
	u_char* dump_packet_response = NULL;

	dev = "eth0";
	//dev = "wlan0";
	// create handle for the avialable device using find_all_dev
	if ((handle = pcap_open_live(dev, 1518, 0, 4000, errbuf)) == NULL) {
		printf("Could not open device %s: error: %s \n ", dev, errbuf);
		//exit(1);
		//close(sockfd);
		//pcap_close(handle);

		pheader1 = NULL;
		free(pheader1);

		pthread_mutex_unlock(&mutex1);
		return -1;
	}
	//Compile the handle with fileter
	if (pcap_compile(handle, &filter, filter_exp, 0, 0) == -1) {
		printf("Compiling handle filter failed %s", pcap_geterr(handle));

		//exit(1);
		//close(sockfd);

		pheader1 = NULL;
		free(pheader1);
		pcap_close(handle);

		pthread_mutex_unlock(&mutex1);

		return -1;
	}
	//set the filter expression
	if (pcap_setfilter(handle, &filter) == -1) {
		printf("set filter failed on %s \n", filter_exp);
		//exit(1);
		//close(sockfd);

		pcap_close(handle);

		pthread_mutex_unlock(&mutex1);
		return -1;
	}
	pthread_mutex_unlock(&mutex1);

	//Filling headers based on scan flag and socket related stuff
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

	//http://sock-raw.org/papers/syn_scanner
	//IP_HDRINCL to tell the kernel that headers are included in the packet (
	int one = 1;
	const int *val = &one;
	if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
		printf(
				"Error setting IP_HDRINCL. Error number : %d . Error message : %s \n",
				errno, strerror(errno));
		//exit(0);
		pheader1 = NULL;
		free(pheader1);
		pcap_close(handle);
		return -1;
	}
	struct sockaddr_in dest;
	dest.sin_family = AF_INET;
	dest.sin_port = htons(port);
	dest.sin_addr.s_addr = inet_addr(host); //need to change this one//
	if (scan_flag != 6) {
		//packet fill stuff
		char datagram[4096]; //dtaa sent over network
		struct pseudo_header psh;
		int count, attempt; //temp variables to use in this function
		struct sockaddr_in * ip;
		//Filling Headers
		memset(datagram, 0, 4096);
		struct iphdr* iph = (struct iphdr *) datagram;

		//Ip header
		iph->ihl = 5;
		iph->version = 4;
		iph->tos = 0;
		//iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
		iph->id = htons(54321); //Id of this packet
		iph->frag_off = htons(16384);
		iph->ttl = 64;
		iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
		iph->protocol = IPPROTO_TCP;
		iph->check = 0; //zero currently
		iph->saddr = inet_addr(localiptemp); //Need yo automate 129.79.247.86 blondie(local ip address)
		iph->daddr = dest.sin_addr.s_addr;
		iph->check = compute_checksum((unsigned short *) datagram, iph->tot_len >> 1);
		int check;
		struct tcphdr* tcph = (struct tcphdr *) (datagram + sizeof(struct ip));
		tcph->source = htons(1254); //random port
		tcph->dest = htons(port);
		tcph->seq = htonl(12998345); //sequence number change to random()
		tcph->ack_seq = 0; //ack sequence
		tcph->doff = sizeof(struct tcphdr) / 4;	//tcp header (its size)
		tcph->fin = 0;	//fin flag not set
		tcph->syn = 0; //syn flag is set
		tcph->rst = 0; //rst flag is not set
		tcph->psh = 0; //push flag is not sset
		tcph->ack = 0; // ack is not set
		tcph->urg = 0; //urg is not set
		tcph->window = htons(14600);	// maximum allowed window size
		tcph->check = 0;	//filled later using pseudoheader
		tcph->urg_ptr = 0; //urgent pointrer not sse
		//Fill pesudo header to compute checksum
		bzero((void *) &psh, sizeof(struct pseudo_header)); //clean it
		psh.source_address = inet_addr(localiptemp); //inet_addr(host) Needs to be changes local ip
		psh.dest_address = dest.sin_addr.s_addr;
		psh.placeholder = 0;
		psh.protocol = IPPROTO_TCP;
		psh.tcp_length = htons(sizeof(struct tcphdr));

		if (scan_flag == 1) {
			tcph->syn = 1;
			memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));
			tcph->check = compute_checksum((unsigned short*) &psh,
					sizeof(struct pseudo_header));

			//Send the packet
			attempt = 0;
			packet_response = NULL;
			while (packet_response == NULL && attempt < 3) {
				if (sendto(sockfd, datagram,
						sizeof(struct ip) + sizeof(struct tcphdr), 0,
						(struct sockaddr *) &dest, sizeof(dest)) < 0) {
					printf(
							"Error sending syn packet. Error number : %d . Error message : %s \n",
							errno, strerror(errno));
					//exit(0);
					close(sockfd);
					pcap_close(handle);
					return -1;
				}
				//printf("\n sent packet");
				attempt++;
				//Pcap response start here
				dump_packet_response = NULL;
				int n = pcap_next_ex(handle, &pheader1, &packet_response); //fetch the response
				if (n > 0) {
					dump_packet_response = (u_char*) malloc(
							sizeof(u_char) * pheader1->len);
					memcpy(dump_packet_response, packet_response,
							pheader1->len);
				}

				else {
					packet_response = NULL;
					continue;
				}

				int check = check_response_icmp(dump_packet_response);
				if (check == 0) {
					packet_response = NULL;
					dump_packet_response = NULL;
				}
			}
			find_status(dump_packet_response, 1, inet_addr(localiptemp), host,
					port); //1 is for indicating syn scan done
			//close(sockfd);
		}
		if (scan_flag == 2 || scan_flag == 3 || scan_flag == 4
				|| scan_flag == 5) //NULL Scan
						{
			if (scan_flag == 2)
				tcph->syn = 0;
			if (scan_flag == 3)
				tcph->fin = 1;
			if (scan_flag == 4) {
				tcph->fin = 1;
				tcph->psh = 1;
				tcph->urg = 1;
			}
			if (scan_flag == 5) //ACK Scan
					{
				//sockfd= socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
				// printf("sockfd is %d",sockfd);
				//Write for ACK flag
				//clear out last scan flags first
				tcph->fin = 0;
				tcph->psh = 0;
				tcph->urg = 0;
				//set ack flag
				tcph->ack = 1;
			}
			memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));
			tcph->check = compute_checksum((unsigned short*) &psh,
					sizeof(struct pseudo_header));

			//Send the packet
			attempt = 0;
			do {
				if (sendto(sockfd, datagram,
						sizeof(struct ip) + sizeof(struct tcphdr), 0,
						(struct sockaddr *) &dest, sizeof(dest)) < 0) {
					printf(
							"Error sending syn packet. Error number : %d . Error message : %s \n",
							errno, strerror(errno));
					//exit(0);
					close(sockfd);
					pcap_close(handle);
					return -1;
				}

				//printf("\n  while loop sent packet");
				attempt++;
				dump_packet_response = NULL;
				//Pcap response start here
				//pthread_mutex_lock( &mutex1 );
				int n = pcap_next_ex(handle, &pheader1, &packet_response);

				if (n > 0) {
					dump_packet_response = (u_char*) malloc(
							sizeof(u_char) * pheader1->len);
					memcpy(dump_packet_response, packet_response,
							pheader1->len);

				} else {
					packet_response = NULL;
					continue;

				}                 //cout << "   pheader1->len "<< pheader1->len;
								  //cout.flush();
				dump_packet_response = (u_char*) malloc(
						sizeof(u_char) * pheader1->len);
				memcpy(dump_packet_response, packet_response, pheader1->len);

				int check = check_response_icmp(dump_packet_response);
				if (check == 0) {
					packet_response = NULL;
					dump_packet_response = NULL;
				}
				//pthread_mutex_unlock( &mutex1 );
			} while (packet_response == NULL && attempt < 3); // && flag == 0);

			//cout << " Attempts " << attempt << "\n";
			//cout << " packet_response  " << packet_response << "\n";

			if (scan_flag == 2)
				find_status(dump_packet_response, 2, inet_addr(localiptemp),
						host, port);
			if (scan_flag == 3)
				find_status(dump_packet_response, 3, inet_addr(localiptemp),
						host, port);
			if (scan_flag == 4)
				find_status(dump_packet_response, 4, inet_addr(localiptemp),
						host, port); //2 is for indicating NULL scan done
			if (scan_flag == 5) //ACK Scan
				find_status(dump_packet_response, 5, inet_addr(localiptemp),
						host, port);
			//close(sockfd);
		}

		pheader1 = NULL;
		free(pheader1);
		close(sockfd);
		pcap_close(handle);
	}
//Begin UDP Scan 

	return 1;

}

void send_packet_org(const char *host, int port, int scan_flag) {

	//char * localiptemp = "192.168.0.11";

	pthread_mutex_lock(&mutex1);

	//pcap stuff
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr pheader;
	pcap_pkthdr * pheader1 = (pcap_pkthdr *) malloc(sizeof(pcap_pkthdr)); // Be sure to free this
	struct bpf_program filter;	// berkley packet filter
	char filter_exp[256]; // Filter Exp ,Need to append victim ip to it

	const u_char* packet_response;
	u_char* dump_packet_response = NULL;

	//packet fill stuff
	char datagram[4096]; //dtaa sent over network
	struct sockaddr_in dest;
	struct pseudo_header psh;
	int count, sockfd, attempt; //temp variables to use in this function

	if (scan_flag == 6)
		sprintf(filter_exp,
				"src host %s and dst host %s and udp port %d or ip proto \\icmp",
				host, localiptemp, port, port); //query string to capture like wireshark filter expression
	else
		sprintf(filter_exp,
				"src host %s and dst host %s and tcp port %d or ip proto \\icmp",
				host, localiptemp, port);
	//printf("\n %s \n", filter_exp); // Need to change it based on parsing done

	struct sockaddr_in * ip;

	dev = "eth0";
	//dev = "wlan0";
	// create handle for the avialable device using find_all_dev
	if ((handle = pcap_open_live(dev, 1518, 0, 4000, errbuf)) == NULL) {
		printf("Could not open device %s: error: %s \n ", dev, errbuf);
		//exit(1);
		//close(sockfd);
		//pcap_close(handle);

		pheader1 = NULL;
		free(pheader1);

		pthread_mutex_unlock(&mutex1);
		return;
	}
	//Compile the handle with fileter
	if (pcap_compile(handle, &filter, filter_exp, 0, 0) == -1) {
		printf("Compiling handle filter failed %s", pcap_geterr(handle));

		//exit(1);
		//close(sockfd);

		pheader1 = NULL;
		free(pheader1);
		pcap_close(handle);

		pthread_mutex_unlock(&mutex1);

		return;
	}
	//set the filter expression
	if (pcap_setfilter(handle, &filter) == -1) {
		printf("set filter failed on %s \n", filter_exp);
		//exit(1);
		//close(sockfd);

		pcap_close(handle);

		pthread_mutex_unlock(&mutex1);
		return;
	}

	pthread_mutex_unlock(&mutex1);

	//Filling headers based on scan flag and socket related stuff
	if (scan_flag != 6) {
		sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	} else {
		sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	}
	//http://sock-raw.org/papers/syn_scanner
	//IP_HDRINCL to tell the kernel that headers are included in the packet (
	int one = 1;
	const int *val = &one;
	if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
		printf(
				"Error setting IP_HDRINCL. Error number : %d . Error message : %s \n",
				errno, strerror(errno));
		//exit(0);
		pheader1 = NULL;
		free(pheader1);
		pcap_close(handle);
		return;
	}
	//Filling Headers
	memset(datagram, 0, 4096);
	struct iphdr* iph = (struct iphdr *) datagram;
	dest.sin_family = AF_INET;
	dest.sin_port = htons(port);
	dest.sin_addr.s_addr = inet_addr(host); //need to change this one//
	//Ip header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	//iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
	iph->id = htons(54321); //Id of this packet
	iph->frag_off = htons(16384);
	iph->ttl = 64;
	if (scan_flag != 6) {
		iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
		iph->protocol = IPPROTO_TCP;

		iph->check = 0; //zero currently
		iph->saddr = inet_addr(localiptemp); //Need yo automate 129.79.247.86 blondie(local ip address)
		iph->daddr = dest.sin_addr.s_addr;
		iph->check = compute_checksum((unsigned short *) datagram, iph->tot_len >> 1);
		int check;
		//if (scan_flag != 6) {
		//zerout datagram
		// all the ip ,tcp,udp headers are from netinet.h libraries .Using it to fill structures .

		struct tcphdr* tcph = (struct tcphdr *) (datagram + sizeof(struct ip));
		tcph->source = htons(1254); //random port
		tcph->dest = htons(port);
		tcph->seq = htonl(12998345); //sequence number change to random()
		tcph->ack_seq = 0; //ack sequence
		tcph->doff = sizeof(struct tcphdr) / 4;	//tcp header (its size)
		tcph->fin = 0;	//fin flag not set
		tcph->syn = 0; //syn flag is set
		tcph->rst = 0; //rst flag is not set
		tcph->psh = 0; //push flag is not sset
		tcph->ack = 0; // ack is not set
		tcph->urg = 0; //urg is not set
		tcph->window = htons(14600);	// maximum allowed window size
		tcph->check = 0;	//filled later using pseudoheader
		tcph->urg_ptr = 0; //urgent pointrer not sse
		//Fill pesudo header to compute checksum
		bzero((void *) &psh, sizeof(struct pseudo_header)); //clean it
		psh.source_address = inet_addr(localiptemp); //inet_addr(host) Needs to be changes local ip
		psh.dest_address = dest.sin_addr.s_addr;
		psh.placeholder = 0;
		psh.protocol = IPPROTO_TCP;
		psh.tcp_length = htons(sizeof(struct tcphdr));

		if (scan_flag == 1) {
			tcph->syn = 1;
			memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));
			tcph->check = compute_checksum((unsigned short*) &psh,
					sizeof(struct pseudo_header));

			//Send the packet
			attempt = 0;
			packet_response = NULL;
			while (packet_response == NULL && attempt < 3) {
				if (sendto(sockfd, datagram,
						sizeof(struct ip) + sizeof(struct tcphdr), 0,
						(struct sockaddr *) &dest, sizeof(dest)) < 0) {
					printf(
							"Error sending syn packet. Error number : %d . Error message : %s \n",
							errno, strerror(errno));
					//exit(0);
					close(sockfd);
					pcap_close(handle);
					return;
				}
				//printf("\n sent packet");
				attempt++;
				//Pcap response start here
				dump_packet_response = NULL;
				int n = pcap_next_ex(handle, &pheader1, &packet_response); //fetch the response
				if (n > 0) {
					//cout << "   pheader1->len "<< pheader1->len;
					//cout.flush();
					dump_packet_response = (u_char*) malloc(
							sizeof(u_char) * pheader1->len);
					memcpy(dump_packet_response, packet_response,
							pheader1->len);

					//dump_packet_response=(u_char*)malloc(sizeof(pheader1->len));
					//memcpy(dump_packet_response,packet_response,pheader1->len);
				}

				else {
					packet_response = NULL;
					continue;
				}

				int check = check_response_icmp(dump_packet_response);
				if (check == 0)
					packet_response = NULL;

				//if (packet_response == NULL)
				//	sleep(1); //wait for 4 seconds and retransmit
				//printf("Received a packet with length of [%d]\n", pheader.len);
				//printf("Response is :%d \n ", n);
				//cout << "Packet Response is : " << packet_response << endl;
			}
			find_status(dump_packet_response, 1, inet_addr(localiptemp), host,
					port); //1 is for indicating syn scan done
			//close(sockfd);
		}
		if (scan_flag == 2 || scan_flag == 3 || scan_flag == 4
				|| scan_flag == 5) //NULL Scan
						{
			if (scan_flag == 2)
				tcph->syn = 0;
			if (scan_flag == 3)
				tcph->fin = 1;
			if (scan_flag == 4) {
				tcph->fin = 1;
				tcph->psh = 1;
				tcph->urg = 1;
			}
			if (scan_flag == 5) //ACK Scan
					{
				//sockfd= socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
				// printf("sockfd is %d",sockfd);
				//Write for ACK flag
				//clear out last scan flags first
				tcph->fin = 0;
				tcph->psh = 0;
				tcph->urg = 0;
				//set ack flag
				tcph->ack = 1;
			}
			memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));
			tcph->check = compute_checksum((unsigned short*) &psh,
					sizeof(struct pseudo_header));

			//Send the packet
			attempt = 0;
			do {
				if (sendto(sockfd, datagram,
						sizeof(struct ip) + sizeof(struct tcphdr), 0,
						(struct sockaddr *) &dest, sizeof(dest)) < 0) {
					printf(
							"Error sending syn packet. Error number : %d . Error message : %s \n",
							errno, strerror(errno));
					//exit(0);
					close(sockfd);
					pcap_close(handle);
					return;
				}

				//printf("\n  while loop sent packet");
				attempt++;
				dump_packet_response = NULL;
				//Pcap response start here
				//pthread_mutex_lock( &mutex1 );
				int n = pcap_next_ex(handle, &pheader1, &packet_response);

				if (n > 0) {
					dump_packet_response = (u_char*) malloc(
							sizeof(u_char) * pheader1->len);
					memcpy(dump_packet_response, packet_response,
							pheader1->len);

				} else {
					packet_response = NULL;
					continue;

				}                 //cout << "   pheader1->len "<< pheader1->len;
								  //cout.flush();
				dump_packet_response = (u_char*) malloc(
						sizeof(u_char) * pheader1->len);
				memcpy(dump_packet_response, packet_response, pheader1->len);

				int check = check_response_icmp(dump_packet_response);
				if (check == 0)
					packet_response = NULL;
				//pthread_mutex_unlock( &mutex1 );
			} while (packet_response == NULL && attempt < 3); // && flag == 0);

			//cout << " Attempts " << attempt << "\n";
			//cout << " packet_response  " << packet_response << "\n";

			if (scan_flag == 2)
				find_status(dump_packet_response, 2, inet_addr(localiptemp),
						host, port);
			if (scan_flag == 3)
				find_status(dump_packet_response, 3, inet_addr(localiptemp),
						host, port);
			if (scan_flag == 4)
				find_status(dump_packet_response, 4, inet_addr(localiptemp),
						host, port); //2 is for indicating NULL scan done
			if (scan_flag == 5) //ACK Scan
				find_status(dump_packet_response, 5, inet_addr(localiptemp),
						host, port);
			//close(sockfd);
		}

//Begin UDP Scan 
	} else {
		if (scan_flag == 6) { //UDP Scan

			unsigned char buffkk[65536];
			memset(buffkk, 0, 65536);
			struct udphdr* udph = (struct udphdr *) (datagram
					+ sizeof(struct ip));
			iph->check = 0; //zero currently
			iph->saddr = inet_addr(localiptemp); //Need yo automate 129.79.247.86 blondie(local ip address)
			iph->daddr = dest.sin_addr.s_addr;
			//iph->check = csum((unsigned short *) datagram, iph->tot_len >> 1);
			iph->protocol = IPPROTO_RAW;
			if (port != 53) {
				iph->tot_len = sizeof(struct ip) + sizeof(struct udphdr);
			}
			//http://www.tcpipguide.com/free/t_UDPMessageFormat-2.htm
			udph->source = htons(1254);
			// Destination port number
			udph->dest = htons(port);
			if (port != 53) {
				udph->len = htons(sizeof(struct udphdr));

			} else {
				//http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/

				struct DNS_HEADER *dns = NULL;
				struct question *qinfo = NULL;
				unsigned char data[5000];

				//Fill DNS header
				//struct iphdr* iph = (struct iphdr *) buffkk;
				//struct udphdr* udph = (struct udphdr *) (buffkk + sizeof(struct ip));

				dns = (struct DNS_HEADER *) (buffkk + sizeof(struct iphdr)
						+ sizeof(struct udphdr)); // &buffkk[sizeof(struct iphdr)+sizeof(struct udphdr)];
				dns->id = (unsigned short) htons(getpid());
				dns->qr = 0;
				dns->opcode = 0;
				dns->aa = 0;
				dns->tc = 0;
				dns->rd = 1;
				dns->ra = 0;
				dns->z = 0;
				dns->ad = 0;
				dns->cd = 0;
				dns->rcode = 0;
				dns->q_count = htons(1);
				dns->ans_count = 0;
				dns->auth_count = 0;
				dns->add_count = 0;
				unsigned char *qname;
				qname = (unsigned char*) &buffkk[sizeof(struct DNS_HEADER)
						+ sizeof(struct ip) + sizeof(struct udphdr)];
				unsigned char dnshsot[] = "www.google.com";
				change_to_dns_format(qname, dnshsot);
				qinfo = (struct question*) &buffkk[sizeof(struct DNS_HEADER)
						+ (strlen((const char*) qname) + 1) + sizeof(struct ip)
						+ sizeof(struct udphdr)]; //fill it
				qinfo->qtype = htons(1); // query type
				qinfo->qclass = htons(1); // For Internet

				iph->tot_len = sizeof(struct ip) + sizeof(struct udphdr)
						+ sizeof(struct DNS_HEADER)
						+ (strlen((const char*) qname) + 1)
						+ sizeof(struct question);
				udph->len = htons(
						sizeof(struct udphdr) + sizeof(struct DNS_HEADER)
								+ (strlen((const char*) qname) + 1)
								+ sizeof(struct question));

			}

			udph->check = htons(0); //Not needed as per RFC http://www.tcpipguide.com/free/t_UDPMessageFormat-2.htm
			//cout <<" try to send packet for udp \n" ;
			//              cout.flush();
			attempt = 0;
			do {

				if (port != 53) {
					if (sendto(sockfd, datagram,
							sizeof(struct ip) + sizeof(struct tcphdr), 0,
							(struct sockaddr *) &dest, sizeof(dest)) < 0) {
						printf(
								"Error sending syn packet. Error number : %d . Error message : %s \n",
								errno, strerror(errno));
						//exit(0);
						close(sockfd);
						pcap_close(handle);
						return;
					}

				}
				if (port == 53) {

					if (sendto(sockfd, buffkk, iph->tot_len, 0,
							(struct sockaddr *) &dest, sizeof(dest)) < 0) {
						printf(
								"Error sending syn packet. Error number : %d . Error message : %s \n",
								errno, strerror(errno));

						//exit(0);
						close(sockfd);
						pcap_close(handle);
						return;
					}

				}
				//cout <<" send packet for udp \n" ;
				//cout.flush();
				dump_packet_response = NULL;

				attempt++;

				//Pcap response start here
				//pthread_mutex_lock( &mutex1 );
				int n = pcap_next_ex(handle, &pheader1, &packet_response);
				printf("\n  packet_response withn udp scan %d \n", n);
				if (n > 0) {
					//continue;
					dump_packet_response = (u_char*) malloc(
							sizeof(u_char) * pheader1->len);
					memcpy(dump_packet_response, packet_response,
							pheader1->len);

				} else {

					packet_response = NULL;
					continue;
				}
				//cout << "   pheader1->len "<< pheader1->len;
				//cout.flush();

				int check = check_response_icmp(dump_packet_response);
				if (check == 0)
					packet_response = NULL;
				//pthread_mutex_unlock( &mutex1 );
			} while (packet_response == NULL && attempt < 3);

			find_status(dump_packet_response, 6, inet_addr(localiptemp), host,
					port);

		}

	}

	pheader1 = NULL;
	free(pheader1);
	close(sockfd);
	pcap_close(handle);
}

void print_services(int start_port, int end_port) {
	int i;
	struct servent * serv = (servent *) malloc(sizeof(servent));
	char proto[4] = "tcp";
	for (i = start_port; i <= end_port; i++) {
		serv = getservbyport(htons(i), proto);
		if (!serv)
			cout << i << " : " << "Unknown Application" << endl;
		else {
			cout << i << " : " << serv->s_name << endl;
		}
	}
}

void verify_service(char * host) {
	int sockfd, portno;
	struct sockaddr_in serv_addr;

	//pcap stuff
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr pheader;
	struct bpf_program filter;		// berkley packet filter
	char filter_exp[256]; // Filter Exp ,Need to append victim ip to it
	const u_char* packet_response;
	const u_char* packet_response2;

	portno = 22;
	sprintf(filter_exp, "src host %s and tcp port %d", host, portno);
	printf("\n %s \n", filter_exp);

	dev = "wlan0";
	// create handle for the avialable device using find_all_dev
	if ((handle = pcap_open_live(dev, 1518, 0, 0, errbuf)) == NULL) {
		printf("Could not open device %s: error: %s \n ", dev, errbuf);
		exit(1);
	}
	//Compile the handle with fileter
	if (pcap_compile(handle, &filter, filter_exp, 0, 0) == -1) {
		printf("Compiling handle filter failed");
		exit(1);
	}
	//set the filter expression
	if (pcap_setfilter(handle, &filter) == -1) {
		printf("set filter failed on %s \n", filter_exp);
		exit(1);
	}

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
		printf(
				"Error creating socket. Error number : %d . Error message : %s \n",
				errno, strerror(errno));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(portno);
	serv_addr.sin_addr.s_addr = inet_addr(host);

	if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		printf("Error connecting. Error number : %d . Error message : %s \n",
				errno, strerror(errno));

	packet_response = pcap_next(handle, &pheader);
	packet_response2 = pcap_next(handle, &pheader);
	//	int n = 0;
	//	while (n <= 0){
	//		n = read(sockfd, (void *)packet_response, 1024);
	//	}

	if (packet_response2 == NULL) {
		cout << "Null packet received!" << endl;
	} else {
		iphdr* ip_packet;
		ip_packet = (struct iphdr *) (packet_response + ETHERNET_SIZE);
		int ip_size = (ip_packet->ihl) * 4; //No of words (4)
		tcphdr* tcp_packet;
		tcp_packet = (struct tcphdr*) (packet_response + 14 + ip_size);
		cout << "TCP Packet Received";

		iphdr* ip_packet2;
		ip_packet2 = (struct iphdr *) (packet_response2 + ETHERNET_SIZE);
		int ip_size2 = (ip_packet2->ihl) * 4; //No of words (4)
		tcphdr* tcp_packet2;
		tcp_packet2 = (struct tcphdr*) (packet_response2 + 14 + ip_size2);
		cout << "TCP Packet Received";
	}

	close(sockfd);
}

///////////////////////////////////

////////////////////////////
// Commenting Thread part at present

void* process_job_queue(void* bt_args) {
	bt_args_t* my_arg = (bt_args_t*) bt_args;
	//cout<<" Inside process_job_queue\N";
	//cout <<" Size of queue " << my_arg->jobqueue.size()<<"\n";;
	bool empty_check = false;

	pthread_mutex_lock(&mutex1);
	empty_check = my_arg->jobqueue.empty();
	pthread_mutex_unlock(&mutex1);

	while (!empty_check) {
		// get the element of job queue
		pthread_mutex_lock(&mutex1);
		job_element t = my_arg->jobqueue.front();
		my_arg->jobqueue.pop();
		//cout <<" Size of queue " << my_arg->jobqueue.size()<<"\n";;
		//bt_args->jobqueue.push(t);
		//cout<<"\n Process Job: for "<<t.ip<<"\t"<<t.port<<"\t"<<t.scantype;
		pthread_mutex_unlock(&mutex1);

		//char*hostip=hostname_to_ip(t->);
		// processing the element job here

		//int scantype;

		for (int i = 0; i < t.scantype.size(); i++) {

			//cout << "size of  scantype" << t.scantype.size() <<"  "<< t.scantype[i]<<endl;
			//cout.flush();

			//scantype= t.scantype[i];
			//printf("\n inside thread ip  %s port : %d flag: %d",t.ip.c_str(), t.port, scantype);
			try {
				// if
				int r = send_packet(t.ip.c_str(), t.port, t.scantype[i]);

				//cout << " ther reutrned form send_packet" << r;
				//cout.flush();
				if (r == -1) {
					pthread_mutex_lock(&mutex1);
					my_arg->jobqueue.push(t);
					pthread_mutex_unlock(&mutex1);
				}
				//send_packet_udp(t.ip.c_str(), t.port, t.scantype[i]);
			} catch (int e) {
				cout
						<< " Catch error during thread and continue to next job element\n";
				cout.flush();
				continue;
			}
		}

		// check for the empty
		pthread_mutex_lock(&mutex1);
		empty_check = my_arg->jobqueue.empty();
		pthread_mutex_unlock(&mutex1);

	}

	pthread_exit(NULL);

}

void create_call_threads(bt_args_t * bt_args) {
	//http://www.tutorialspoint.com/cplusplus/cpp_multithreading.htm

	cout << " Inside creat_call_thread\N";
	cout << " Size of queue " << bt_args->jobqueue.size() << "\n";
	;
	int num_threads = bt_args->threadcount;
	pthread_t threads[num_threads];
	int rc, i;
	for (i = 0; i < num_threads; i++) {
		cout << "main() : creating thread, " << i << endl;
		rc = pthread_create(&threads[i], NULL, process_job_queue,
				(void *) bt_args);
		if (rc != 0) {
			cout << "Error:unable to create thread " << i << " exit with " << rc
					<< endl;
			//exit(-1);
		}

	}

	// wait for join the threads

	for (i = 0; i < num_threads; i++) {

		pthread_join(threads[i], NULL);
	}

	cout << " done/n";
	cout.flush();
	return;

}

/*
 * This function converts the hostname into
 * IP by calling the gethostbyname() utility
 * Ref: http://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
 */
char* hostname_to_ip(char * hostname) {
	struct hostent *he;
	struct in_addr **addr_list;
	int i;

	if ((he = gethostbyname(hostname)) == NULL) {
		// get the host info
		herror("gethostbyname");
		return NULL;
	}

	addr_list = (struct in_addr **) he->h_addr_list;

	for (i = 0; addr_list[i] != NULL; i++) {
		//Return the first one;
		return inet_ntoa(*addr_list[i]);
	}

	return NULL;
}

////

string get_services_name(int portno) {
	string myname = "";
	struct servent * serv = (servent *) malloc(sizeof(servent));
	char proto[4] = "tcp";
	serv = getservbyport(htons(portno), proto);
	if (!serv) {
		myname = "Unknown Application";
	} else {
		myname = serv->s_name;
	}

	return myname;
}

/*
 * This function is called by pcap_dispatch in
 * get_verify_service. It simply extracts the tcp
 * packet from the response received for specific
 * services like ssh, etc...
 */
void process_pkt(u_char *args, const struct pcap_pkthdr *header,
		const u_char *packet_response) {
	iphdr* ip_packet;
	ip_packet = (struct iphdr *) (packet_response + ETHERNET_SIZE);
	int ip_size = (ip_packet->ihl) * 4; //No of words (4)
	tcphdr* tcp_packet;
	tcp_packet = (struct tcphdr*) (packet_response + ETHERNET_SIZE + ip_size);
	int tcphdr_size = (tcp_packet->doff * 4);
	if (tcp_packet->ack == 1 && tcp_packet->psh == 1) {
		u_char * protocol_name;
		protocol_name = (u_char *) (packet_response + ETHERNET_SIZE + ip_size
				+ tcphdr_size);
		//cout << protocol_name << endl;
		memcpy(args, protocol_name, 1024);
	} else {
		//cout << "Some other packet received" << endl;
		sleep(1);
	}
}

string get_verify_service(const char * host, int portno) {
	int sockfd;
	struct sockaddr_in serv_addr;
	string service_name = "";

	//pcap stuff
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter; //Berkley packet filter
	char filter_exp[256]; //Filter Exp

	sprintf(filter_exp, "src host %s and tcp port %d", host, portno);
	//printf("\n %s \n", filter_exp);

	dev = "eth0";
	//create handle for the avialable device using find_all_dev
	if ((handle = pcap_open_live(dev, 1518, 0, 4000, errbuf)) == NULL) {
		printf("Could not open device %s: error: %s \n ", dev, errbuf);
		//exit(1);
		service_name.append("Err");
		return service_name;
	}
	//Compile the handle with fileter
	if (pcap_compile(handle, &filter, filter_exp, 0, 0) == -1) {
		printf("Compiling handle filter failed");
		service_name.append("Err");
		return service_name;
	}
	//set the filter expression
	if (pcap_setfilter(handle, &filter) == -1) {
		printf("set filter failed on %s \n", filter_exp);
		service_name.append("Err");
		return service_name;
	}

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		printf(
				"Error creating socket. Error number : %d . Error message : %s \n",
				errno, strerror(errno));
		service_name.append("Err");
		return service_name;
	}
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(portno);
	serv_addr.sin_addr.s_addr = inet_addr(host);

	if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr))
			< 0) {
		printf("Error connecting. Error number : %d . Error message : %s \n",
				errno, strerror(errno));
		service_name.append("Err");
		return service_name;
	}
	int n_pckts, n;
	u_char * service_description = (u_char *) malloc(1024);
	char * send_string;
	string response;
	switch (portno) {
	case 22:
		service_name.append("SSH");
		n_pckts = pcap_dispatch(handle, -1, process_pkt, service_description);

		response.assign(service_description, service_description + 1023);
		//cout << response;
		//cout.flush();
		//if (!response.empty() && response[response.size() - 1] == '\n' || response[response.size() - 1] == '\r' )
		if (response.find("\r\n") != string::npos)
			response.erase(response.find("\r\n"));
		if (response.find("SSH") != string::npos) {
			service_name.append("(Version:");
			service_name.append(response);
			service_name.append(")");
		} else {
			service_name.append("(Not Running)");
		}
//              cout << "Service installed at Port " << portno << " : "
//                              << service_description << endl;
		break;
	case 24:
		service_name.append("SMTP");

		//cout << response;
		//cout.flush();
		//cout << response;
		n_pckts = pcap_dispatch(handle, -1, process_pkt, service_description);
		response.assign(service_description, service_description + 1023);
		if (service_description == NULL) {
			service_name.append("Not Running");
		} else {
			size_t smtp_start, smtp_end;

			smtp_start = response.find(".com") + 5;
			if (smtp_start < 0) {
				cout << " smtp_start " << smtp_start;
				cout.flush();

				smtp_end = response.find(";", smtp_start);
				string smtp_version = response.substr(smtp_start,
						smtp_end - smtp_start);
				service_name.append("(");
				service_name.append(smtp_version);
				service_name.append(")");
			} else {
				service_name.append("(");
				service_name.append("RUNNING");
				service_name.append(")");
			}
		}
//              cout << "Service installed at Port " << portno << " : "
//                              << service_description << endl;
		break;
	case 43:
		service_name.append("WhoIs");
		send_string = "www.indiana.edu\r\n";
		n = write(sockfd, send_string, strlen(send_string) + 1);
		if (n < 0) {
//                      cout << "Error in sending WHOIS request" << endl;
			service_name.append("(Failure:Error in sending WHOIS request)");
		}
		n = read(sockfd, service_description, 1024);
		if (n < 0) {
//                      cout << "Error in receiving WHOIS response" << endl;
			service_name.append("(Failure:Error in receiving WHOIS response)");
		}
		response.assign(service_description, service_description + 1023);
		if (response.find("Whois") == string::npos)
			response.append("(Not Running)");
		else {
			size_t whois_start, whois_end;
			whois_start = response.find("Version");
			whois_end = response.find("\n", whois_start);
			if (whois_start != string::npos) {
				string whois_version = response.substr(whois_start + 8,
						whois_end - whois_start - 8);
//                      cout << "Whois version : " << version << endl;
				service_name.append("(Version:");
				service_name.append(whois_version);
				service_name.append(")");
			}
		}
		break;
	case 80:
		service_name.append("HTTP");
		send_string = "GET / HTTP/1.1\r\n\r\n";
		n = write(sockfd, send_string, strlen(send_string) + 1);
		if (n < 0) {
			//cout << "Error in sending WHOIS request" << endl;
			service_name.append("(Failure:Error in sending HTTP request)");
		}
		n = read(sockfd, service_description, 1024);
		if (n < 0) {
			//cout << "Error in sending WHOIS request" << endl;
			service_name.append("(Failure:Error in receiving WHOIS response)");
		}
		response.assign(service_description, service_description + 1023);
		//cout << response << endl;
		if (response.find("HTTP") != string::npos) {
			size_t server_pos, content_pos;
			server_pos = response.find("Server");
			content_pos = response.find("\r\n", server_pos);
			if (server_pos != string::npos) {
				string http_version = response.substr(server_pos + 8,
						content_pos - server_pos - 8);
				//cout << "HTTP version : " << http_version << endl;
				service_name.append("(Version:");
				service_name.append(http_version);
				service_name.append(")");
			}
		} else {
			service_name.append("(Not Running)");
		}

		break;
	case 110:
		service_name.append("POP");
		n_pckts = pcap_dispatch(handle, -1, process_pkt, service_description);
		if (service_description == NULL) {
			service_name.append("(Not Running)");
		} else {
			response.assign(service_description, service_description + 1023);
			if (response.find("OK") != string::npos) {
				size_t server_start, server_end;
				server_start = response.find("OK") + 3;
				server_end = response.find(" ", server_start);
				string server_name = response.substr(server_start,
						server_end - server_start);
				//cout << "Server : " << server_name << endl;
				service_name.append("(Server:");
				service_name.append(server_name);
				service_name.append(")");
			}
		}
		break;
	case 143:
		service_name.append("IMAP");
		n_pckts = pcap_dispatch(handle, -1, process_pkt, service_description);
		if (service_description == NULL) {
			service_name.append("(Not Running)");
		} else {
			response.assign(service_description, service_description + 1023);
			if (response.find("OK") != string::npos) {
				size_t server_start, server_end;
				server_start = response.find("CAPABILITY") + 11;
				server_end = response.find(" ", server_start);
				string server_name = response.substr(server_start,
						server_end - server_start);
				//cout << "Version : " << server_name << endl;
				service_name.append("(Version:");
				service_name.append(server_name);
				service_name.append(")");
			}
		}
		break;
	default:
		service_name.append("Service Checking not supported here");
		//cout << "Service checking for port " << portno
		//                << " is not currently supported" << endl;
		break;
	}
	free(service_description);
	close(sockfd);
	return service_name;
}

void draw_conclusion(vector<int> scanlist) {

	map<string, map<int, result_elem> >::iterator it;

	for (it = result_map.begin(); it != result_map.end(); ++it) {

		cout << "\n\nConclusion for Host" << it->first << endl;
		string myhostip = it->first;
		cout << " =========================================\n";
		cout.flush();

		//cout <<  " size of result map " << result_map.size() <<endl;
		//get result for each port

		vector<int> open_ports;
		vector<int> other_ports;
		map<int, string> ports_conc;
		map<int, result_elem> resmap = it->second; // for the host
		map<int, result_elem>::iterator sec_it;
		int i;
		for (sec_it = resmap.begin(); sec_it != resmap.end(); ++sec_it) {
			//cout<< "Debug: port number"<< sec_it->first<<endl;

			int port = sec_it->first;

			result_elem temp_res = sec_it->second;
			//cout<< "Debug:  "<< temp_res.result[1]<<" "<<temp_res.result[2]<<" "<<temp_res.result[3]<<" "<<temp_res.result[4]<<" "<<temp_res.result[5]<<" ";
			bool open_flag = false;
			bool close_flag = false;
			bool filtered_flag = false;
			bool filteredopen_flag = false;
			bool unfiltered_flag = false;
			for (i = 0; i < scanlist.size(); i++) {
				if (temp_res.result[scanlist[i]] == 1)
					open_flag = true;
				if (temp_res.result[scanlist[i]] == 4)
					close_flag = true;
				if (temp_res.result[scanlist[i]] == 2) //or temp_res.result[scanlist[i]]==3)
					filteredopen_flag = true;
				if (temp_res.result[scanlist[i]] == 3)
					filtered_flag = true;
				if (temp_res.result[scanlist[i]] == 5)
					unfiltered_flag = true;

			}
			//cout<<" Debug: " << open_flag<< " --" <<close_flag<<"---"<<filtered_flag<<endl;
			if (open_flag == true) {
				open_ports.push_back(port);
				ports_conc[port] = "OPEN";
			} else {
				other_ports.push_back(port);
				if (close_flag == true)
					ports_conc[port] = "CLOSED";
				else {
					if (filteredopen_flag)
						ports_conc[port] = "OPEN-FILTERED";
					else {
						if (filtered_flag)
							ports_conc[port] = "FILTERED";
						else
							ports_conc[port] = "UNFILTERED";
					}
				}
			}
		}

		/// Print the conclusion for that host
		//cout <<  " size of port map for that host " << resmap.size() <<endl;
		//cout<< " size of open ports " << open_ports.size() << " size of other ports" << other_ports.size() <<" size of conclusion ports" << ports_conc.size()<< endl;
		//cout <<left;
		cout << left;
		cout << "OPEN ports \n";
		cout << "=======================\n";
		cout << setw(5) << "port" << setw(55) << "Service Name" << setw(100)
				<< "Results" << setw(30) << "conclusion " << endl;
		//cout<<right;
		//for(int s=0;s<5+55+100+30;s++)
		//  cout<<"=";
		//cout<<endl;
		//cout<<"====================================================================================================================================================\n";
		//cout<<left;
		for (i = 0; i < open_ports.size(); i++) {
			cout << setw(5) << open_ports[i] << setw(50); //<<"\t\t\t\t";
			sec_it = resmap.find(open_ports[i]);
			result_elem temp_res = sec_it->second;
			string serviceName = get_verify_service(myhostip.c_str(),
					open_ports[i]);
			cout << serviceName << setw(100);
			cout.flush();

			//cout<<setw(40);
			string out_res;
			for (int ii = 0; ii < scanlist.size(); ii++) {
				//cout<< " deubg "<<   temp_res.result[1] <<" " << temp_res.result[2] <<" " <<temp_res.result[3] << " "<<temp_res.result[4]  <<endl;
				//cout.flush();

				if (temp_res.result[scanlist[ii]] >= 1
						&& temp_res.result[scanlist[ii]] <= 5)

						{
					//cout<<scanNames[scanlist[ii]]<<":"<<resultNames[temp_res.result[scanlist[ii]]]<<" "; //":"<<temp_res.result[scanlist[ii]]<<" ";
					//cout.flush();
					out_res.append(scanNames[scanlist[ii]]);
					out_res.append(":");
					out_res.append(resultNames[temp_res.result[scanlist[ii]]]);
					out_res.append(" ");
					//cout<<out_res;
				}

			}
			cout << out_res;
			//cout<<"\t\t\t\t";
			//cout <<"Debug conclusion: "<<open_ports[i];
			cout.flush();
			//cout << "DEBUG: "<< ports_conc.find(open_ports[i])->first  <<endl;
			//cout<<"\t\t\t\t";
			//cout <<setw(40)<<"conclusion: "<<ports_conc.find(open_ports[i])->second  <<endl;
			string conc = "conclusion:";
			conc.append(ports_conc.find(other_ports[i])->second);
			//cout <<setw(30)<<"conclusion: "<<ports_conc.find(other_ports[i])->second<<endl;
			cout << setw(30) << conc << endl;
			cout.flush();

		}

		cout << "\nCLOSED/FILTERED ports \n";
		cout << "=======================\n";
		cout << setw(5) << "port" << setw(55) << "Service Name" << setw(100)
				<< "Results" << setw(30) << "conclusion" << endl;

		//cout<<"=======================================================================================================================================================\n";
		//cout<<left;
		for (i = 0; i < other_ports.size(); i++) {
			//cout <<"DDD"<<endl;

			//cout<< "i" << i << "scanlistsize" <<scanlist.size()<<endl ;
			//cout <<"dd" <<endl;
			cout << setw(5) << other_ports[i] << setw(50);
			//cout.flush();

			string serviceName = get_services_name(other_ports[i]);
			cout << serviceName << setw(100);
			cout.flush();

			sec_it = resmap.find(other_ports[i]);
			result_elem temp_res = sec_it->second;
			string out_res;
			for (int ii = 0; ii < scanlist.size(); ii++) {
				//cout << "Scanlist "<< ii << scanlist[ii];

				//cout<<setw(40);

				if (temp_res.result[scanlist[ii]] >= 1
						&& temp_res.result[scanlist[ii]] <= 5) {
					//cout<<scanNames[scanlist[ii]]<<":"<<resultNames[temp_res.result[scanlist[ii]]]<< " ";
					out_res.append(scanNames[scanlist[ii]]);
					out_res.append(":");
					out_res.append(resultNames[temp_res.result[scanlist[ii]]]);
					out_res.append(" ");

					//cout.flush();
					//cout<< " deubg "<<   temp_res.result[1] <<" " << temp_res.result[2] <<" " <<temp_res.result[3] << " "<<temp_res.result[4]  <<endl;
					//cout.flush();
					//":"<<temp_res.result[scanlist[i]]<<" ";
					cout.flush();
				}

			}
			cout << out_res;

			//cout<<"\t\t\t\t";
			//cout <<"Debug conclusion: "<<other_ports[i];
			//cout.flush();
			//cout << "DEBUG: "<< ports_conc.find(other_ports[i])->first  <<endl;
			//cout<<"\t\t\t\t";
			string conc = "conclusion:";
			conc.append(ports_conc.find(other_ports[i])->second);
			//cout <<setw(30)<<"conclusion: "<<ports_conc.find(other_ports[i])->second<<endl;
			cout << setw(30) << conc << endl;
			cout.flush();

		}

	}

}

void fill_the_maps_For_conclusion() {

	for (int i = 0; i < vectorresults.size(); i++) {

		result_elem e = vectorresults[i];
		string myhost = e.host;
		int myport = e.port;
		if (result_map.count(myhost) > 0) {
			// check host
			map<string, map<int, result_elem> >::iterator it = result_map.find(
					myhost);
			map<int, result_elem> portmap = it->second;

			// get the port if exist
			if (portmap.count(myport) > 0) {
				map<int, result_elem>::iterator portmapit = portmap.find(
						myport);

				result_elem port_elem = portmapit->second;

				port_elem.result[e.scantype] = e.result[e.scantype];
				portmap[myport] = port_elem;
				//portmap.insert(make_pair(myport,port_elem));

				//cout<<" \nDebug1: inside filling port for existing host" << myport<< endl;
				//cout<< "\nDebug1:  port_elemet from map "<< port_elem.result[1]<<" "<<port_elem.result[2] <<" "<< port_elem.result[3]<<" "<<port_elem.result[4]<<" "<<port_elem.result[5]<<" ";
				//cout<< "\nDebug1:  elemnt from vector "<< e.result[1]<<" "<<e.result[2]<<" "<<e.result[3]<<" "<<e.result[4]<<" "<<e.result[5]<<" ";
			}

			else {
				portmap.insert(make_pair(myport, e));
				portmap[myport] = e;
				//cout<<"Debug2: inside filling port for existing host" << myport<< endl;
				//cout<< "\nDebug2:  elemnt from vector "<< e.result[1]<<" "<<e.result[2]<<" "<<e.result[3]<<" "<<e.result[4]<<" "<<e.result[5]<<" ";

			}

			// chek port

			//cout<< "Host exist , now insert the port with updated element"<<endl;
			//cout<<" debg : "<< elem.host << elem.port <<endl;
			//cout<< "Debug:  "<< elem.result[1]<<" "<<elem..result[2]<<" "<<elem..result[3]<<" "<<elem..result[4]<<" "<<elem..result[5]<<" ";

			//result_map.insert(make_pair(myhost,portmap));
			result_map[myhost] = portmap;

		} else {
			map<int, result_elem> temp;
			temp.insert(make_pair(myport, e));
			result_map.insert(make_pair(myhost, temp));

		}

	}
}

//////////////////////////

int main(int argc, char * argv[]) {

	//struct ps_args;
	char* host = argv[1];
	int port = atoi(argv[2]);
	int flag = atoi(argv[3]);
	char ip[] = "129.79.247.87";
	get_local_ip(localiptemp);

	//printf("\n  host %s port : %d flag: %d\n", host, port, flag);

	//char*hostip = hostname_to_ip(host);
	//printf("\n port : %d flag: %d", 50, 0);

	//send_packet(host, port, flag);
	//print_services(1, 1024);
	//verify_service(ip);

	bt_args_t bt_args;
	parse_args(argc, argv, &bt_args);
	//return 0;
	//create_call_threads(&bt_args);

	static clock_t tStart = clock();
	auto t1 = std::chrono::high_resolution_clock::now();

	//cout<<" Inside creat_call_thread\N";
	//cout <<" Size of queue " << bt_args.jobqueue.size()<<"\n";;
	int num_threads = bt_args.threadcount;
	pthread_t threads[num_threads];
	int rc, i;
	for (i = 0; i < num_threads; i++) {
		cout << "Creating thread, " << i << endl;
		rc = pthread_create(&threads[i], NULL, process_job_queue,
				(void *) &bt_args);
		if (rc != 0) {
			cout << "Error:unable to create thread " << i << " exit with " << rc
					<< endl;
			//exit(-1);
		}

	}

	// wait for join the threads

	for (i = 0; i < num_threads; i++) {

		pthread_join(threads[i], NULL);
	}

	cout << " done thread -- draw output";

	//cout<< " len of results " << vectorresults.size();
	cout.flush();
	fill_the_maps_For_conclusion();
	draw_conclusion(bt_args.scanlist);
	cout.flush();

	//printf("\n Time taken using clock resolution: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);

	auto t2 = std::chrono::high_resolution_clock::now();
	std::cout << " \nTime taken :"
			<< (std::chrono::duration_cast < std::chrono::milliseconds
					> (t2 - t1).count()) / 1000 << " seconds\n";
	/*int i;
	 for (i = 3306 ; i < 3309 ; i++){
	 send_packet(host, i, flag);
	 }*/

	//call the send packet using MUTEX
	//read response using MUTEX
}

