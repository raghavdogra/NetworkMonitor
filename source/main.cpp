#include <stdio.h>
#include <pcap.h>
#include <iostream>
#include <string>
#include <mydump.h>
#include <sstream>

using namespace std;

int s_p;
string str;
ostringstream stream;

int parse_args(int &i_p, int &f_p, int &s_p, int &e_p, string &interface, string &fl, string &str, string &expr, char*argv[],int argc)
{
	i_p = f_p = s_p = e_p = 0;
        int nextarg = _EXPRESSION;
        string stri = "-i";
        string strr = "-r";
        string strs = "-s";
        for(int i = 1; i<argc;i++) {
                if(stri.compare(argv[i]) == 0) {
                        nextarg = _INTERFACE;
                }
                else if (strr.compare(argv[i]) == 0) {
                        nextarg = _FILE;
                }
                else if (strs.compare(argv[i]) == 0) {
                        nextarg = _STRING;
                }
                else {
                        nextarg = _EXPRESSION;
                }

                if(nextarg == _INTERFACE) {
                        interface = argv[++i];
                        i_p = 1;
                }
                else if (nextarg == _FILE) {
                        fl = argv[++i];
                        f_p = 1;
                }
                else if (nextarg == _STRING) {
                        str = argv[++i];
                        s_p = 1;
                }
                else {
                        expr = expr + " " + argv[i];
                        e_p = 1;
                }
        }
	return 1;
}

void print_ascii (const u_char * start, int size)
{
	for(int i = 0; i< (16-size);i++)
		printf("   ");
	printf("	");
	for(int i=0; i<size; i++) {
		if (isprint(*(start+i)))
			printf("%c", *(start+i));
		else
			printf(".");
	}
	return;
}


void payload_print(const char * payload, int size) {
	const u_char * start = (const u_char *) payload;
	int i = 0;
	int linesize = 16;
	int linecursor = 0;
	for(i=0;i<size;i++) {
		printf("%02x ",*(start+i));
		linecursor++;
		if(linecursor == linesize) {
			print_ascii ((start+i-15),16);
			printf("\n");
			linecursor = linecursor % linesize;
		}
	}
	print_ascii((start+i-linecursor),linecursor);
	printf("\n");
	return;
}				

bool printable(const char * payload, int size) {
	if(s_p!=1)
		return true;
	string strbuf ="";
	const u_char * start = (const u_char *) payload;
	int i = 0;
//	int linesize = 16;
//	int linecursor = 0;
	for(i=0;i<size;i++) {
		char c = *(start+i);
                if (isprint(*(start+i)))
                        strbuf = strbuf+ c;
                else
                        strbuf = strbuf + ".";
	}

	if(strstr(strbuf.c_str(),str.c_str()))
		return true;
	else
		return false;
}
				
void print_timestamp(const struct pcap_pkthdr * header) {

	struct timeval timev;
	timev = header->ts;
	time_t currtime;
	struct tm * currt;
	
	currtime = timev.tv_sec;
	currt = localtime(&currtime);
	char tmpbuf[64], buf[64];
	strftime(tmpbuf,sizeof(tmpbuf), "%Y-%m-%d %H:%M:%S",currt);
	snprintf(buf, sizeof(buf), "%s.%06d", tmpbuf, (int)timev.tv_usec);
	stream << buf;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	stream.str("");
	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	const struct udphdr * udp;
	void * proto;	
	stream << "\nPacket number ";
	stream <<dec<< count;
	stream << ":\n";
	count++;

	print_timestamp(header);
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	/* print source and destination MAC address */
	stream <<"  " << ether_ntoa((struct ether_addr *) ethernet->ether_shost)  << " -> ";
	stream << ether_ntoa((struct ether_addr *) ethernet->ether_dhost);

	/* print type */
	//stream << ethernet->ether_type << " type " << hex << (bpf_u_int32) ethernet->ether_type;
	//int type = ethernet->ether_type;
	//printf(" type 0x%x ",ntohs( ethernet->ether_type));
	stream << " type 0x" << hex << ntohs( ethernet->ether_type) << " ";

	/* print len */
	stream << " len " << dec<< header->len <<endl;
	//printf(" len %d\n",header->len);
	//stream << " len " << header->len <<endl;

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
//	if (size_ip < 20) {
//		printf("   * Invalid IP header length: %u bytes\n", size_ip);
//		return;
//	}

//	stream << inet_ntoa(ip->ip_src) << " -> ";
//	stream << inet_ntoa(ip->ip_dst) ;

	/* print source and destination IP addresses */
//	printf("       From: %s\n", inet_ntoa(ip->ip_src));
//	printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
	//		printf(" TCP\n");
			proto = (void *)(packet + SIZE_ETHERNET + size_ip);
			tcp_handler((struct sniff_tcp*)proto,ip);
			break;
		case IPPROTO_UDP:
	//		printf(" UDP\n");
			proto = (void*)(packet + SIZE_ETHERNET + size_ip);
			udp_handler((struct udphdr*)proto,ip);
			break;
		case IPPROTO_ICMP:
	//		printf(" ICMP\n");
			proto = (void *)(packet + SIZE_ETHERNET + size_ip);
			icmp_handler((struct icmphdr*)proto,ip);
			break;
			;
		default:
			other_handler(ip,header->len);
	//		printf(" unknown\n");
			return;
	}
return;
}
int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	const char * dev;
	string interface, fl, expr="";

	int i_p, f_p, e_p; //presence of -i,-f,-s or expression
	parse_args(i_p,f_p,s_p,e_p,interface,fl,str,expr,argv,argc);


		

	if(i_p == 1) {
		cout << interface <<endl;
		dev = interface.c_str();
	}
	else {
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
		cout << dev <<endl;
	}
	if(f_p == 1)
		cout << fl <<endl;	
	if(s_p == 1)
		cout << str <<endl;	
	if(e_p == 1)
		cout << expr << endl;	

	pcap_t *handle;			/* Session handle */
	//char *dev;			/* The device to sniff on */
	//char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	const char *filter_exp =  expr.c_str();	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */


	if(f_p == 1) {
		handle = pcap_open_offline(fl.c_str(),errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't file device %s: %s\n",fl.c_str() , errbuf);
			return(2);
		}
	} 
	else {
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return(2);
		}	
	}


		/* Compile and apply the filter */
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		/* Grab all the packets */
		pcap_loop(handle, -1, got_packet, NULL);;
		/* Print its length */
		printf("Jacked a packet with length of [%d]\n", header.len);
		/* And close the session */
		pcap_close(handle);
		return(0);

	return(0);
}

