#include <stdio.h>
#include <pcap.h>
#include <iostream>
#include <string>
#include <mydump.h>

using namespace std;

void tcp_handler (const struct sniff_tcp* tcp, const struct sniff_ip *ip) {
        int size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20) {
                printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                return;
        }
        cout << inet_ntoa(ip->ip_src);
	cout << ":"<< ntohs(tcp->th_sport);
	cout << " -> ";
        cout << inet_ntoa(ip->ip_dst) ;
	cout << ":" << ntohs(tcp->th_dport) << endl;

       // printf("   Src port: %d\n", ntohs(tcp->th_sport));
       // printf("   Dst port: %d\n", ntohs(tcp->th_dport));

        /* define/compute tcp payload (segment) offset */
        const char *payload = (char *)((char *)tcp + size_tcp);
	
//        printf("payload = %x  packet_ethsize+sizeip = %x \n",payload, tcp);
//        printf ("size tcp = %d\n",size_tcp);
//        printf ("tcp = %x\n",tcp);

	int size_ip = IP_HL(ip)*4;

        /* compute tcp payload (segment) size */
        int size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
        /*
         * Print payload data; it might be binary, so don't just
         * treat it as a string.
         */
        if (size_payload > 0) {
                printf("   Payload (%d bytes):\n", size_payload);
                payload_print(payload, size_payload);
        }
	return;
}

void udp_handler (const struct udphdr* udp, const struct sniff_ip *ip) {
	int size_udp1 = sizeof(struct udphdr);
	int size_udp2 = sizeof(udp);
	cout << size_udp1 << " " << size_udp2 << endl;
        const char *payload = (char *)((char *)udp + size_udp1);
	
        cout << inet_ntoa(ip->ip_src);
	cout << ":" << ntohs(udp->uh_sport);
	cout << " -> ";
        cout << inet_ntoa(ip->ip_dst) ;
	cout << ":" << ntohs(udp->uh_dport) << endl;

	int size_ip = IP_HL(ip)*4;
        int size_payload = ntohs(ip->ip_len) - (size_ip + size_udp1);
        if (size_payload > 0) {
                printf("   Payload (%d bytes):\n", size_payload);
                payload_print(payload, size_payload);
        }
	return;
}

void icmp_handler (const struct icmphdr* icmp, const struct sniff_ip *ip) {
	int size_icmp1 = sizeof(struct icmphdr);
	int size_icmp2 = sizeof(icmp);
	cout << size_icmp1 << " " << size_icmp2 << endl;
        const char *payload = (char *)((char *)icmp + size_icmp1);
	
        cout << inet_ntoa(ip->ip_src);
	//cout << ":" ntohs(tcp->th_sport);
	cout << " -> ";
        cout << inet_ntoa(ip->ip_dst) <<endl;
	//cout << ":" ntohs(tcp->th_dport);

	int size_ip = IP_HL(ip)*4;
        int size_payload = ntohs(ip->ip_len) - (size_ip + size_icmp1);
        if (size_payload > 0) {
                printf("   Payload (%d bytes):\n", size_payload);
                payload_print(payload, size_payload);
        }
	return;
}

