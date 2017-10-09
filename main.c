#include <stdio.h>
#include <pcap.h>
#include <iostream>
#include <string>
#include "mydump.h"

using namespace std;

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	const char * dev;
	string interface, fl, str, expr;

	int i_p, f_p, s_p, e_p; //presence of -i,-f,-s or expression
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
			expr = argv[i];
			e_p = 1;
		}
	}

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

	return(0);
}

