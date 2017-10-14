# NetworkMonitor

##############################################################################
			Steps to run the program:
##############################################################################

1)  To compile:
$make

2)  To run:
$./mydump [-i interface] [-r file] [-s string] expression




NOTE: 1) The order of the arguements does not matter and the program would run
correctly. However, the correctness of the arguements matters. For example, 
if any of the -i,-r,-f arguement is not followed by an arguement, the program
would fail.

2)If the interface argument is provided, the program listens on the mentioned
interface, otherwise it listens on the default interface.

3)If the file arguement is present, it reads the data from the pcap file. If
both the interface and file arguements are present, the program reads from the
file.

4)If string arguement is present, the program only displays the payloads which
contains the string filter

##############################################################################
			Sample Outputs:
##############################################################################

------------------------Run without any arguements----------------------------

raghavdogra@ubuntu:~/NetworkMonitor$ sudo ./mydump 

2017-10-13 23:34:58.501548  00:c:29:e3:79:bb -> 00:50:56:e5:98:65 type 0x800  len 84
172.16.207.143:53795 -> 172.16.207.2:53  UDP
e7 7a 01 00 00 01 00 00 00 00 00 00 0c 64 65 74 	.z...........det
65 63 74 70 6f 72 74 61 6c 07 66 69 72 65 66 6f 	ectportal.firefo
78 03 63 6f 6d 00 00 01 00 01                   	x.com.....

2017-10-13 23:34:58.502662  00:c:29:e3:79:bb -> 00:50:56:e5:98:65 type 0x800  len 84
172.16.207.143:53795 -> 172.16.207.2:53  UDP
c2 86 01 00 00 01 00 00 00 00 00 00 0c 64 65 74 	.............det
65 63 74 70 6f 72 74 61 6c 07 66 69 72 65 66 6f 	ectportal.firefo
78 03 63 6f 6d 00 00 1c 00 01                   	x.com.....

2017-10-13 23:34:58.506947  00:50:56:e5:98:65 -> 00:c:29:e3:79:bb type 0x800  len 197
172.16.207.2:53 -> 172.16.207.143:53795  UDP
e7 7a 81 80 00 01 00 04 00 00 00 00 0c 64 65 74 	.z...........det
65 63 74 70 6f 72 74 61 6c 07 66 69 72 65 66 6f 	ectportal.firefo
78 03 63 6f 6d 00 00 01 00 01 c0 0c 00 05 00 01 	x.com...........
00 00 00 05 00 28 0c 64 65 74 65 63 74 70 6f 72 	.....(.detectpor
74 61 6c 07 66 69 72 65 66 6f 78 03 63 6f 6d 09 	tal.firefox.com.
65 64 67 65 73 75 69 74 65 03 6e 65 74 00 c0 36 	edgesuite.net..6
00 05 00 01 00 00 00 05 00 11 05 61 31 30 38 39 	...........a1089
01 64 06 61 6b 61 6d 61 69 c0 59 c0 6a 00 01 00 	.d.akamai.Y.j...
01 00 00 00 05 00 04 c7 6d 63 88 c0 6a 00 01 00 	........mc..j...
01 00 00 00 05 00 04 c7 6d 63 8b                	........mc.




##############################################################################
			Function Descriptions:
##############################################################################


main(): gets the inputs, calls the parse_args() to get the appropriate
arguements. Initializes the device, and loops till the end of file in the -r 
and infinitely in the -i option.

parse_args(): Parses the argv and argc arguements passed via command line and
sets the appropriate flags and strings.

got_packet(): The callback function which is called on reading every packet by
the pcap_loop(). It puts all the desired outputs to the output string stream 
and then finally calls the handler of the protocol of the packet. The packet
handlers for TCP, UDP, ICMP and other packet types is called, based upon the 
packet type. The packet handler is responsible for printing the string stream
onto the console.

tcp_handler(): The function which handles the tcp packet parsing and prints.
Each of the handler decides if the string filter is matched and outputs the
string stream and the payload onto the console.


icmp_handler(): The function which handles the icmp packet parsing and prints.
Each of the handler decides if the string filter is matched and outputs the
string stream and the payload onto the console.


udp_handler(): The function which handles the udp packet parsing and prints.
Each of the handler decides if the string filter is matched and outputs the
string stream and the payload onto the console.


other_handler(): The function which handles the tcp packet parsing and prints.
Each of the handler decides if the string filter is matched and outputs the
string stream and the payload onto the console.

printable(): returns the boolean that the current packet has to be printed
or not.

payload_print(): prints the payload.

print_timestamp(): prints the timestamp onto the string stream.

print_ascii(): prints the ascii version of the payload onto the screen.
