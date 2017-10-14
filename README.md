# NetworkMonitor

##############################################################################
			Steps to run the program:
##############################################################################

1)  To compile:
$make

2)  To run:
$./mydump [-i interface] [-r file] [-s string] expression




NOTE: The order of the arguements does not matter and the program would run
correctly. However, the correctness of the arguements matters. For example, 
if any of the -i,-r,-f arguement is not followed by an arguement, the program
would fail.


##############################################################################
			Sample Outputs:
##############################################################################





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
