How to execute:-


To execute it one should have root permission.

Example :-

To do all types of scan on ports from 1 to 100 on 129.79.247.87 ip with 100 threads you should use below command 
Here speedup specifies the number of threads needed( 500 is maximum allowed) .
nice sudo  ./Test --ip  129.79.247.87    --port 1-100  --scan ACK,SYN,UDP,XMAS,NULL,FIN  --speedup 100


Samples from output:

Given TCP port unfiltered for host 129.79.247.87 and port 98 and scantype is ACK 
Given TCP port closed  for host 129.79.247.87 and port 53 and scantype is SYN 
Given TCP port unfiltered for host 129.79.247.87 and port 93 and scantype is ACK 
Given TCP port closed  for host 129.79.247.87 and port 57 and scantype is SYN 
Given TCP port unfiltered for host 129.79.247.87 and port 96 and scantype is ACK 
Given TCP port closed  for host 129.79.247.87 and port 56 and scantype is SYN 
Given TCP port closed  for host 129.79.247.87 and port 54 and scantype is SYN 
Given TCP port unfiltered for host 129.79.247.87 and port 94 and scantype is ACK 
Given TCP port closed  for host 129.79.247.87 and port 60 and scantype is SYN 
Given TCP port closed  for host 129.79.247.87 and port 59 and scantype is SYN 
Given TCP port closed  for host 129.79.247.87 and port 61 and scantype is SYN 
Given TCP port closed  for host 129.79.247.87 and port 65 and scantype is SYN 



Conclusion for Host129.79.247.87
 =========================================
OPEN ports 
=======================
port Service Name                                           Results                                                                                             conclusion                    
22   SSH(Version:SSH-2.0-OpenSSH_5.3)                  ACK:UNFILTERED SYN:OPEN UDP:CLOSED XMAS:OPEN|FILTERED NULL:OPEN|FILTERED FIN:OPEN|FILTERED          conclusion:CLOSED             
24   SMTP(RUNNING)                                     ACK:UNFILTERED SYN:OPEN UDP:CLOSED XMAS:OPEN|FILTERED NULL:OPEN|FILTERED FIN:OPEN|FILTERED          conclusion:CLOSED             
43   WhoIs(Version:1.0rc)                              ACK:UNFILTERED SYN:OPEN UDP:CLOSED XMAS:OPEN|FILTERED NULL:OPEN|FILTERED FIN:OPEN|FILTERED          conclusion:CLOSED             
80   HTTP(Version:Apache/2.2.15 (Red Hat))             ACK:UNFILTERED SYN:OPEN UDP:CLOSED XMAS:OPEN|FILTERED NULL:OPEN|FILTERED FIN:OPEN|FILTERED          conclusion:CLOSED             

CLOSED/FILTERED ports 
=======================
port Service Name                                           Results                                                                                             conclusion                    
1    tcpmux                                            ACK:UNFILTERED SYN:CLOSED UDP:CLOSED XMAS:CLOSED NULL:CLOSED FIN:CLOSED                             conclusion:CLOSED             
2    nbp                                               ACK:UNFILTERED SYN:CLOSED UDP:CLOSED XMAS:CLOSED NULL:CLOSED FIN:CLOSED                             conclusion:CLOSED             
3    Unknown Application                               ACK:UNFILTERED SYN:CLOSED UDP:CLOSED XMAS:CLOSED NULL:CLOSED FIN:CLOSED                             conclusion:CLOSED             

:::::





Basic Overview of system:- 
Steps involved are
1.	All the required option parsing processing is done.
2.	Create a raw packet based on the type of scan and fill it accordingly
3.	Preparing threads based on speed up option. If no speed up then it will create a single thread.
4.	Created thread is invoked to send the filled raw packet and fetch the response of remote system.
5.	Based on the response the status of port is decided.
6.	If there are multiple scans on same port and same ip, we should derived conclusion among all the status.
7.	Checked the version of ports specified and pushed into vector
8.	All the scan results and derivations are pushed into vector.
9.	Finally all the information in the vector is processed to produce formatted output.
10.	Continue steps 4 to 9 for all created threads.


Functions and Files used are :-


Args_setup.cpp
Similar to bit torrent we used a structure to store all the parameter supplied to the program. All the parsing of options such as speedup, file, ip, port, scan and help is done in this file. The processed ports are stored in portlist vector, scans supplied are stored in scan list vector and ip list is stored in iplist vector.

Args_setup.h
•It has the header file and structures used to store IP, Scan, Port and args structure to store all options.

Portscanner.cpp
This file is the heart of the project.Here based on the vectors (IP,Scan and port) we prepared a queue of triples.Based on speeup we created threads and single thread is prepared for no speedup option. 

Functions used are

•Send_packet() 
It creates a TCP packet with desired flag and sends to remote host. Pcap filter is initialized and compiled here.Pcap is made to listed to device based on compiled filter expression.Once raw packet is sent, the response is captured using pcap _next_ex() . Also pcap will listen for 4 seconds and it is specified in pcap_open_live function.The packet response is validated using check_response_icmp() . If it is not expect packet retransmission is done thrice. send_packet_udp() is called if scan 
flag is UDP .

•find_status ()
Once you get the packet response for the scan the response is processed to get status of port using find_status () .It is written to incorporate logic given in port scanning techniques  section of lab document.

•check_response_icmp() 
It verifies whether given response is expected or not. It returns the status code.It also verify whether packet response is NULL or not.

•send_packet_udp()
It is similar to Send_packet() it is to send UDP packets instead of TCP raw packets.

•process_job_queue()
It will get all the triplets from the queue and call threads to scan them.


Resources used:-

http://www.cplusplus.com/forum/general/9403/
http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/
http://sock-raw.org/papers/syn_scanner
http://www.tutorialspoint.com/cplusplus/cpp_multithreading.htm
http://www.tcpipguide.com/free/t_UDPMessageFormat-2.htm
http://nmap.org/book/man-port-scanning-techniques.html
http://www.auditmypc.com/port-scanning.asp
http://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
http://www.tcpdump.org/pcap.html
We talked about approach with Srihari.
http://sock-raw.org/papers/syn_scanner
http://www.yolinux.com/TUTORIALS/LinuxTutorialPosixThreads.html
http://www.cplusplus.com/forum/general/13135/
http://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
http://stackoverflow.com/questions/12231166/timing-algorithm-clock-vs-time-in-c

