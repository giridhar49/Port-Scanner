#ifndef ARG_H
#define ARG_H

#include <vector>
#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fstream>
#include <stdio.h>
#include <netdb.h>
#include <sys/types.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <ctype.h>

#include<math.h>
#include <sstream>
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
#define ETHERNET_SIZE  14
#include <iostream>
#include <sstream>
#include <queue>
#include <thread>
#include <map>



using namespace std;

typedef struct
{
	string host;
	int port;
	int result[7]; // result for each type of scan  // note zero is out that why need extra element
        int scantype;  // needed because results filled in thread so each element 
// 1 OPEN  2 OPEN|FILTERED 3 FILTERED 4 CLOSED 5 UNFILTERED



} result_elem;

typedef struct {
string ip;
int port;
vector<int> scantype;
}job_element;

typedef struct{
  string ip;
  int port;
  vector<string> results;
}result;

////
/*
logic for results is
1- open is open
2- closed if not open and one closed
3- filterd otherwise

*/

////


typedef struct{
//int isprefix;
//int isfile;
//int isip;
int threadcount;
vector<int> portlist;
vector<int> scanlist;
vector<string> iplist;
int scanflag; //no flag set
queue<job_element> jobqueue;
 
       
}bt_args_t;

void usage(FILE * file);
void parse_args(int argc,  char * argv[], bt_args_t * bt_args);
#endif
