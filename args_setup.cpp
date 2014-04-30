#include "args_setup.h"


int check_ip_add(string ipAdd){
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAdd.c_str(), &(sa.sin_addr));
    return result;            

}
vector<string> get_AllIPs_From_network_Prefix(string prefix);

queue<job_element> fill_queue_jobs(bt_args_t * bt_args){
    int idx1,idx2,idx3;
    
    queue<job_element> jobq;
    for (idx1=0;idx1<bt_args->iplist.size();idx1++)                
        for (idx2=0;idx2< bt_args->portlist.size();idx2++)
        {
              job_element temp_elem;
              temp_elem.ip=bt_args->iplist[idx1];
              temp_elem.port= bt_args->portlist[idx2];
              //cout<<"Scanlist size "<< bt_args->scanlist.size() <<endl;
              for (idx3=0;idx3<bt_args->scanlist.size();idx3++){
                
                temp_elem.scantype.push_back(bt_args->scanlist[idx3]);
               
                
                } 
                jobq.push(temp_elem); 
    }
    return jobq;
}

vector< string >  read_file(const char* filename){
        vector< string > ips;
        string my_ip;
	ifstream infile;
	infile.open (filename);
        while(!infile.eof()) // To get you all the lines.
        {
	        getline(infile,my_ip); // Saves the line in STRING.
	        //cout<<"From file "<<my_ip<<endl; // Prints our STRING.
                
                if (my_ip.find("/")!=-1)
                    {
                        
                        vector<string> t=get_AllIPs_From_network_Prefix(my_ip);
                        //cout<<"D: "<<t.size()<<endl; 
                    
                    
                    
                    for (int i=0;i<t.size();i++){
                             int result=check_ip_add(t[i]);
                             //cout<<"D: "<<t[i]<<endl; 
                            if (result != 1){
                                printf(" worng IP when reading from file, plz try the program again with correct ip \n");
                                exit(1); 
                            }
                            ips.push_back(t[i]);
                        
                        }
                     }
                    
                else{
                        int result=check_ip_add(my_ip);
                        if (result != 1){
                            printf(" worng IP when reading from file, plz try the program again with correct ip \n");
                            exit(1); 
                        }
                        ips.push_back(my_ip);
                    }
                
        }
	infile.close();
        
        return ips;
}
 
    
vector<string> get_AllIPs_From_network_Prefix(string prefix){

    vector<string> addresses;

    if (prefix.find("/")==-1)
        return addresses;
    const char* pref = prefix.c_str();
    unsigned char ip[4];
    int bitCount = 0, byteCount = 3, slashPos = 0;
    for(int i = 0; i < prefix.length(); i++){
        if(isdigit(pref[i])){
        bitCount++;
        }
        else if(pref[i] == '.'){
        ip[byteCount] = (char) atoi(prefix.substr(i-bitCount, bitCount).c_str());
        byteCount--;
        bitCount = 0;
        }
        else if(pref[i] == '/'){
        ip[byteCount] = (char) atoi(prefix.substr(i-bitCount, bitCount).c_str());
        slashPos = i;
        }
        else{

        }
    }

    //get prefix length
    int prefixLength = atoi(prefix.substr(slashPos+1, prefix.length()-slashPos).c_str());
    //cout<< "prefixLength" <<  prefixLength << " slashPos" << slashPos;
    //generate netmask (in case we get inconsistent prefixes)
    unsigned long mask = 0;
    unsigned long bit = 0x80000000;
    for(int i = 0; i < prefixLength; i++){
    mask = mask | bit;
    bit = bit >> 1;
    }

    //get smallest IP address
    unsigned long minIP = (*(unsigned long*) ip) & mask;
    unsigned char ipOctets[4], *temp;
    temp = (unsigned char *) &minIP;

    //enumerate over all ip addresses
    minIP = minIP + 1;
    ostringstream tempString;
    int s;
    s=pow(2, (32 - prefixLength)) - 2;
    for(int i = 0; i < s; i++){
    tempString.clear();
    tempString.str("");
    tempString  << dec <<  (int) temp[3] << "." << (int) temp[2] << "." << (int) temp[1] << "." << (int)temp[0];
    //cout << tempString.str() << endl;
    addresses.push_back(tempString.str());
    minIP++;
}

return addresses;
}






vector<int> parse_string_comma_delimited_for_ports(string temp){
      
    int idx;  
    istringstream ss(temp);
    string token;
    vector<string> output;
    vector<int> ports;
    int scanflagtemp;
    while(std::getline(ss, token, '-')) {
    //cout << token << '\n';
    output.push_back(token);
    }
    
    // seprate the cases 1,2,3 and 1,2,3-5
    // output should be 2 strings
    
    string fpart=output[0];
    istringstream ss1(fpart);
    string token1;
    while(std::getline(ss1, token1, ',')) {
    //cout << token << '\n';
    int value;
    istringstream ( token1 ) >> value;
    //int value = atoi(token1.c_str());
    ports.push_back(int(value));
    }
    int i;
    if (output.size() >1)
        {
        string spart=output[1];
           // 
           int p1=ports[ports.size()-1];
           //int p2=int(spart);
           int p2;
           istringstream ( spart ) >> p2;
           for (i=p1;i<=p2;i++)
            ports.push_back(int(i));
        
        }
        
    
    /*
    for (i=0;i<output.size();i++)
    {
     cout << output[i] << "----";
     
    }
    
    for (i=0;i<ports.size();i++)
    {
     cout << "port "<< ports[i] << "----";
     
    }
    */
    
    return ports;


}
vector<int> parse_string_comma_delimited(string temp){
      
    int idx;  
    istringstream ss(temp);
    string token;
    vector<string> output;
    vector<int> scan_flags;
    int scanflagtemp;
    while(std::getline(ss, token, ',')) {
    //cout << token << '\n';
    output.push_back(token);
    }
      
    for (idx=0;idx<output.size();idx++){
          string scantype =output[idx];
          
          if(scantype.compare("SYN")==0) scanflagtemp=1; //pushed into scan_list vector
          else if(scantype.compare("NULL")==0) scanflagtemp=2;
          else if(scantype.compare("FIN")==0) scanflagtemp=3; 
          else if(scantype.compare("XMAS")==0) scanflagtemp=4;
          else if(scantype.compare("ACK")==0) scanflagtemp=5;
          else if(scantype.compare("UDP")==0) scanflagtemp=6;
          //else  bt_args->scanflag=0; //pushed into scan_list vector
          scan_flags.push_back(scanflagtemp);
                  
          }
    
    return scan_flags;
    
    
             

}

void usage(FILE * file){
  if(file == NULL){
    file = stdout;
  }
  
  fprintf(file,
  	  " Usage:\n"
          "./portScanner [option1 .... optionN]\n"
          "  --help \tPrint this help screen\n"
          "  --ports <ports to scan> \tExample: \"./portScanner --ports 1,2,3-5\"\n"
          "  --ip <IP address to scan> \tExample: \"./portScanner --ip 127.0.0.1\"\n"
          "  --prefix <IP prefix to scan> \tExample: \"./portScanner --prefix 127.143.151.123/24\"\n"
          "  --file <file name containing IP addresses to scan>   \tExample: \"./portScanner --file filename.txt\"\n"
          "  --speedup <parallel threads to use> \tExample: \"./portScanner --speedup 10\"\n"
          "  --scan <one or more scans> \tExample: \"./portScanner --scan SYN NULL FIN XMAS\"\n");
}







void parse_args(int argc,char * argv[], bt_args_t * bt_args){

//// intialize the structure
   
    bt_args->threadcount=1;
    //bt_args->scanflag=0;
    int idx;
    for(int i = 1; i < argc; i++) {
        string arg = argv[i];
   	
         
        if(arg == "--help") {
   	   usage(stdout);
   	   exit(0);
   		 }

        else if (arg== "--port"){
                //Need to fill this 
                
                /*
                int intialport,finalport;
                intialport= (int) atoi(argv[i+1]);
                finalport=(int) atoi((argv[i+2]));
                i=i+2;
                
                for(idx=intialport;idx<=finalport;idx++)
                    bt_args->portlist.push_back(idx);
                    
                bt_args->isip=1;
                 */
                 
                    bt_args->portlist=parse_string_comma_delimited_for_ports(argv[i+1]);   
                    
                    }
	else if(arg.compare("--speedup")==0){
		char *count=argv[i+1];
                int thread_counts=atoi(count);
                if ( thread_counts > 500)
                    thread_counts=500;
		bt_args->threadcount=thread_counts;
                
                
		}

        else if(arg.compare("--ip")==0){
                // Need to convert hostname into ip and fill the vector
                 
                 /*   struct hostent *he;
                    struct in_addr **addr_list;
                    he =gethostbyname(argv[i+1]);
                    if (he == 0) {  // get the host info
                         herror("gethostbyname");
                            return ;
                        }
                */
                // IP should be in format 127.0.0.1
                // check for ip http://stackoverflow.com/questions/318236/how-do-you-validate-that-a-string-is-a-valid-ip-address-in-c
                string ipAdd=(argv[i+1]);
                // check if the ip is correct ip.
                int result=check_ip_add(ipAdd);
                if (result != 1){
                    printf(" worng IP try the program again with correct ip \n");
                    exit(1); 
                }
                
                bt_args->iplist.push_back(ipAdd);
                //cout<< " IP address is "<< ipAdd <<endl;
                //Ip List should be parsed using tokenizer and store it in a list 
                        
                //bt_args->isip=1;
		}

	else if(arg.compare("--prefix")==0){
		//Need to parse prefix into ip 
                //1 - get all ips 
                string prefixStr=argv[i+1];
                
                if (prefixStr.find("/")==-1)
                {
                     printf(" worng prefix,plz try the program again with correct ip \n");
                    exit(1); 
                    
                }
                    
                vector<string> templist=get_AllIPs_From_network_Prefix(prefixStr);
                
                // 2- insert all ips into the arg list for ips
                
                for (idx=0;idx<templist.size();idx++)
                    {
                        
                      int result=check_ip_add(templist[idx]);
                        if (result != 1){
                            printf(" worng IP try the program again with correct ip \n");
                            exit(1); 
                        }  
                    bt_args->iplist.push_back(templist[idx]);
                
                    
                    }
                /*
                cout<< " All Ips in iplist now is "<<bt_args->iplist.size()<<endl;
                for (idx=0;idx<templist.size();idx++)
                    cout<< bt_args->iplist[idx]<<endl;
                */   
                
                //bt_args->isip=1; //Indicating that IP is set
		}
        else if(arg.compare("--file")==0){
                
                string filename=argv[i+1];
                vector<string> temp_ip_list=read_file(filename.c_str());
                
                
                // insert all ips readed from file into the args_iplist 
                for (idx=0;idx<temp_ip_list.size();idx++){
                    // check if ip is correct or not
                    //cout << temp_ip_list[idx] <<endl;
                    //cout << "----\n";
                    
                    if (check_ip_add(temp_ip_list[idx])){
                        bt_args->iplist.push_back(temp_ip_list[idx]);
                        
                    }
                    
                }
		//bt_args->isip=1;
		
                }

        else if(arg.compare("--scan")==0){
          
              string  scantype=argv[i+1]; 
              bt_args->scanlist=parse_string_comma_delimited(scantype);
              
 
            }


                 

}

        
  
    
    
    
    if (bt_args->scanlist.size()<1){
            
            // fill the scan list with all types of scan
            for (int s=1;s<=5;s++)
                bt_args->scanlist.push_back(s);
            
            }
            
        if (bt_args->portlist.size() <1){
            // fill the port list from 1 to 1024
            for (int s=1;s<=1024;s++)
            bt_args->portlist.push_back(s);
            
            }
            
            
            if (bt_args->iplist.size()<1){
                
                printf (" There is no ip, plz run the program again with correct ip \n");
                exit(1);
                }
             
        
        
            
            
            bt_args->jobqueue=fill_queue_jobs(bt_args);
            /*
            cout << " The job queue: \n";
            while(!bt_args->jobqueue.empty())
            {
                job_element t=bt_args->jobqueue.front();
                bt_args->jobqueue.pop();
                cout<<"\nTest "<<t.ip<<"\t"<<t.port<<"\t"<<t.scantype;
            
            } */   
            
            
            
            //create_call_threads(bt_args);
            
            
}


/*
////////////////////////////

pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;

void* process_job_queue(void* bt_args){
         bt_args_t* my_arg=(bt_args_t*)bt_args;
        cout<<" Inside process_job_queue\N";
        cout <<" Size of queue " << my_arg->jobqueue.size()<<"\n";;
        bool empty_check=false;
       
        
        pthread_mutex_lock( &mutex1 );
        empty_check=my_arg->jobqueue.empty();
        pthread_mutex_unlock( &mutex1 );
 
        while (!empty_check)
        {
            // get the element of job queue
            pthread_mutex_lock( &mutex1 );
            job_element t=my_arg->jobqueue.front();
            my_arg->jobqueue.pop();
            cout <<" Size of queue " << my_arg->jobqueue.size()<<"\n";;
            //bt_args->jobqueue.push(t);
            //cout<<"\n Process Job: for "<<t.ip<<"\t"<<t.port<<"\t"<<t.scantype;
            pthread_mutex_unlock( &mutex1 );
            
            //char*hostip=hostname_to_ip(t->);
            // processing the element job here
            
            int scantype;
            
            for (int i=0; i< t.scantype.size();i++)
            {
                
                scantype= t.scantype[i];
                printf("\n inside thread ip  %s port : %d flag: %d",t.ip.c_str(), t.port, scantype);
                send_packet(t.ip.c_str(), t.port, scantype);
                    
            }
            
            // check for the empty
            pthread_mutex_lock( &mutex1 );
            empty_check=my_arg->jobqueue.empty();
            pthread_mutex_unlock( &mutex1 );
            
        }
        
        
      

}

void create_call_threads(bt_args_t * bt_args){
    //http://www.tutorialspoint.com/cplusplus/cpp_multithreading.htm
    
    cout<<" Inside creat_call_thread\N";
    cout <<" Size of queue " << bt_args->jobqueue.size()<<"\n";;
    int num_threads=bt_args->threadcount;
    pthread_t threads[num_threads];
    int rc,i;
    for( i=0; i < num_threads; i++ ){
      cout << "main() : creating thread, " << i << endl;
      rc=pthread_create(&threads[i], NULL, process_job_queue, (void *)bt_args);
      if ( rc != 0){
         cout << "Error:unable to create thread " << i<< " exit with "<< rc << endl;
         //exit(-1);
      }
      
      }
      
      
      
      // wait for join the threads
      
      for( i=0; i < num_threads; i++ ){
          
             pthread_join( threads[i], NULL);
          }
          
        
        exit(0);

}

///////////////////////////////////

*/

