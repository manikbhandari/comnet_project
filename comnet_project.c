
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>	//For standard things
#include <stdlib.h>	//malloc
#include <string.h>	//strlen
 
#include <netinet/ip_icmp.h>	//Provides declarations for icmp header
#include <netinet/udp.h>	//Provides declarations for udp header
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <netinet/if_ether.h>	//For ETH_P_ALL
#include <net/ethernet.h>	//For ether_header
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <linux/filter.h> // CHANGE: include lsf

struct ethernet {
    unsigned char dest[6];
    unsigned char source[6];
    uint16_t eth_type;
};

struct arp {
    uint16_t htype;
    uint16_t ptype;
    unsigned char hlen;
    unsigned char plen;
    uint16_t oper;
    /* addresses */
    unsigned char sender_ha[6];
    unsigned char sender_pa[4];
    unsigned char target_ha[6];
    unsigned char target_pa[4];
};

#define ETH_HDR_LEN 14
#define BUFF_SIZE 2048

struct sock_filter arpfilter[] = {
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12), /* Skip 12 bytes */
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETH_P_ARP, 0, 1), /* if eth type != ARP
                                                         skip next instr. */
    BPF_STMT(BPF_RET+BPF_K, sizeof(struct arp) +
                 sizeof(struct ethernet)),
    BPF_STMT(BPF_RET+BPF_K, 0), /* Return, either the ARP packet or nil */
};

// //DNS PART BEGINS
// //List of DNS Servers registered on the system
// char dns_servers[10][100];
// int dns_server_count = 0;
// //Types of DNS resource records :)
 
// #define T_A 1 //Ipv4 address
// #define T_NS 2 //Nameserver
// #define T_CNAME 5 // canonical name
// #define T_SOA 6 /* start of authority zone */
// #define T_PTR 12 /* domain name pointer */
// #define T_MX 15 //Mail server
 
// //Function Prototypes
// void ngethostbyname (unsigned char* , int);
// void ChangetoDnsNameFormat (unsigned char*,unsigned char*);
// unsigned char* ReadName (unsigned char*,unsigned char*,int*);
// void get_dns_servers();
 
// //DNS header structure
// struct DNS_HEADER
// {
//     unsigned short id; // identification number
 
//     unsigned char rd :1; // recursion desired
//     unsigned char tc :1; // truncated message
//     unsigned char aa :1; // authoritive answer
//     unsigned char opcode :4; // purpose of message
//     unsigned char qr :1; // query/response flag
 
//     unsigned char rcode :4; // response code
//     unsigned char cd :1; // checking disabled
//     unsigned char ad :1; // authenticated data
//     unsigned char z :1; // its z! reserved
//     unsigned char ra :1; // recursion available
 
//     unsigned short q_count; // number of question entries
//     unsigned short ans_count; // number of answer entries
//     unsigned short auth_count; // number of authority entries
//     unsigned short add_count; // number of resource entries
// };
 
// //Constant sized fields of query structure
// struct QUESTION
// {
//     unsigned short qtype;
//     unsigned short qclass;
// };
 
// //Constant sized fields of the resource record structure
// #pragma pack(push, 1)
// struct R_DATA
// {
//     unsigned short type;
//     unsigned short _class;
//     unsigned int ttl;
//     unsigned short data_len;
// };
// #pragma pack(pop)
 
// //Pointers to resource record contents
// struct RES_RECORD
// {
//     unsigned char *name;
//     struct R_DATA *resource;
//     unsigned char *rdata;
// };
 
// //Structure of a Query
// typedef struct
// {
//     unsigned char *name;
//     struct QUESTION *ques;
// } QUERY;

// //DNS PART ENDS

void print_arp_packet(unsigned char *, int, int);
void ProcessPacket(unsigned char* , int);
void ProcessDNSPacket(unsigned char* , int);
void ProcessHTTPPacket(unsigned char* , int);
void ProcessTCPPacket(unsigned char* , int);
void ProcessUDPPacket(unsigned char* , int);
void ProcessICMPPacket(unsigned char* , int);
void ProcessIGMPPacket(unsigned char* , int);
void ipPrint(unsigned char* , int);
void tcpPrint(unsigned char * , int );
void udpPrint(unsigned char * , int );
void icmpPrint(unsigned char* , int );
void PrintData (unsigned char* , int);
void httpPrint (unsigned char* , int);
static void dump_arp(struct arp *);

FILE *logfile, *ethfile, *arpfile, *icmpfile, *tcpfile, *udpfile, *httpfile, *dnsfile;

struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;	
#define buff_size 65536
int sock;
int main()
{
	int saddr_size , data_size;
	struct sockaddr saddr;
		
	unsigned char *buffer = (unsigned char *) malloc(buff_size); //Its Big!
	
	logfile=fopen("log.txt","w+");
	ethfile=fopen("ethernet.txt","w+");
	arpfile=fopen("arp.txt","w+");
	// ipfile=fopen("ip.txt","w+");
	icmpfile=fopen("icmp.txt","w+");
	tcpfile=fopen("tcp.txt","w+");
	udpfile=fopen("udp.txt","w+");
	httpfile=fopen("http.txt","w+");
	dnsfile=fopen("dns.txt","w+");

	if(logfile==NULL) 
	{
		printf("Unable to create log.txt file.");
	}
	printf("Starting...\n");
	
	int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
	//setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+ 1 );
	sock = sock_raw;
	if(sock_raw < 0)
	{
		//Print the error with proper message
		perror("Socket Error");
		return 1;
	}
	
	int op;
	int filter_dns = 0, filter_http = 0, filter_tcp = 0, filter_udp = 0, filter_icmp = 0, filter_igmp = 0;
	printf("Options: \n1: Filter Packets \n2: Capture all packets\n");
	scanf("%d", &op);
	if(op == 1){
		printf("Which kind of packet? (enter in all small): ");
		char *kind;
		kind = (char *)malloc(50*sizeof(char));
		scanf("%s", kind);
		if(strcmp(kind, "dns") == 0){
			filter_dns = 1;
			printf("Starting Capture of only DNS packets\n");
		}
		else if(strcmp(kind, "http") == 0){
			filter_http = 1;
			printf("Starting Capture of only http packets\n");
		}
		else if(strcmp(kind, "tcp") == 0){
			filter_tcp = 1;
			printf("Starting Capture of only tcp packets\n");
		}
		else if(strcmp(kind, "udp") == 0){
			filter_udp = 1;
			printf("Starting Capture of only udp packets\n");
		}
		else if(strcmp(kind, "icmp") == 0){
			filter_icmp = 1;
			printf("Starting Capture of only icmp packets\n");
		}
		else if(strcmp(kind, "igmp") == 0){
			filter_igmp = 1;
			printf("Starting Capture of only igmp packets\n");
		}
	}

	while(total < 50)
	{

		saddr_size = sizeof saddr;
		//Receive a packet
		data_size = recvfrom(sock_raw , buffer , buff_size , 0 , &saddr , (socklen_t*)&saddr_size);
		if(data_size <0 )
		{
			printf("Recvfrom error , failed to get packets\n");
			return 1;
		}
		//Now process the packet
		if(filter_dns == 1){
			ProcessDNSPacket(buffer, data_size);
		}
		else if(filter_http == 1){
			ProcessHTTPPacket(buffer, data_size);	
		}
		else if(filter_tcp == 1){
			ProcessTCPPacket(buffer, data_size);	
		}
		else if(filter_udp == 1){
			ProcessUDPPacket(buffer, data_size);	
		}
		else if(filter_icmp == 1){
			ProcessICMPPacket(buffer, data_size);	
		}
		else if(filter_igmp == 1){
			ProcessIGMPPacket(buffer, data_size);	
		}
		else{
			ProcessPacket(buffer , data_size);
			// printf("processing all packets\n");
		}
	}
	close(sock_raw);
	printf("Finished");
	return 0;
}

void ProcessDNSPacket(unsigned char* buffer, int size){
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));

	unsigned short iphdrlen;
	iphdrlen = iph->ihl*4;

	struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
	// ++total;

	struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen  + sizeof(struct ethhdr));

	if(iph->protocol == 6){ //dns uses either tcp
		if(ntohs(tcph->dest == 53)){
			fprintf(logfile, "\nThis packet was received port 53\n"); //Confirm this from someone
			tcpPrint(buffer, size);
			++total;
		}
		else if(ntohs(tcph->source) == 53){
			fprintf(logfile, "\nThis packet was sent to port 53\n"); //Confirm this from someone
			tcpPrint(buffer, size);	
			++total;
		}
	}	
	else if(iph->protocol == 17){ //or udp
		if(ntohs(udph->dest == 53)){
			fprintf(logfile, "\nThis packet was received port 53\n"); //Confirm this from someone
			udpPrint(buffer, size);
			++total;
		}
		else if(ntohs(udph->source) == 53){
			fprintf(logfile, "\nThis packet was sent to port 53\n"); //Confirm this from someone
			udpPrint(buffer, size);	
			++total;
		}
	}
}

void ProcessHTTPPacket(unsigned char* buffer, int size){
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));

	unsigned short iphdrlen;
	iphdrlen = iph->ihl*4;

	struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
	// ++total;

	// struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));

	if(iph->protocol == 6){ //http uses only tcp
		if(ntohs(tcph->dest) == 80){
			fprintf(logfile, "\nThis packet was received at port 80\n"); //Confirm this from someone
			tcpPrint(buffer, size);
			++total;
		}
		else if(ntohs(tcph->source) == 80){
			fprintf(logfile, "\nThis packet was sent through port 80\n"); //Confirm this from someone
			tcpPrint(buffer, size);	
			++total;
		}
		if(ntohs(tcph->dest) == 443){
			fprintf(logfile, "\nThis packet was received at port 443\n"); //Confirm this from someone
			tcpPrint(buffer, size);
			++total;
		}
		else if(ntohs(tcph->source) == 443){
			fprintf(logfile, "\nThis packet was sent through port 443\n"); //Confirm this from someone
			tcpPrint(buffer, size);	
			++total;
		}
	}	
}

void ProcessTCPPacket(unsigned char* buffer, int size){
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));


	if(iph->protocol == 6){ //this is a tcp packet
		tcpPrint(buffer, size);
		++total;
	}	
}
void ProcessUDPPacket(unsigned char* buffer, int size){
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));


	if(iph->protocol == 17){ //this is a udp packet
		udpPrint(buffer, size);
		++total;
	}	
}
void ProcessICMPPacket(unsigned char* buffer, int size){
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));


	if(iph->protocol == 1){ //this is an icmp packet
		icmpPrint(buffer, size);
		++total;
	}	
}
void ProcessIGMPPacket(unsigned char* buffer, int size){
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));


	if(iph->protocol == 2){ //this is an igmp packet
		
		++total;
	}	
}
void ProcessPacket(unsigned char* buffer, int size)
{
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	++total;
	
	struct arp* arp_hdr = (struct arp*)(buffer + 14);
	dump_arp(arp_hdr);

	switch (iph->protocol) //Check the Protocol and do accordingly...
	{
		case 1:  //ICMP Protocol
			++icmp;
			icmpPrint( buffer , size);
			break;
		
		case 2:  //IGMP Protocol
			++igmp;
			break;
		
		case 6:  //TCP Protocol
			++tcp;
			tcpPrint(buffer , size);
			break;
		
		case 17: //UDP Protocol
			++udp;
			udpPrint(buffer , size);
			break;
		
		default: //Some Other Protocol like ARP etc.
			++others;
			break;
	}
	printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);
}


void ethernet(unsigned char* Buffer, int Size)
{
	ProcessHTTPPacket(Buffer, Size);
	struct ethhdr *eth = (struct ethhdr *)Buffer;
	
	// print_arp_packet(Buffer, Size, sock);

	fprintf(ethfile,"Packet number %d\n", total);
	fprintf(ethfile, "Ethernet Header\n");
	fprintf(ethfile, "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	fprintf(ethfile, "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	fprintf(ethfile, "   |-Protocol            : %u \n\n",(unsigned short)eth->h_proto);
}

void print_arp_packet(unsigned char* Buffer, int Size, int sock){
	// int sock;
    ProcessHTTPPacket(Buffer, Size);
    ProcessHTTPPacket(Buffer, Size);
    void *buffer = NULL;
    ssize_t recvd_size;
    struct ethernet *eth_hdr = NULL;
    struct arp *arp_hdr = NULL;
    struct sock_filter *filter;
    struct sock_fprog  fprog;


    if ((filter = malloc(sizeof(arpfilter))) == NULL) {
        perror("malloc");
        close(sock);
        exit(1);
    }
    memcpy(filter, &arpfilter, sizeof(arpfilter));
    fprog.filter = filter;
    fprog.len = sizeof(arpfilter)/sizeof(struct sock_filter);

    /* CHANGE add filter */
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) == -1) {
        perror("setsockopt");
        close(sock);
        exit(1);
    }
    buffer = malloc(BUFF_SIZE);
   
    memcpy(buffer, Buffer, BUFF_SIZE);
    eth_hdr = (struct ethernet *)buffer;
    if(ntohs(eth_hdr->eth_type) == ETH_P_ARP) {
       arp_hdr = (struct arp *)(buffer+ETH_HDR_LEN);
       dump_arp(arp_hdr);
    }          
    
}
// FILE *fp;
static void dump_arp(struct arp *arp_hdr)
{
    // fp = fopen("arp_dump.txt", "a");

	char *filename = (char *)malloc(20*sizeof(char));
	sprintf(filename, "arp/%d.txt", total);
	FILE *fp = fopen(filename, "w+");

    uint16_t htype = ntohs(arp_hdr->htype);
    uint16_t ptype = ntohs(arp_hdr->ptype);
    uint16_t oper = ntohs(arp_hdr->oper);
    switch(htype)
    {
        case 0x0001:
            fprintf(fp, "ARP HTYPE: Ethernet(0x%04X)\n", htype);
            break;
        default:
            fprintf(fp, "ARP HYPE: 0x%04X\n", htype);
            break;
    }
    switch(ptype)
    {
        case 0x0800:
            fprintf(fp, "ARP PTYPE: IPv4(0x%04X)\n", ptype);
            break;
        default:
            fprintf(fp, "ARP PTYPE: 0x%04X\n", ptype);
            break;
    }
    fprintf(fp, "ARP HLEN: %d\n", arp_hdr->hlen);
    fprintf(fp, "ARP PLEN: %d\n", arp_hdr->plen);
    switch(oper)
    {
        case 0x0001:
            fprintf(fp, "ARP OPER: Request(0x%04X)\n", oper);
            break;
        case 0x0002:
            fprintf(fp, "ARP OPER: Response(0x%04X)\n", oper);
            break;
        default:
            fprintf(fp, "ARP OPER: 0x%04X\n", oper);
            break;
    }
    fprintf(fp, "ARP Sender HA: %02X:%02X:%02X:%02X:%02X:%02X\n",
           arp_hdr->sender_ha[0],arp_hdr->sender_ha[1],arp_hdr->sender_ha[2],
           arp_hdr->sender_ha[3], arp_hdr->sender_ha[4], arp_hdr->sender_ha[5]);
    fprintf(fp, "ARP Sender PA: %d.%d.%d.%d\n", arp_hdr->sender_pa[0],
           arp_hdr->sender_pa[1], arp_hdr->sender_pa[2], arp_hdr->sender_pa[3]);
    fprintf(fp, "ARP Target HA: %02X:%02X:%02X:%02X:%02X:%02X\n",
           arp_hdr->target_ha[0],arp_hdr->target_ha[1],arp_hdr->target_ha[2],
           arp_hdr->target_ha[3], arp_hdr->target_ha[4], arp_hdr->target_ha[5]);
    fprintf(fp, "ARP Target PA: %d.%d.%d.%d\n", arp_hdr->target_pa[0],
           arp_hdr->target_pa[1], arp_hdr->target_pa[2], arp_hdr->target_pa[3]);
    fprintf(fp, "ARP DONE =====================\n");
}

void ipPrint(unsigned char* Buffer, int Size)
{
	ProcessHTTPPacket(Buffer, Size);
	ProcessHTTPPacket(Buffer, Size);
	ethernet(Buffer , Size);
  
	unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
	char *filename = (char *)malloc(20*sizeof(char));
	sprintf(filename, "ip/%d.txt", total);
	FILE *ipfile = fopen(filename, "w+");

	fprintf(ipfile, "Packet Number : %d\n", total);
	fprintf(ipfile, "IP Header\n");
	fprintf(ipfile, "   |-IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(ipfile, "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(ipfile, "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(ipfile, "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(ipfile, "   |-Identification    : %d\n",ntohs(iph->id));
	
	fprintf(ipfile, "   |-TTL      : %d\n",(unsigned int)iph->ttl);
	fprintf(ipfile, "   |-Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(ipfile, "   |-Checksum : %d\n",ntohs(iph->check));
	fprintf(ipfile, "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
	fprintf(ipfile, "   |-Destination IP   : %s\n\n",inet_ntoa(dest.sin_addr));
}

void tcpPrint(unsigned char* Buffer, int Size)
{
	ProcessHTTPPacket(Buffer, Size);
	ProcessHTTPPacket(Buffer, Size);
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
			
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

	char *filename = (char *)malloc(20*sizeof(char));
	sprintf(filename, "tcp/%d.txt", total);
	FILE *tcpfile = fopen(filename, "w+");
	
	fprintf(tcpfile , "\n\n***********************TCP Packet no %d*************************\n", tcp);	
		
	ipPrint(Buffer,Size);
		
	fprintf(tcpfile , "\n");
	fprintf(tcpfile , "TCP Header\n");
	fprintf(tcpfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
	fprintf(tcpfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
	fprintf(tcpfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
	fprintf(tcpfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
	fprintf(tcpfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	//fprintf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
	//fprintf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	fprintf(tcpfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	fprintf(tcpfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	fprintf(tcpfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
	fprintf(tcpfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
	fprintf(tcpfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	fprintf(tcpfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
	fprintf(tcpfile , "   |-Window         : %d\n",ntohs(tcph->window));
	fprintf(tcpfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
	fprintf(tcpfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
	fprintf(tcpfile , "\n\n");
	fprintf(logfile , "                        DATA Dump                         ");
	fprintf(logfile , "\n");
		
	fprintf(logfile , "IP Header\n");
	PrintData(Buffer,iphdrlen);
		
	fprintf(logfile , "TCP Header\n");
	PrintData(Buffer+iphdrlen,tcph->doff*4);
		
	fprintf(logfile , "Data Payload\n");	
	PrintData(Buffer + header_size , Size - header_size );

	if(ntohs(tcph->source) == 80 || ntohs(tcph->dest) == 80){
		httpPrint(Buffer + header_size , Size - header_size );
	}
						
	fprintf(logfile , "\n###########################################################");
}

void udpPrint(unsigned char *Buffer , int Size)
{
	
	ProcessHTTPPacket(Buffer, Size);
	ProcessHTTPPacket(Buffer, Size);
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

	char *filename = (char *)malloc(20*sizeof(char));
	sprintf(filename, "udp/%d.txt", total);
	FILE *udpfile = fopen(filename, "w+");
	
	fprintf(udpfile , "\n\n***********************UDP Packet no %d*************************\n", udp);
	
	ipPrint(Buffer,Size);			
	
	fprintf(udpfile , "\nUDP Header\n");
	fprintf(udpfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
	fprintf(udpfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
	fprintf(udpfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
	fprintf(udpfile , "   |-UDP Checksum     : %d\n\n" , ntohs(udph->check));
	
	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	PrintData(Buffer , iphdrlen);
		
	fprintf(logfile , "UDP Header\n");
	PrintData(Buffer+iphdrlen , sizeof udph);
		
	fprintf(logfile , "Data Payload\n");	
	
	//Move the pointer ahead and reduce the size of string
	PrintData(Buffer + header_size , Size - header_size);
	
	fprintf(logfile , "\n###########################################################");
}

void icmpPrint(unsigned char* Buffer , int Size)
{
	ProcessHTTPPacket(Buffer, Size);
	ProcessHTTPPacket(Buffer, Size);
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	
	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

	char *filename = (char *)malloc(20*sizeof(char));
	sprintf(filename, "icmp/%d.txt", total);
	FILE *icmpfile = fopen(filename, "w+");
	
	fprintf(icmpfile , "\n\n***********************ICMP Packet no %d*************************\n", icmp);	
	
	ipPrint(Buffer , Size);
			
	fprintf(icmpfile , "\n");
		
	fprintf(icmpfile , "ICMP Header\n");
	fprintf(icmpfile , "   |-Type : %d",(unsigned int)(icmph->type));
			
	if((unsigned int)(icmph->type) == 11)
	{
		fprintf(icmpfile , "  (TTL Expired)\n");
	}
	else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
	{
		fprintf(icmpfile , "  (ICMP Echo Reply)\n");
	}
	
	fprintf(icmpfile , "   |-Code : %d\n",(unsigned int)(icmph->code));
	fprintf(icmpfile , "   |-Checksum : %d\n",ntohs(icmph->checksum));
	//fprintf(logfile , "   |-ID       : %d\n",ntohs(icmph->id));
	//fprintf(logfile , "   |-Sequence : %d\n",ntohs(icmph->sequence));
	fprintf(icmpfile , "\n\n");

	fprintf(logfile , "IP Header\n");
	PrintData(Buffer,iphdrlen);
		
	fprintf(logfile , "UDP Header\n");
	PrintData(Buffer + iphdrlen , sizeof icmph);
		
	fprintf(logfile , "Data Payload\n");	
	
	//Move the pointer ahead and reduce the size of string
	PrintData(Buffer + header_size , (Size - header_size) );
	
	fprintf(logfile , "\n###########################################################");
}

void httpPrint(unsigned char* data , int Size){
	
	char *filename = (char *)malloc(20*sizeof(char));
	sprintf(filename, "http/%d.txt", total);
	FILE *httpfile = fopen(filename, "w+");

	fprintf(httpfile , "\n***********http packet************\n"); //if its a number or alphabet

	int i , j;
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			// fprintf(httpfile , "         ");
			int flag = 0;
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(httpfile , "%c",(unsigned char)data[j]); //if its a number or alphabet
				
				else{
					
					if(flag == 0){
						flag = 1;
					}
					else {
					fprintf(httpfile , "\n"); //otherwise print a dot	
					flag = 0;
				} 
			}
		}
			// fprintf(httpfile , "\n");
		} 
		
		// if(i%16==0) fprintf(logfile , "   ");
		// 	fprintf(logfile , " %02X",(unsigned int)data[i]);
				
		if( i==Size-1)  //print the last spaces
		{
			// for(j=0;j<15-i%16;j++) 
			// {
			//   fprintf(httpfile , "   "); //extra spaces
			// }
			
			// fprintf(httpfile , "         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) 
				{
				  fprintf(httpfile , "%c",(unsigned char)data[j]);
				}
				else 
				{
				  // fprintf(httpfile , "\n");
				}
			}
			
			// fprintf(httpfile ,  "\n" );
		}
	}
}



void PrintData (unsigned char* data , int Size)
{
	
	int i , j;
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(logfile , "         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet
				
				else fprintf(logfile , "."); //otherwise print a dot
			}
			fprintf(logfile , "\n");
		} 
		
		if(i%16==0) fprintf(logfile , "   ");
			fprintf(logfile , " %02X",(unsigned int)data[i]);
				
		if( i==Size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) 
			{
			  fprintf(logfile , "   "); //extra spaces
			}
			
			fprintf(logfile , "         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) 
				{
				  fprintf(logfile , "%c",(unsigned char)data[j]);
				}
				else 
				{
				  fprintf(logfile , ".");
				}
			}
			
			fprintf(logfile ,  "\n" );
		}
	}
}