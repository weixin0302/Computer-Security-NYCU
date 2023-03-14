#include <stdio.h> 
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h> 
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>

struct PSEUDO_HEADER
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t udp_length;
};

struct DNS_HEADER
{
    unsigned short id :16;
    unsigned short flags :16;
    unsigned short q_count :16;
    unsigned short ans_count :16;
    unsigned short auth_count :16;
    unsigned short add_count :16;
};

struct query
{
	unsigned short qtype;
	unsigned short qclass;
};

unsigned short csum(unsigned short *ptr, int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

void DNS_format(char * buff, const char * hostname) {
    char record[50];

    strncpy(record, hostname, 50);
    strncat(record, ".", 2);

    for (uint16_t i = 0, j = 0; record[i]; i++) {
        if(record[i] == '.') {
            *buff++ = i - j;
            for(; j < i; j++) {
                *buff++ = record[j];
            }
            j++;
        }
    }
    *buff++ = '\0';
}
