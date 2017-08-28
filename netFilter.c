#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <libnetfilter_queue/libnetfilter_queue.h>


char filterList[255][255];
int filterSize = 0;


char *subStr( char *pnInput, int nStart, int nLen ){
    int nLoop ;
    int nLength ;
    char *pszOutPut ;

    if( pnInput == NULL ){
        return NULL ;
    }
    pszOutPut = (char *)malloc( sizeof(char) * nLen + 1 ) ;
    nLength = strlen( pnInput ) ;

    if( nLength > nStart + nLen ){
        nLength = nStart + nLen ;
    }
    for( nLoop = nStart ; nLoop < nLength ; nLoop++ ){
        pszOutPut[nLoop-nStart] = pnInput[nLoop] ;
    }
    pszOutPut[nLoop - nStart] = '\0' ;
    return pszOutPut ;
}

/* returns packet id */
static int filter (struct nfq_data *tb)
{
	struct nfqnl_msg_packet_hdr *ph;
	//struct nfqnl_msg_packet_hw *hwph;
	//u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;
	int ip_len = 0;
	struct ip *ip;
	struct tcphdr *tcp;
	unsigned char *http_data;
	char *token = NULL;
	char *first = NULL;
	char *second = NULL;
	char *third = NULL;

	ret = nfq_get_payload(tb, &data);

	if(ret <= 0)
		return 0;

	ip = (struct ip*)(data);

	if(ip->ip_p != 0x06)
		return 0;

	tcp = (struct tcphdr *)(data + (ip->ip_hl * 4));

	if(tcp->th_dport != 0x5000)
		return 0;
	
	http_data = (unsigned char*)(data + ((ip->ip_hl * 4) + (tcp->th_off) * 4));


	first = strstr(http_data, "GET / HTTP/1.");
	
	if(first == NULL)
		return 0;

	second = strstr(first, "Host: ");

	if(second ==NULL)
		return 0;

	token = strtok(second, "\r\n");

	if(token == NULL)
		return 0;

	third = subStr(token, 6, strlen(token));

	for(int i=0; i<filterSize; i++){
		if(!strstr(third, filterList[i])){
			printf("%s is filtered\n", third);
			return 1;
		}
	}

	return 0;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{

	struct nfqnl_msg_packet_hdr *ph;
	int flag = 0;
	u_int32_t id;

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
	}
	
	flag = filter(nfa);

	if(flag)
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);		

	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char fileBuf[255];
	char buf[4096] __attribute__ ((aligned));

	if(argc < 2){
		printf("need rule file\n");
		return 0;
	}

	FILE *fp = fopen(argv[1], "r");

	if(fp == NULL){
		printf("can't open the file\n");
		return 0;
	}

	while(!feof(fp)){
		if(fgets(fileBuf, sizeof(fileBuf), fp)){
			strncpy(filterList[filterSize], fileBuf, sizeof(filterList[filterSize]));
			filterSize++;
		}
	}


	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
