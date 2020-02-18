#ifndef _gbn_h
#define _gbn_h

#include<sys/types.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<signal.h>
#include<unistd.h>
#include<fcntl.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<time.h>

typedef struct sockaddr sockaddr;

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define TRUE 1
#define FALSE 0

/*----- Error variables -----*/
extern int h_errno;
extern int errno;

/*----- Debugging flag for logging -----*/
/* #define DEBUG 0 */

/*----- Protocol parameters -----*/
#define LOSS_PROB 1e-2    /* loss probability												*/
#define CORR_PROB 1e-3    /* corruption probability											*/
#define DATALEN   1024    /* length of the payload      					                */
#define N         1024    /* max number of packets a single call to gbn_send can process 	*/
#define TIMEOUT      1    /* timeout to resend packets (1 second)        					*/
#define MAX_CONN     5    /* max number of connection/disconnection attempts           		*/
#define MAX_WINDOW   8	  /* max window size							 					*/

/*----- Packet types -----*/
#define EMPTY   -1
#define SYN      0        /* Opens a connection                          */
#define SYNACK   1        /* Acknowledgement of the SYN packet           */
#define DATA     2        /* Data packets                                */
#define DATAACK  3        /* Acknowledgement of the DATA packet          */
#define FIN      4        /* Ends a connection                           */
#define FINACK   5        /* Acknowledgement of the FIN packet           */
#define RST      6        /* Reset packet used to reject new connections */

/*----- Go-Back-n packet format -----*/
typedef struct {
	uint8_t  type;            /* packet type (e.g. SYN, DATA, ACK, FIN)     */
	uint8_t  seqnum;          /* sequence number of the packet              */
    uint16_t checksum;        /* header and payload checksum                */
	uint16_t data_len;        /* length of actually filled data				*/
    uint8_t data[DATALEN];    /* pointer to the payload                     */
} __attribute__((packed)) gbnhdr;

typedef struct state_t {
	/* Your state information could be encoded here. */
	int is_client;
	sockaddr remote;
	socklen_t socklen;	
	uint8_t state;
	uint8_t seqnum;
	size_t window_size;
	size_t total_bytes;
} state_t;

enum {
	CLOSED=0,
	LISTENING,  /* Server-only: listening to incoming connection attempts */
	SYN_WAIT,   /* Client: connection attempt started, waiting to send SYN
				   Server: accepting incoming connection attempt, waiting to receive SYN */
	SYN_SENT, 	/* Client: SYN sent, waiting to receive SYNACK */
	SYN_RCVD, 	/* Server: SYN received, waiting to send SYNACK */
	ESTABLISHED,
	FIN_SENT,
	FIN_RCVD
};

extern state_t s;

int gbn_connect(int sockfd, const sockaddr *server, socklen_t socklen);
int gbn_listen(int sockfd, int backlog);
int gbn_bind(int sockfd, const sockaddr *server, socklen_t socklen);
int gbn_socket(int domain, int type, int protocol);
int gbn_accept(int sockfd, sockaddr *addr, socklen_t *addrlen);
int gbn_close(int sockfd);
ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags);

ssize_t maybe_sendto(int s, const void *buf, size_t len, int flags, const sockaddr *to, socklen_t tolen);
ssize_t maybe_recvfrom(int s, void *buf, size_t len, int flags, sockaddr *from, socklen_t *fromlen);

uint16_t checksum(uint16_t *buf, int nwords);


#endif
