#include "gbn.h"

state_t s;

/* Static helper functions */
static int validate(gbnhdr *packet) {
	uint16_t *buf = (uint16_t *) packet->data;
	uint16_t cs = checksum(buf, sizeof(*buf) / sizeof(uint16_t));
	return cs == packet->checksum;
}

static void timeout_handler(int signum) {}

static void send_syn(int sockfd, const gbnhdr *syn_pac, const sockaddr *to, socklen_t tolen) {
	if (maybe_sendto(sockfd, syn_pac, sizeof(*syn_pac), 0, to, tolen) == -1) {
		printf("ERROR: Failed to send SYN");
		s.state = CLOSED;
		return;
	}

	printf("INFO: SYN successfully sent");
	s.state = SYN_SENT;
}

static void receive_synack(int sockfd, gbnhdr *synack_pac) {
	sockaddr from;
	socklen_t fromlen = sizeof(from);

	alarm(TIMEOUT);
	if (maybe_recvfrom(sockfd, (char *)synack_pac, sizeof(*synack_pac), 0, &from, &fromlen) == -1) {
		if (errno == EINTR) {
			printf("WARN: Timeout waiting for SYNACK");
			s.state = CONNECTING;
			errno = 0;
		} else {
			printf("ERROR: Failed to receive SYNACK");
			s.state = CLOSED;
		}
		return;
	}

	if (synack_pac->type != SYNACK) {
		printf("WARN: SYNACK not received");
		s.state = CONNECTING;
		return;
	}

	printf("INFO: SYNACK successfully received");
	s.state = SYN_RCVD;
	alarm(0);
}

static void send_synack(int sockfd, const gbnhdr *synack_pac, const sockaddr *to, socklen_t tolen) {
	if (maybe_sendto(sockfd, synack_pac, sizeof(*synack_pac), 0, to, tolen) == -1) {
		printf("ERROR: Failed to send SYNACK");
		s.state = CLOSED;
		return;
	}

	printf("INFO: SYNACK successfully sent. Connection established");
	s.state = ESTABLISHED;
}

/* Implemented interfaces */
uint16_t checksum(uint16_t *buf, int nwords) {
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags) {
	
	/* TODO: Your code here. */

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */

	return(-1);
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags) {

	/* TODO: Your code here. */

	return(-1);
}

int gbn_close(int sockfd) {

	/* TODO: Your code here. */
	return close(sockfd);
}

int gbn_connect(int sockfd, const sockaddr *server, socklen_t socklen) {
	/* Your code here. */
	gbnhdr syn_pac = {SYN,}; /* SYN to be sent out */
	gbnhdr synack_pac = {EMPTY,}; /* packet to store the received SYNACK and then to be sent out as the final SYNACK */

	printf("INFO: Begin connection attempt...");
	s.state = CONNECTING;
	int attempts = 0;

	while (attempts++ < MAX_ATTEMPTS && s.state != CLOSED && s.state != ESTABLISHED) {
		switch (s.state) {
			case CONNECTING: {
				send_syn(sockfd, &syn_pac, server, socklen);
				break;
			}
			case SYN_SENT: {
				receive_synack(sockfd, &synack_pac);
				break;
			}
			case SYN_RCVD: {
				send_synack(sockfd, &synack_pac, server, socklen);
				break;
			}
		}
	}
	
	return (s.state == ESTABLISHED ? 0 : -1);
}

int gbn_listen(int sockfd, int backlog) {
	/* Your code here. */
	s.state = LISTENING;
	return 0;
}

int gbn_bind(int sockfd, const sockaddr *server, socklen_t socklen) {
	/* Your code here. */
	return bind(sockfd, server, socklen);
}

int gbn_socket(int domain, int type, int protocol) {	
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));
	
	/* Your code here. */
	signal(SIGALRM, timeout_handler);
    siginterrupt(SIGALRM, 1);

	return socket(domain, type, protocol);
}

int gbn_accept(int sockfd, sockaddr *client, socklen_t *socklen) {

	/* TODO: Your code here. */

	return(-1);
}

ssize_t maybe_recvfrom(int s, char *buf, size_t len, int flags, sockaddr *from, socklen_t *fromlen) {

	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB*RAND_MAX) {


		/*----- Receiving the packet -----*/
		int retval = recvfrom(s, buf, len, flags, from, fromlen);

		/*----- Packet corrupted -----*/
		if (rand() < CORR_PROB*RAND_MAX) {
			/*----- Selecting a random byte inside the packet -----*/
			int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

			/*----- Inverting a bit -----*/
			char c = buf[index];
			if (c & 0x01)
				c &= 0xFE;
			else
				c |= 0x01;
			buf[index] = c;
		}

		return retval;
	}
	/*----- Packet lost -----*/
	return(len);  /* Simulate a success */
}

ssize_t maybe_sendto(int s, const void *buf, size_t len, int flags, const sockaddr *to, socklen_t tolen) {

    char *buffer = malloc(len);
    memcpy(buffer, buf, len);
    
    
    /*----- Packet not lost -----*/
    if (rand() > LOSS_PROB*RAND_MAX) {
        /*----- Packet corrupted -----*/
        if (rand() < CORR_PROB*RAND_MAX) {
            
            /*----- Selecting a random byte inside the packet -----*/
            int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

            /*----- Inverting a bit -----*/
            char c = buffer[index];
            if (c & 0x01)
                c &= 0xFE;
            else
                c |= 0x01;
            buffer[index] = c;
        }

        /*----- Sending the packet -----*/
        int retval = sendto(s, buffer, len, flags, to, tolen);
        free(buffer);
        return retval;
    }
    /*----- Packet lost -----*/
    else
        return(len);  /* Simulate a success */
}
