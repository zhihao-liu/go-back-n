#include "gbn.h"

state_t s;

/* Static helper functions */
static int validate(gbnhdr *packet) {
	uint16_t *buf = (uint16_t *) packet->data;
	uint16_t cs = checksum(buf, sizeof(*buf) / sizeof(uint16_t));
	return cs == packet->checksum;
}

static void timeout_handler(int signum) {}

static void send_syn(int sockfd, const gbnhdr *syn_pac, const sockaddr *server, socklen_t socklen) {
	if (maybe_sendto(sockfd, syn_pac, sizeof(*syn_pac), 0, server, socklen) == -1) {
		printf("ERROR: Failed to send SYN");
		s.state = CLOSED;
		return;
	}

	printf("INFO: SYN successfully sent");
	s.state = SYN_SENT;
}

static void receive_syn(int sockfd, gbnhdr *syn_pac, sockaddr *client, socklen_t *socklen) {
	if (maybe_recvfrom(sockfd, (char *)syn_pac, sizeof(*syn_pac), 0, client, socklen) == -1) {
		printf("ERROR: Failed to receive SYN");
		s.state = CLOSED;
		return;
	}

	if (syn_pac->type != SYN) {
		printf("WARN: SYN not received");
		return;
	}

	printf("INFO: SYN successfully received");
	s.state = SYN_RCVD;
}

static void send_synack(int sockfd, const gbnhdr *synack_pac, const sockaddr *client, socklen_t socklen) {
	if (maybe_sendto(sockfd, synack_pac, sizeof(*synack_pac), 0, client, socklen) == -1) {
		printf("ERROR: Failed to send SYNACK");
		s.state = CLOSED;
		return;
	}

	printf("INFO: SYNACK successfully sent");
	s.state = SYN_SENT;
}

static void receive_synack(int sockfd, gbnhdr *synack_pac) {
	sockaddr server;
	socklen_t socklen = sizeof(server);

	alarm(TIMEOUT);
	if (maybe_recvfrom(sockfd, (char *)synack_pac, sizeof(*synack_pac), 0, &server, &socklen) == -1) {
		if (errno == EINTR) {
			printf("WARN: Timeout waiting for SYNACK");
			s.state = SYN_WAIT;
			errno = 0;
		} else {
			printf("ERROR: Failed to receive SYNACK");
			s.state = CLOSED;
		}
		return;
	}

	if (synack_pac->type != SYNACK) {
		printf("WARN: SYNACK not received");
		s.state = SYN_WAIT;
		return;
	}

	printf("INFO: SYNACK successfully received");
	s.state = SYN_RCVD;
	alarm(0);
}

static void send_echo_synack(int sockfd, const gbnhdr *synack_pac, const sockaddr *server, socklen_t socklen) {
	if (maybe_sendto(sockfd, synack_pac, sizeof(*synack_pac), 0, server, socklen) == -1) {
		printf("ERROR: Failed to send echo SYNACK");
		s.state = CLOSED;
		return;
	}

	printf("INFO: Echo SYNACK successfully sent. Connection established");
	s.state = ESTABLISHED;
}

static void receive_echo_synack(int sockfd, gbnhdr *synack_pac) {
	sockaddr client;
	socklen_t socklen = sizeof(client);

	alarm(TIMEOUT);
	if (maybe_recvfrom(sockfd, (char *)synack_pac, sizeof(*synack_pac), 0, &client, &socklen) == -1) {
		if (errno == EINTR) {
			printf("WARN: Timeout waiting for echo SYNACK");
			s.state = SYN_RCVD;
			errno = 0;
		} else {
			printf("ERROR: Failed to receive echo SYNACK");
			s.state = CLOSED;
		}
		return;
	}

	if (synack_pac->type != SYNACK) {
		printf("WARN: Echo SYNACK not received");
		s.state = SYN_RCVD;
		return;
	}

	printf("INFO: Echo SYNACK successfully received. Connection establishe");
	s.state = ESTABLISHED;
	alarm(0);
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
	gbnhdr synack_pac = {EMPTY,}; /* packet to store the received SYNACK */
	gbnhdr echo_pac = {SYNACK,}; /* Echo SYNACK to be sent back */

	printf("INFO: Begin connection attempt...");
	s.state = SYN_WAIT;
	int attempts = 0;

	while (s.state != CLOSED && s.state != ESTABLISHED) {
		switch (s.state) {
			case SYN_WAIT: {
				if (++attempts > MAX_ATTEMPTS) {
					printf("ERROR: Exceeded maximum number of attempts to resend SYN");
					s.state = CLOSED;
					break;
				};

				send_syn(sockfd, &syn_pac, server, socklen);
				break;
			}
			case SYN_SENT: {
				receive_synack(sockfd, &synack_pac);
				break;
			}
			case SYN_RCVD: {
				send_echo_synack(sockfd, &echo_pac, server, socklen);
				break;
			}
			default: {
				return -1;
			}
		}
	}
	
	return (s.state == ESTABLISHED ? 0 : -1);
}

int gbn_listen(int sockfd, int backlog) {
	/* Your code here. */
	printf("INFO: Listening for incoming connection attempts...");
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
	/* Your code here. */
	if (s.state != LISTENING) return -1;

	gbnhdr syn_pac = {EMPTY,}; /* packet to store the received SYN */
	gbnhdr synack_pac = {SYNACK,}; /* SYNACK to be sent back */
	gbnhdr echo_pac = {EMPTY,}; /* packet to store the received echo SYNACK */

	printf("INFO: Accepting incoming connection...");
	s.state = SYN_WAIT;
	int attempts = 0;

	while (s.state != CLOSED && s.state != ESTABLISHED) {
		switch (s.state) {
			case SYN_WAIT: {
				receive_syn(sockfd, &syn_pac, client, socklen);
				break;
			}
			case SYN_RCVD: {
				if (++attempts > MAX_ATTEMPTS) {
					printf("ERROR: Exceeded maximum number of attempts to resend SYNACK");
					s.state = CLOSED;
					break;
				};

				send_synack(sockfd, &synack_pac, client, *socklen);
				break;
			}
			case SYN_SENT: {
				receive_echo_synack(sockfd, &echo_pac);
				break;
			}
			default: {
				return -1;
			}
		}
	}
	
	return (s.state == ESTABLISHED ? 0 : -1);
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
