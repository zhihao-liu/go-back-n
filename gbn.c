#include "gbn.h"

state_t s;

/* Static helper functions */
static uint16_t checksum_packet(const gbnhdr *packet) {
	uint8_t buf[DATALEN + 2];
	buf[0] = packet->type;
	buf[1] = packet->seqnum;
	memcpy(buf + 2, packet->data, DATALEN);
	return checksum((uint16_t *)buf, sizeof(buf) / sizeof(uint16_t));
}

static bool validate(const gbnhdr *packet) {
	return checksum_packet(packet) == packet->checksum;
}

static void timeout_handler(int signum) {}

static void send_syn(int sockfd, const sockaddr *server, socklen_t socklen) {
	s.seqnum = rand();
	gbnhdr pac = {SYN, s.seqnum,};
	pac.checksum = checksum_packet(&pac);

	if (maybe_sendto(sockfd, &pac, sizeof(pac), 0, server, socklen) == -1) {
		printf("ERROR: Unknown error sending SYN %d\n", s.seqnum);
		s.state = CLOSED;
		return;
	}

	printf("SYN %d successfully sent\n", s.seqnum);
	s.state = SYN_SENT;
	alarm(TIMEOUT);
}

static void recv_synack(int sockfd) {
	gbnhdr pac = {EMPTY,};
	sockaddr server;
	socklen_t socklen = sizeof(server);

	if (maybe_recvfrom(sockfd, (char *)&pac, sizeof(pac), 0, &server, &socklen) == -1) {
		if (errno == EINTR) {
			printf("WARN: Timeout waiting for SYNACK %d\n", s.seqnum + 1);
			s.state = SYN_WAIT;
			errno = 0;
		} else {
			printf("ERROR: Unknown error receiving SYNACK %d\n", s.seqnum + 1);
			s.state = CLOSED;
		}
		return;
	}

	if (!validate(&pac) || pac.type != SYNACK || pac.seqnum != s.seqnum + 1) {
		if (!validate(&pac)) printf("CORRUPT");
		printf("%d", pac.type);
		printf("%d", pac.seqnum);
		/* Expected SYNACK not received, maintain current state to retry */
		return;
	}

	printf("SYNACK %d successfully received\n", s.seqnum + 1);
	printf("Connection Established\n");
	s.state = ESTABLISHED;
	++s.seqnum;
	alarm(0);
}

static void recv_syn(int sockfd, sockaddr *client, socklen_t *socklen) {
	gbnhdr pac = {EMPTY,};

	if (maybe_recvfrom(sockfd, (char *)&pac, sizeof(pac), 0, client, socklen) == -1) {
		printf("ERROR: Unknown error receiving SYN\n");
		s.state = CLOSED;
		return;
	}

	if (!validate(&pac) || pac.type != SYN) {
		/* SYN not received, maintain current state to keep waiting */
		return;
	}

	printf("SYN %d successfully received\n", pac.seqnum);
	s.state = SYN_RCVD;
	s.seqnum = pac.seqnum + 1;
}

static void send_synack(int sockfd, const sockaddr *client, socklen_t socklen) {
	gbnhdr pac = {SYNACK, s.seqnum, };
	pac.checksum = checksum_packet(&pac);

	if (maybe_sendto(sockfd, &pac, sizeof(pac), 0, client, socklen) == -1) {
		printf("ERROR: Unknown error sending SYNACK %d\n", s.seqnum);
		s.state = CLOSED;
		return;
	}

	printf("SYNACK %d successfully sent\n", s.seqnum);
	printf("Connection Established\n");
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
	printf("Attempting to connect...\n");
	s.state = SYN_WAIT;
	int attempts = 0;

	while (s.state != CLOSED && s.state != ESTABLISHED) {
		switch (s.state) {
			case SYN_WAIT: {
				if (++attempts > MAX_CONN) {
					printf("ERROR: Exceeded maximum number of connection attempts\n");
					s.state = CLOSED;
					break;
				};

				send_syn(sockfd, server, socklen);
				break;
			}
			case SYN_SENT: {
				recv_synack(sockfd);
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
	printf("Listening for incoming connection attempts...\n");
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

	printf("Accepting incoming connection...\n");
	s.state = SYN_WAIT;

	while (s.state != CLOSED && s.state != ESTABLISHED) {
		switch (s.state) {
			case SYN_WAIT: {
				recv_syn(sockfd, client, socklen);
				break;
			}
			case SYN_RCVD: {
				send_synack(sockfd, client, *socklen);
				break;
			}
			default: {
				return -1;
			}
		}
	}
	
	return (s.state == ESTABLISHED ? sockfd : -1);
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
