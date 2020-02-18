#include "gbn.h"

state_t s;

/* Static helper functions */
static uint8_t next(uint8_t seqnum) {
	return seqnum + 1;
}

static uint16_t checksum_packet(const gbnhdr *packet) {
	uint8_t buf[DATALEN + 2];
	buf[0] = packet->type;
	buf[1] = packet->seqnum;
	memcpy(buf + 2, packet->data, DATALEN);
	return checksum((uint16_t *)buf, sizeof(buf) / sizeof(uint16_t));
}

static int validate(const gbnhdr *packet) {
	return checksum_packet(packet) == packet->checksum;
}

static void timeout_handler(int signum) {}

static int send_syn(int sockfd) {
	s.seqnum = rand();
	gbnhdr pac = {SYN, s.seqnum,};
	pac.checksum = checksum_packet(&pac);

	if (maybe_sendto(sockfd, &pac, sizeof(pac), 0, &s.remote, s.socklen) == -1) {
		printf("ERROR: Unknown error sending SYN %d\n", s.seqnum);
		return -1;
	}

	printf("SYN %d successfully sent\n", s.seqnum);
	s.state = SYN_SENT;
	alarm(TIMEOUT);
	return 0;
}

static int recv_synack(int sockfd) {
	gbnhdr pac = {EMPTY,};

	if (maybe_recvfrom(sockfd, &pac, sizeof(pac), 0, &s.remote, &s.socklen) == -1) {
		if (errno == EINTR) {
			printf("WARN: Timeout waiting for SYNACK %d\n", next(s.seqnum));
			s.state = SYN_WAIT;
			errno = 0;
			return 0;
		} else {
			printf("ERROR: Unknown error receiving SYNACK %d\n", next(s.seqnum));
			return -1;
		}
	}

	if (!validate(&pac) || pac.type != SYNACK || pac.seqnum != next(s.seqnum)) {
		/* Expected SYNACK not received, maintain current state to keep waiting */
		return 0;
	}

	printf("SYNACK %d successfully received\n", next(s.seqnum));
	printf("Connection Established\n");
	s.state = ESTABLISHED;
	++s.seqnum;
	alarm(0);
	return 0;
}

static int recv_syn(int sockfd) {
	gbnhdr pac = {EMPTY,};

	if (maybe_recvfrom(sockfd, &pac, sizeof(pac), 0, &s.remote, &s.socklen) == -1) {
		printf("ERROR: Unknown error receiving SYN\n");
		return -1;
	}

	if (!validate(&pac) || pac.type != SYN) {
		/* SYN not received, maintain current state to keep waiting */
		return 0;
	}

	printf("SYN %d successfully received\n", pac.seqnum);
	s.state = SYN_RCVD;
	s.seqnum = pac.seqnum + 1;
	return 0;
}

static int send_synack(int sockfd) {
	gbnhdr pac = {SYNACK, s.seqnum,};
	pac.checksum = checksum_packet(&pac);

	if (maybe_sendto(sockfd, &pac, sizeof(pac), 0, &s.remote, s.socklen) == -1) {
		printf("ERROR: Unknown error sending SYNACK %d\n", s.seqnum);
		return -1;
	}

	printf("SYNACK %d successfully sent\n", s.seqnum);
	printf("Connection Established\n");
	s.state = ESTABLISHED;
	return 0;
}

static int send_fin(int sockfd) {
	gbnhdr pac = {FIN, s.seqnum,};
	pac.checksum = checksum_packet(&pac);

	if (maybe_sendto(sockfd, &pac, sizeof(pac), 0, &s.remote, s.socklen) == -1) {
		printf("ERROR: Unknown error sending FIN %d\n", s.seqnum);
		return -1;
	}

	printf("FIN %d successfully sent\n", s.seqnum);
	s.state = FIN_SENT;
	alarm(TIMEOUT);
	return 0;
}

static int recv_finack(int sockfd) {
	gbnhdr pac = {EMPTY,};

	if (maybe_recvfrom(sockfd, &pac, sizeof(pac), 0, &s.remote, &s.socklen) == -1) {
		if (errno == EINTR) {
			printf("WARN: Timeout waiting for FINACK %d\n", next(s.seqnum));
			s.state = ESTABLISHED;
			errno = 0;
			return 0;
		} else {
			printf("ERROR: Unknown error receiving SYNACK %d\n", next(s.seqnum));
			return -1;
		}
	}

	if (!validate(&pac) || pac.type != FINACK || pac.seqnum != next(s.seqnum)) {
		/* Expected FINACK not received, maintain current state to keep waiting */
		return 0;
	}

	printf("FINACK %d successfully received\n", next(s.seqnum));
	s.state = CLOSED;
	alarm(0);
	return 0;
}

static size_t make_window(gbnhdr* window, const void *buf, size_t len, int offset) {
	size_t n = 0;
	for (; n < s.window_size && offset < len; ++n) {
		gbnhdr *pac = &window[n];

		pac->seqnum = s.seqnum + n;
		pac->data_len = MIN(DATALEN, len - offset);
		memcpy(pac->data, buf + offset, pac->data_len);
		pac->checksum = checksum_packet(pac);

		offset += pac->data_len;
	}

	return n;
}

static int send_window(int sockfd, const gbnhdr *window, size_t n) {
	size_t i;
	for (i = 0; i < n; ++i) {
		const gbnhdr *pac = &window[i];

		if (maybe_sendto(sockfd, pac, sizeof(*pac), 0, &s.remote, s.socklen) == -1) {
			printf("ERROR: Unknown error sending packet %d", pac->seqnum);
			return -1;
		}
	}

	alarm(TIMEOUT);
	return n;
}

static int recv_window_ack(int sockfd, size_t n, size_t *offset) {
	int n_ack = 0;
	gbnhdr pac = {EMPTY,};

	while (n_ack < n) {
		if (maybe_recvfrom(sockfd, &pac, sizeof(pac), 0, &s.remote, &s.socklen) == -1) {
			if (errno == EINTR) {
				printf("WARN: Timeout waiting for ACK %d\n", next(s.seqnum));
				return n_ack;
			} else {
				printf("ERROR: Unknown error receiving ACK\n");
				return -1;
			}
		}

		if (!validate(&pac) || pac.type != DATAACK || pac.seqnum != next(s.seqnum)) continue;

		++n_ack;
		++s.seqnum;
		*offset += pac.data_len;
	}

	alarm(0);
	return n_ack;
}

static void speed_up() {
	if (s.window_size * 2 <= MAX_WINDOW) {
		s.window_size *= 2;
	}
}

static void slow_down() {
	if (s.window_size / 2 > 0) {
		s.window_size /= 2;
	}
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
	/* Your code here. */

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */

	gbnhdr window[MAX_WINDOW];
	size_t i;
	for (i = 0; i < MAX_WINDOW; ++i) {
		window[i].type = DATA;
	}

	s.window_size = 1;
	size_t offset = 0;

	while (offset < len) {
		size_t n = make_window(window, buf, len, offset);

		if (send_window(sockfd, window, n) == -1) return -1;

		int n_ack = recv_window_ack(sockfd, n, &offset);
		if (n_ack == -1) return -1;
		if (n_ack == n) {
			speed_up();
		} else {
			slow_down();
		}
	}

	return len;
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags) {
	/* Your code here. */
	gbnhdr pac = {EMPTY,};
	gbnhdr ack_pac = {DATAACK,};

	int received = FALSE;
	while (!received) {
		if (maybe_recvfrom(sockfd, &pac, sizeof(pac), 0, &s.remote, &s.socklen) == -1) {
			printf("ERROR: Unknown error receiving packet\n");
			return -1;
		}

		if (!validate(&pac)) continue;

		if (pac.type == FIN && pac.seqnum == s.seqnum) {
			s.state = FIN_RCVD;
			break;
		}

		if (pac.type != DATA) continue;

		if (pac.seqnum == s.seqnum) {
			printf("Packet %d received\n", s.seqnum);
			received = TRUE;
			++s.seqnum;
		}

		ack_pac.seqnum = s.seqnum;
		ack_pac.data_len = pac.data_len;
		ack_pac.checksum = checksum_packet(&ack_pac);
		if (maybe_sendto(sockfd, &ack_pac, sizeof(ack_pac), 0, &s.remote, s.socklen) == -1) {
			printf("ERROR: Unknown error sending ACK %d\n", s.seqnum);
			return -1;
		}
	}

	if (s.state == FIN_RCVD) {
		++s.seqnum;
		gbnhdr finack_pac = {FINACK, s.seqnum};
		finack_pac.checksum = checksum_packet(&finack_pac);

		if (maybe_sendto(sockfd, &finack_pac, sizeof(finack_pac), 0, &s.remote, s.socklen) == -1) {
			printf("ERROR: Unknown error sending FINACK %d\n", s.seqnum);
			return -1;
		}

		return 0;
	}

	memcpy(buf, pac.data, pac.data_len);
	return pac.data_len;
}

int gbn_close(int sockfd) {
	/* Your code here. */
	if (s.is_client) {
		int attempts = 0;

		while (s.state != CLOSED) {
			switch (s.state) {
				case ESTABLISHED: {
					if (++attempts > MAX_CONN) {
						printf("ERROR: Exceeded maximum number of disconnection attempts\n");
						return -1;
					};

					if (send_fin(sockfd) == -1) return -1;
					break;
				}
				case FIN_SENT: {
					if (recv_finack(sockfd) == -1) return -1;
					break;
				}
				default: {
					return -1;
				}
			}
		}
	}

	printf("Connection closed\n");
	s.state = CLOSED;
	return close(sockfd);
}

int gbn_connect(int sockfd, const sockaddr *server, socklen_t socklen) {
	/* Your code here. */
	printf("Attempting to connect...\n");
	s.is_client = TRUE;
	s.remote = *server;
	s.socklen = socklen;
	s.state = SYN_WAIT;
	int attempts = 0;

	while (s.state != ESTABLISHED) {
		switch (s.state) {
			case SYN_WAIT: {
				if (++attempts > MAX_CONN) {
					printf("ERROR: Exceeded maximum number of connection attempts\n");
					return -1;
				};

				if (send_syn(sockfd) == -1) return -1;
				break;
			}
			case SYN_SENT: {
				if (recv_synack(sockfd) == -1) return -1;
				break;
			}
			default: {
				return -1;
			}
		}
	}
	
	return 0;
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

	s.state = CLOSED;

	return socket(domain, type, protocol);
}

int gbn_accept(int sockfd, sockaddr *client, socklen_t *socklen) {
	/* Your code here. */
	if (s.state != LISTENING) return -1;

	printf("Accepting incoming connection...\n");
	s.is_client = FALSE;
	s.socklen = sizeof(s.remote);
	s.state = SYN_WAIT;

	while (s.state != ESTABLISHED) {
		switch (s.state) {
			case SYN_WAIT: {
				if (recv_syn(sockfd) == -1) return -1;
				break;
			}
			case SYN_RCVD: {
				if (send_synack(sockfd) == -1) return -1;
				break;
			}
			default: {
				return -1;
			}
		}
	}
	
	return sockfd;
}

ssize_t maybe_recvfrom(int s, void *buf, size_t len, int flags, sockaddr *from, socklen_t *fromlen) {
	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB*RAND_MAX) {

		/*----- Receiving the packet -----*/
		int retval = recvfrom(s, buf, len, flags, from, fromlen);
		char *buffer = (char *)buf;

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