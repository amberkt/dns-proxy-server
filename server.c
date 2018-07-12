#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "functions.h"


/********************************************************************************
 * @check_query_data ()
 *	Returns pointer to the next query and stores domain name to res_str variable
 *******************************************************************************/

int main () {

	int sock = -1;
	int res = 0;
	FILE * config_fd;

	fd_set rfds;
	char str_buff[BUFF_LEN] = {0};
	char ip_upper_serv[BUFF_LEN];
	char block_list_arr[MAX_BLOCK_ADDR][255] = {0};
	int block_list_count = 0;
	int serv_rsp;
	struct timeval tv;
	struct dns_header * dns_pack;
	struct sigaction sigact;
	struct sockaddr_in socket_data;		
	struct sockaddr_in upper_ip_addr_info;

	struct dns_header {
		uint16_t identification;
		uint16_t flags;
		uint16_t quest_num;
		uint16_t num_ans;			
		uint16_t num_of_auth;
		uint16_t num_of_add;
		char data[];
	}__attribute__((packed));

	struct client_id {
		struct in_addr ip_addr_client;
		unsigned int t_id;
		unsigned short port;
		unsigned char field_valid;
	};

	#define MAX_TID_VALUES 64

	struct client_id client_table [MAX_TID_VALUES];


	upper_ip_addr_info.sin_family = AF_INET;
	upper_ip_addr_info.sin_port = htons(SERV_PORT);

	if ((config_fd = fopen (CONFIG_FILE_NAME, "r")) != NULL) {
		while (!feof(config_fd)) {
			fgets (str_buff, BUFF_LEN, config_fd);
			if (sscanf(str_buff, "upper_dns_server %s", ip_upper_serv) != 0) {
				upper_ip_addr_info.sin_addr.s_addr = inet_addr(ip_upper_serv);
				printf ("[ Debug ]: Upper DNS server -> %s\n", ip_upper_serv);
			} else if (sscanf (str_buff, "serv_rsp %d", &serv_rsp) != 0) {
				printf ("[ Debug ]: DNS response -> %d\n", serv_rsp);
			} else if (sscanf (str_buff, "block_list %s", block_list_arr[block_list_count]) != 0 ) {
				printf ("[ Debug ]: Block list entry -> %s\n", block_list_arr[block_list_count]);
				if (block_list_count != (MAX_BLOCK_ADDR - 1))
					block_list_count++;
				else {
					printf("[ Debug ]: Max block entries count exceeded, replacing the latest one..\n");
				}
			}
		}
		fclose (config_fd);
	} else {
		printf("[ Debug ]: Error while opening config file (%s)\n", CONFIG_FILE_NAME);
		return 1;
	}

	if ((sock = socket (AF_INET, SOCK_DGRAM, 0u)) == -1) {
		printf ("[ Debug ]: Error creating socket!  Errno = %d (%s) \n", errno, strerror(errno));
		return 1;
	}
		
	memset (&socket_data, 0, sizeof(socket_data));

	socket_data.sin_family = AF_INET;
	socket_data.sin_port = htons(SERV_PORT);
	socket_data.sin_addr.s_addr = htonl(INADDR_ANY); 

	if ((bind (sock, (struct sockaddr *) &socket_data, sizeof(socket_data)) == -1)) {
		printf ("[ Debug ]: Bind error!  Errno = %d (%s) \n", errno, strerror(errno));
		close(sock);
		return 1;
	}

	sigact.sa_handler = sig_handle; 
	sigaction(SIGINT, &sigact, 0);

	while (1) {

		FD_ZERO (&rfds);
		FD_SET (sock, &rfds);

		tv.tv_sec = 5;
		tv.tv_usec = 0;

		if ((res = select (sock + 1, &rfds, NULL, NULL, &tv)) == -1) {
			printf ("[ Debug ]: Select() error!  Errno = %d (%s) \n", errno, strerror(errno));
			close(sock);
			return 1;
		} else if (res > 0) {
			if (FD_ISSET(sock, &rfds)) {

				int qdcount = 0;
				int i = 0;
				int j = 0;
				static unsigned char client_counter = 1;
				char * res = NULL;
				char buff[1024];
				struct sockaddr_in client_info; /* client addr */
				unsigned int clientlen = sizeof(client_info);
				int num_received = 0;

				if ((num_received = recvfrom(sock, buff, sizeof(buff), 0, (struct sockaddr *) &client_info, &clientlen)) == 0) 
					continue;

				dns_pack = (struct dns_header *) buff;	

				if (!(ntohs(dns_pack->flags) & (1 << 15))) {

					char res_query[256] = {0};

					for (j = 0; j < MAX_TID_VALUES; j++) {
						if (!client_table[j].field_valid)
							break;
					}

					memcpy (&client_table[j].ip_addr_client, &client_info.sin_addr, sizeof(client_info.sin_addr));
					client_table[j].t_id = ntohs(dns_pack->identification);
					client_table[j].port = ntohs(client_info.sin_port);
					client_table[j].field_valid = 1;

					client_counter = 0;
					for (int k = 0; k <  MAX_TID_VALUES; k++) {
						if (client_table[k].field_valid) {
							client_counter++;
						}
					}

					char * query_ptr = query_data_to_str (dns_pack->data, res_query, sizeof(res_query));
					printf("[ Debug ]: DNS packet received --> qdcount = %hu, res_query = %s\n", ntohs(dns_pack->quest_num), res_query);

					for (qdcount = 0; qdcount < ntohs(dns_pack->quest_num) - 1; qdcount++) {
						query_ptr = query_data_to_str (query_ptr, res_query, sizeof(res_query));
						printf("[ Debug ]: res_query = %s\n", res_query);
					}

					for (i = 0; i < block_list_count; i++) {					
						if ((res = strstr (block_list_arr[i], res_query)) != NULL) {
							char reply_code = (char) serv_rsp;
							reply_code &= 0x0F;				/* leave only four bits */
							dns_pack->flags = 1 << 15;  	/* this is reply */
							dns_pack->flags |= reply_code; 	/* apply mask */
							dns_pack->flags = htons(dns_pack->flags);
							dns_pack->quest_num = htons(0);
							dns_pack->num_ans = htons(1);
							if (sendto (sock, dns_pack, sizeof(struct dns_header), 0, (struct sockaddr *) &client_info, sizeof(client_info)) == -1)
								printf ("[ Debug ]: Error on send!  Errno = %d (%s) \n", errno, strerror(errno));
							break;
						}	
					}

					if (!res) {
						printf("[ Debug ]: Forwarding to upper DNS server\n");
						sendto(sock, buff, num_received, 0, (struct sockaddr *) &upper_ip_addr_info, sizeof(upper_ip_addr_info));
					}
				} else if ((ntohs(dns_pack->flags) & (1 << 15))) {
					int i = 0;
					for (i = 0; i < MAX_TID_VALUES; i++) {
						if (client_table[i].t_id == ntohs(dns_pack->identification)) {
							client_info.sin_addr = client_table[i].ip_addr_client;
							client_info.sin_port = htons(client_table[i].port);
							sendto(sock, buff, num_received, 0, (struct sockaddr *) &client_info, sizeof(client_info));
							memset (&client_table[i], 0, sizeof(client_table[i]));
							break;
						}
					}
				}
			} 
		}

	}

	close(sock);

	return 0;
}
