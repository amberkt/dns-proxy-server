#include <errno.h>
#include <stdio.h>

#define BUFF_LEN 			255
#define SERV_PORT 			53
#define MAX_CONNECT 		5
#define MAX_SYM 			80
#define MAX_BLOCK_ADDR 		1024
#define QTYPE_LEN 			2
#define QCLASS_LEN 			2


#define SERV_IP_TOKEN 		"upper_dns_server"
#define CONFIG_FILE_NAME 	"config"

#define ASSERT(x, code) if (!(x)) { \
			printf ("%s(), %d: assertion failed with errno = %d (%s) \n", __func__, __LINE__, errno, strerror(errno)); \
			return code; \
		}

char * query_data_to_str(const char * data, char * res_str, size_t sz);
void sig_handle (int sig); 
