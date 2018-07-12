#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include "functions.h"

char * query_data_to_str(const char * data, char * res_str, size_t sz) {

	int i = 0;
	int bytes_written = 0;

	if (!data || !res_str)
		return NULL;

	while (data[i] != 0) {
		if (data[i] <= 63) { /* each label should be up to 63 octets */
			bytes_written += snprintf(res_str + bytes_written, sz - bytes_written, "%.*s.", data[i], data + i + 1);

			i += (data[i] + 1);
		} else {
			printf("Malformed DNS packet - ignore..\n");
			return NULL;
		}
	}

	res_str[strlen(res_str) - 1] = 0;
	return (char *)data + bytes_written + QTYPE_LEN + QCLASS_LEN;
}

void sig_handle (int sig) {
	printf ("[ Debug ]: Exiting the program.. \n");
	exit(EXIT_SUCCESS);
}
