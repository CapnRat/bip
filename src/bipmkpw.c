#include "config.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <fcntl.h>
#include <errno.h>
#include "util.h"
#include "md5.h"

int conf_log_level;
FILE *conf_global_log_file;
int conf_log;

void readpass(char *buffer, int buflen)
{
	int ttyfd = open("/dev/tty", O_RDWR);
	if (ttyfd == -1) {
		fprintf(stderr, "Unable to open tty: %s\n", strerror(errno));
		exit(1);
	}
	
	struct termios tt, ttback;
	memset(&ttback, 0, sizeof(ttback));
	if (tcgetattr(ttyfd, &ttback) < 0) {
		printf("tcgetattr failed: %s\n", strerror(errno));
		exit(1);
	}
	
	memcpy(&tt, &ttback, sizeof(ttback));
	tt.c_lflag &= ~(ICANON|ECHO);
	if (tcsetattr(ttyfd, TCSANOW, &tt) < 0) {
		printf("tcsetattr failed: %s\n", strerror(errno));
		exit(1);
	}
	
	write(ttyfd, "Password: ", 10);
	
	int idx = 0;
	while (idx < buflen) {
		read(ttyfd, buffer+idx, 1);
		if (buffer[idx] == '\n') {
			buffer[idx] = 0;
			break;
		}
		idx++;
	}
	
	write(ttyfd, "\n", 1);
	
	tcsetattr(ttyfd, TCSANOW, &ttback);
	close(ttyfd);
}

int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
	int i;
	static char str[256];
	unsigned char *md5;
	unsigned int seed;

	readpass(str, 256);

	// the time used to type the pass is entropy
	srand(time(NULL));
	seed = rand();
	
	md5 = chash_double(str, seed);
        for (i = 0; i < 20; i++)
		printf("%02x", md5[i]);
	printf("\n");
	free(md5);
	return 0;
}
