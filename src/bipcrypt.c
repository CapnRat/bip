/*
 * $Id$
 *
 * Copyright (C) 2013 Andreia Gaita <shana@spoiledcat.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * See the file "COPYING" for the exact licensing terms.
 */

#include "config.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <fcntl.h>
#include <errno.h>
#include "util.h"
#include "crypt.h"

int conf_log_level;
FILE *conf_global_log_file;
int conf_log_system;

void readpass(char* message, char *buffer, int buflen)
{
	int ttyfd = open("/dev/tty", O_RDWR);
	if (ttyfd == -1) {
		fprintf(stderr, "Unable to open tty: %s\n", strerror(errno));
		exit(1);
	}

	struct termios tt, ttback;
	memset(&ttback, 0, sizeof(ttback));
	if (tcgetattr(ttyfd, &ttback) < 0) {
		fprintf(stderr, "tcgetattr failed: %s\n", strerror(errno));
		exit(1);
	}

	memcpy(&tt, &ttback, sizeof(ttback));
	tt.c_lflag &= ~(ICANON|ECHO);
	if (tcsetattr(ttyfd, TCSANOW, &tt) < 0) {
		fprintf(stderr, "tcsetattr failed: %s\n", strerror(errno));
		exit(1);
	}

	write(ttyfd, message, strlen(message));

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

int main(int argc, char **argv)
{
	int i, j, len, ch;
	static char strkey[256];
	static char strpass[256];
	static char str[256];
	unsigned char* ret;
	unsigned char* salt = NULL;

	readpass("Key: ", strkey, 256);
	strkey[255] = 0;

	aes_init (strkey, salt);

	readpass("Password: ", strpass, 256);
	strpass[255] = 0;

	len = strlen(strpass);

	ret = aes_encrypt(strpass, &len);
	for (i = 0; i < strlen(ret); i++)
		printf ("%02x", ret[i]);
	printf("\n");

	return 0;
}
