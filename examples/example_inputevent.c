/*
 * 2020 André Kovács <info@kovacsandre.com>
 *
 * This example requires at least one line in the gpiodaemon config with
 * direction=in and edge=rising | falling | both keywords to work.
 * This means the corresponding GPIO line has interrupt capabilities.
 *
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <gpiod.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>

volatile sig_atomic_t exit_flag = 0;

static void exit_program(int s)
{
	exit_flag = 1;
}

static void find_event(char *data, char *pin, int *value)
{
	char *lineptr, *arri;

	lineptr = data;

	while (*lineptr && *lineptr != '\n') {
		if (*lineptr == '(')
			arri = lineptr + 1;
		else if (*lineptr == ')') {
			*lineptr = '\0';
			strcpy(pin, arri);
		}
		else if (*lineptr == ':') {
			if (!strcmp(lineptr, ":rising\n")) {
				*value = 1;
			}
			else {
				*value = 0;
			}
		}

		lineptr++;
	}
}

int main(int argc, char const *argv[])
{
	int s;
	struct sockaddr_un remote;
	struct sigaction sa_exit;
	struct pollfd pfd;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <socket path>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	sa_exit.sa_handler = exit_program;
	sa_exit.sa_flags = 0;
	sigemptyset(&sa_exit.sa_mask);
	if (sigaction(SIGINT, &sa_exit, NULL) < 0) {
		perror("sigaction()");
		exit(EXIT_FAILURE);
	}

	exit_flag = 0;

	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	remote.sun_family = AF_UNIX;
	strcpy(remote.sun_path, argv[1]);
	int len = strlen(remote.sun_path) + sizeof(remote.sun_family);
	if (connect(s, (struct sockaddr *)&remote, len) == -1) {
		perror("connect");
		goto end;
	}

	pfd.fd = s;
	pfd.events = POLLIN;

	while (!exit_flag) {
		int rv = poll(&pfd, 1, -1);

		if(rv < 0) {
			if (errno != EINTR)
				perror("poll");
			exit_flag = 1;
			continue;
		}

		if (pfd.revents) {
			char buffer[1024], pin[32];
			int value;

			int t = recv(pfd.fd, buffer, sizeof(buffer)-1, 0);

			if (t > 0) {
				find_event(buffer, pin, &value);
				printf("Pin \"%s\" changed to %d\n", pin, value);
			}
			else if (t == 0) {
				fprintf(stderr, "GPIOdaemon closed connection\n");
				exit_flag = 1;
			}
			else {
				perror("recv");
				exit_flag = 1;
			}
		}
	}

end:
	close(s);

	return 0;
}
