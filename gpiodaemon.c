/*
 * 2019- André Kovács <info@kovacsandre.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <gpiod.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <limits.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>

#define DEFAULT_SOCKET "/var/run/gpiodaemon.sock"
#define DEFAULT_CONFIG "/usr/local/etc/gpiodaemon"
#define MAX_FDS 100
#define MAX_LINES GPIOD_LINE_BULK_MAX_LINES
#define MAX_CHIP 8

#define CONSUMER_MAX 32

volatile sig_atomic_t exit_flag = 0;

struct gpio_chip {
	struct gpiod_chip *gpiochip[MAX_CHIP];
	int chip_num;
};

static const char *const shortopts = "+hdc:s:";
static const struct option longopts[] = {
	{ "help",			no_argument,		NULL,	'h' },
	{ "debug",			no_argument,		NULL,	'd' },
	{ "config",			required_argument,	NULL,	'c' },
	{ "socket",			required_argument,	NULL,	's' },
	{ 0, 				0, 					0, 		0 	}
};

void print_help(const char *name)
{
	printf("Usage: %s [OPTIONS]\n", name);
	printf("\n");
	printf("Options:\n");
	printf("  -h, --help\t\tdisplay this message and exit\n");
	printf("  -d, --debug\t\tprint debug messages\n");
	printf("  -c, --config\t\tconfiguraton file path [/usr/local/etc/gpiodaemon]\n");
	printf("  -s, --socket\t\tsocket path [/var/run/gpiodaemon.sock]\n");

	exit(EXIT_SUCCESS);
}

void exit_program(int s)
{
	exit_flag = 1;
}

static int match_keyword(char *kw, char *opt,
						 char *consumer, int *val,
						 struct gpiod_line_request_config *line)
{
	int rv = 0;

	if (!strcmp(kw, "direction")) {
		if (!strcmp(opt, "in")) {
			puts("directon set to input");
			line->request_type = GPIOD_LINE_REQUEST_DIRECTION_INPUT;
		}
		else if (!strcmp(opt, "out")) {
			puts("directon set to output");
			line->request_type = GPIOD_LINE_REQUEST_DIRECTION_OUTPUT;
		}
		else {
			fprintf(stderr, "Wrong option for \"%s\"\n", kw);
			rv = 1;
		}
	}
	else if (!strcmp(kw, "defval")) {
		if (atoi(opt) == 0) {
			puts("default value LOW");
			*val = 0;
		}
		else {
			puts("default value HIGH");
			*val = 1;
		}
	}
	else if (!strcmp(kw, "consumer")) {
		printf("consumer is \"%s\"\n", opt);
		strncpy(consumer, opt, CONSUMER_MAX);
	}
	else if (!strcmp(kw, "flags")) {
		if (!strcmp(opt, "open_drain")) {
			line->flags |= GPIOD_LINE_REQUEST_FLAG_OPEN_DRAIN;
			puts("flag open drain");
		}
		else if (!strcmp(opt, "open_source")) {
			line->flags |= GPIOD_LINE_REQUEST_FLAG_OPEN_SOURCE;
			puts("flag open source");
		}
		else if (!strcmp(opt, "active_low")) {
			line->flags |= GPIOD_LINE_REQUEST_FLAG_ACTIVE_LOW;
			puts("flag active low");
		}
		else {
			fprintf(stderr, "Wrong option for \"%s\"\n", kw);
			rv = 1;
		}
	}
	else if (!strcmp(kw, "edge")) {
		if (!strcmp(opt, "rising")) {
			line->request_type = GPIOD_LINE_REQUEST_EVENT_RISING_EDGE;
			puts("rising edge");
		}
		else if (!strcmp(opt, "falling")) {
			line->request_type = GPIOD_LINE_REQUEST_EVENT_FALLING_EDGE;
			puts("falling edge");
		}
		else if (!strcmp(opt, "both")) {
			line->request_type = GPIOD_LINE_REQUEST_EVENT_BOTH_EDGES;
			puts("both edges");
		}
		else {
			fprintf(stderr, "Wrong option for \"%s\"\n", kw);
			rv = 1;
		}
	}
	else {
		fprintf(stderr, "Wrong kw \"%s\"\n", kw);
		rv = 1;
	}

	return rv;
}

static int set_gpio_line(const char *chip_name, int line_num, int defval,
						 struct gpiod_line_request_config *linecfg,
						 struct gpio_chip *chips,
						 struct gpiod_line_bulk *entries)
{
	int rv = -1, found = 0;
	struct gpiod_chip *gpio_chip;

	for (size_t i = 0; i < chips->chip_num; i++) {
		if (!strcmp(gpiod_chip_name(chips->gpiochip[i]), chip_name)) {
			gpio_chip = chips->gpiochip[i];
			found = 1;
			break;
		}
	}

	if (found != 1) {
		if (chips->chip_num == MAX_CHIP) {
			fprintf(stderr, "Too many chips opened");
			goto out;
		}
		chips->gpiochip[chips->chip_num] = gpiod_chip_open_lookup(chip_name);
		if (chips->gpiochip[chips->chip_num] == NULL) {
			fprintf(stderr, "gpiod_chip_open_lookup(): %s\n", strerror(errno));
			goto out;
		}
		gpio_chip = chips->gpiochip[chips->chip_num];
		printf("new chip_name is \"%s\"\n", gpiod_chip_name(gpio_chip));
		chips->chip_num++;
	} else
		printf("chip_name is \"%s\"\n", gpiod_chip_name(gpio_chip));

	entries->lines[entries->num_lines] = gpiod_chip_get_line(gpio_chip, line_num);
	if (entries->lines[entries->num_lines] == NULL) {
		fprintf(stderr, "gpiod_chip_get_line(): %s\n", strerror(errno));
		goto out;
	}

	if (!gpiod_line_is_free(entries->lines[entries->num_lines])) {
		fprintf(stderr, "GPIO line (%s) is used\n",
						 gpiod_line_consumer(entries->lines[entries->num_lines]));
		free(entries->lines[entries->num_lines]);
		goto out;
	}

	if (gpiod_line_request(entries->lines[entries->num_lines], linecfg, defval) < 0) {
		fprintf(stderr, "gpiod_line_request(): %s\n", strerror(errno));
		free(entries->lines[entries->num_lines]);
		goto out;
	}

	entries->num_lines += 1;
	rv = 0;

out:
	return rv;
}

static int find_chip_name(char **lineptr, char **arri,
						  char *line, char *gpiochip, size_t len)
{
	while (**lineptr && **lineptr != ':')
			(*lineptr)++;

		if (**lineptr == '\0') {
			fprintf(stderr, "Missing gpiochip\n");
			return -1;
		}

		**lineptr = '\0';
		(*lineptr)++;
		*arri = *lineptr;
		strncpy(gpiochip, line, len);

		return 0;
}

static int find_pin(char **lineptr, char **arri, unsigned int *line_num)
{
	char pin[12];
	int port = -1;

	while (**lineptr && !isspace(**lineptr))
		(*lineptr)++;

	if (**lineptr == '\n') {
		fprintf(stderr, "Missing pin\n");
		return -1;
	}

	**lineptr = '\0';
	(*lineptr)++;
	strncpy(pin, *arri, sizeof(pin)-1);

	if (!strcmp(pin, "all"))
		return 3;
	else if (!strcmp(pin, "all_output"))
		return 2;
	else if (!strcmp(pin, "all_input"))
		return 1;

	if (sscanf(pin, "%d", line_num) != 1) {
		for (int i = 'A'; i < 'Z'; i++) {
			if (pin[1] == i) {
				port = i - 65;
				break;
			}
		}

		if (port < 0) {
			fprintf(stderr, "No valid pin found.");
			return -1;
		}
		else
			/* Line number calculation. This is the pin identifier in the GPIO block device */
			*line_num = port * 32 + atoi(&pin[2]);
	}

	return 0;
}

static int parser(const char *config_file,
				  struct gpio_chip *chips,
				  struct gpiod_line_bulk *entries,
			  	  int *gpioevent_fds, int *gpioevent_line_num)
{
	FILE *fp;
	char line[1024], property[20] = {0}, keyword[20],
		 gpiochip[32], consumer_str[CONSUMER_MAX] = {0};
	char *lineptr, *arri;
	int defval = 0;
	unsigned int pin;

	struct gpiod_line_request_config config = {0};

	if ((fp = fopen(config_file, "r")) == NULL) {
		perror("fopen()");
		return -1;
	}

	config.consumer = consumer_str;

	while (fgets(line, sizeof(line), fp) != NULL) {
		lineptr = line;
		printf("\n%s", lineptr);

		if (*lineptr == '#')
			continue;

		if (line[strlen(line)-2] != ';') {
			fprintf(stderr, "%s\n", "Missing semicolon or newline");
			return -1;
		}

		if (find_chip_name(&lineptr, &arri, line, gpiochip, sizeof(gpiochip)))
			return -1;

		if (find_pin(&lineptr, &arri, &pin))
			return -1;

		/* find keyword */
		arri = property;
		while (*lineptr && *lineptr != '\n') {
			if (*lineptr == ',' || *lineptr == ';') {
				match_keyword(keyword, property,
							  consumer_str, &defval, &config);

				bzero(property, sizeof(property));
				arri = property;
			}
			else if (*lineptr == '=') {
				strncpy(keyword, property, sizeof(keyword));
				bzero(property, sizeof(property));
				arri = property;
			}
			else if (isspace(*lineptr)) {}
			else {
				*arri = *lineptr;
				arri++;
			}
			lineptr++;
		}

		if (set_gpio_line(gpiochip, pin, defval, &config, chips, entries) < 0) {
			fprintf(stderr, "Skip line: %d\n", pin);
		}
		else {
			if (config.request_type == GPIOD_LINE_REQUEST_EVENT_RISING_EDGE ||
				config.request_type == GPIOD_LINE_REQUEST_EVENT_FALLING_EDGE ||
				config.request_type == GPIOD_LINE_REQUEST_EVENT_BOTH_EDGES) {
				if (!gpioevent_fds) {
					return -1;
				}
				printf("add to monitoring... offset: %d fd: %d\n",
						gpiod_line_offset(entries->lines[entries->num_lines - 1]),
 						gpiod_line_event_get_fd(entries->lines[entries->num_lines - 1]));
				*gpioevent_fds = gpiod_line_event_get_fd(entries->lines[entries->num_lines - 1]);
				gpioevent_fds++;
				*gpioevent_line_num = entries->num_lines - 1;
				gpioevent_line_num++;
			}
		}
		config.flags = 0;
		config.request_type = 0;
	}

	fclose(fp);

	return 0;
}

static int send_sock_msg(int fd, const char *msg, size_t len, int flags)
{
	ssize_t rv = send(fd, msg, len, flags);

	if (rv < 0) {
		fprintf(stderr, "send(): %s\n", strerror(errno));
	}
	else if (rv != len) {
		fprintf(stderr, "send(): rv != len\n");
	}

	return rv;
}

static int processing_client_req(char *message, struct gpiod_line_bulk *entries,
								 int sd)
{
	char chipname[32];
	char *ptr, *start;
	const char *lines_chipname;
	int value = -1, rv = -1, pinrv;
	unsigned int line_num, offset;

	struct gpiod_chip *chip;

	start = ptr = message;

	if (find_chip_name(&ptr, &start, message, chipname, sizeof(chipname)) < 0) {
		char msg[] = "Wrong chip!\n";
		send_sock_msg(sd, msg, sizeof(msg), 0);

		return -1;
	}

	if ((pinrv = find_pin(&ptr, &start, &line_num)) < 0) {
		char msg[] = "Wrong pin!\n";
		send_sock_msg(sd, msg, sizeof(msg), 0);

		return -1;
	}

	if (!strcmp(ptr, "set\n"))
		value = 1;
	else if (!strcmp(ptr, "reset\n"))
		value = 0;
	else if (!strcmp(ptr, "get\n")) {}
	else {
		char msg[] = "Wrong keyword!\n";
		send_sock_msg(sd, msg, sizeof(msg), 0);

		return -1;
	}

	/* If a single line requested */
	if (pinrv == 0) {
		for (size_t i = 0; i < entries->num_lines; i++) {
			char msg[12] = {0};

			offset = gpiod_line_offset(entries->lines[i]);
			if (offset != line_num)
				continue;

			chip = gpiod_line_get_chip(entries->lines[i]);
			lines_chipname = gpiod_chip_name(chip);

			if (strcmp(lines_chipname, chipname))
				continue;

			if (value != -1) {
				rv = gpiod_line_set_value(entries->lines[i], value);
				if (rv < 0)
					strcpy(msg, "NOK\n");
				else
					strcpy(msg, "OK\n");
			}
			else {
				rv = gpiod_line_get_value(entries->lines[i]);
				if (rv == 0)
					strcpy(msg, "0\n");
				else
					strcpy(msg, "1\n");
			}
			send_sock_msg(sd, msg, sizeof(msg), 0);
			break;
		}
	}
	/* all (3), all_input (1), all_output (2) */
	else {
		for (size_t i = 0; i < entries->num_lines; i++) {
			char msg[32] = {0};

			int dir = gpiod_line_direction(entries->lines[i]);
			if (pinrv != 3) {
				if (pinrv != dir)
					continue;
			}

			if (pinrv == GPIOD_LINE_DIRECTION_OUTPUT) {
				if (value == -1) {
					rv = gpiod_line_get_value(entries->lines[i]);
					if (rv == 0)
						strcpy(msg, "0\n");
					else
						strcpy(msg, "1\n");
				}
				else {
					rv = gpiod_line_set_value(entries->lines[i], value);
					if (rv < 0)
						strcpy(msg, "NOK\n");
					else
						strcpy(msg, "OK\n");
				}
			}
			else {
				rv = gpiod_line_get_value(entries->lines[i]);
				if (rv == 0)
					strcpy(msg, "0\n");
				else
					strcpy(msg, "1\n");
			}
			send_sock_msg(sd, msg, sizeof(msg), 0);
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	char *config_path = NULL, *socket_path = NULL, cli_message[256] = {0},
		 cli_msg_len = 0;
	unsigned char cli_msg_len_prev = 0;
	int client_sockets[MAX_FDS] = {0}, gpioevent_fds[MAX_LINES] = {0},
		gpioevent_line_num[MAX_LINES] = {0},
	 	master_socket, new_socket, sd, max_sd, srv, len,
		optc, opti;
	socklen_t t;
	fd_set rdfs;
	struct sockaddr_un local, remote;

	struct gpiod_line_bulk entries = { .num_lines = 0 };
	struct gpiod_line_event eventfd;
	struct gpio_chip chips = {0};

	struct sigaction sa_exit;

	for (;;) {
		optc = getopt_long(argc, argv, shortopts, longopts, &opti);
		if (optc < 0)
			break;

		switch (optc) {
		case 'h':
			print_help(argv[0]);
		case 'd':
			break;
		case 's':
			socket_path = strndup(optarg, PATH_MAX - 1);
			break;
		case 'c':
			config_path = strndup(optarg, PATH_MAX - 1);
			break;
		case '?':
		default:
			print_help(argv[0]);
		}
	}

	argc -= optind;
	argv += optind;

	if (config_path == NULL)
		config_path = strdup(DEFAULT_CONFIG);

	if (socket_path == NULL)
		socket_path = strdup(DEFAULT_SOCKET);

	printf("Config path: %s\n", config_path);
	printf("Socket path: %s\n", socket_path);

	if (argc > 0) {
		fprintf(stderr, "Unrecognized option!\n");
		goto out;
	}

	sa_exit.sa_handler = exit_program;
	sa_exit.sa_flags = 0;
	sigemptyset(&sa_exit.sa_mask);
	if (sigaction(SIGINT, &sa_exit, NULL) < 0) {
		perror("sigaction()");
		exit(EXIT_FAILURE);
	}

	exit_flag = 0;

	if (parser(config_path, &chips, &entries, gpioevent_fds, gpioevent_line_num) < 0)
		goto out;

	/* Init socket */
	if ((master_socket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket()");
		goto out;
	}

	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, socket_path);
	unlink(local.sun_path);
	len = strlen(local.sun_path) + sizeof(local.sun_family);
	if (bind(master_socket, (struct sockaddr *)&local, len) == -1) {
		perror("bind()");
		goto out;
	}

	if (listen(master_socket, 5) == -1) {
		perror("listen()");
		goto out;
	}

	t = sizeof(remote);

/*
	if (daemon(0,0) < 0)
		fprintf(stderr, "daemon(): %s\n", strerror(errno));
*/
	while (!exit_flag) {
		FD_ZERO(&rdfs);

		FD_SET(master_socket, &rdfs);
		max_sd = master_socket;

		for (size_t i = 0; i < MAX_FDS; i++) {
			sd = client_sockets[i];
			if(sd > 0)
				FD_SET(sd, &rdfs);

			if(sd > max_sd)
				max_sd = sd;
		}

		for (size_t i = 0; i < entries.num_lines; i++) {
			sd = gpioevent_fds[i];
			if(sd > 0)
				FD_SET(sd, &rdfs);

			if(sd > max_sd)
				max_sd = sd;
		}

		srv = select(max_sd + 1, &rdfs, NULL, NULL, NULL);

		if (srv < 0) {
			if (errno == EINTR)
				continue;
			perror("select()");
		}
		/* New client */
		if (FD_ISSET(master_socket, &rdfs)) {
			if ((new_socket = accept(master_socket,
				(struct sockaddr *)&remote, (socklen_t*)&t)) < 0) {
				perror("accept");
			}

			for (size_t i = 0; i < MAX_FDS; i++) {
				if(client_sockets[i] == 0) {
					client_sockets[i] = new_socket;
					break;
				}
			}
		}
		else {
			/* GPIO interrupt */
			for (size_t i = 0; i < entries.num_lines; i++) {
				sd = gpioevent_fds[i];
				if (FD_ISSET(sd, &rdfs)) {
					char buffer[128] = {0};
					const char *lines_chipname;
					struct gpiod_chip *chip;

					gpiod_line_event_read_fd(sd, &eventfd);
					chip = gpiod_line_get_chip(entries.lines[gpioevent_line_num[i]]);
					lines_chipname = gpiod_chip_name(chip);

					snprintf(buffer, sizeof(buffer)-1, "[%ld.%.9ld] %s:%u(%s):%s\n",
							eventfd.ts.tv_sec, eventfd.ts.tv_nsec,
							lines_chipname,
						 	gpiod_line_offset(entries.lines[gpioevent_line_num[i]]),
							gpiod_line_consumer(entries.lines[gpioevent_line_num[i]]),
							eventfd.event_type == GPIOD_LINE_EVENT_RISING_EDGE ?
												  "rising" : "falling");
					printf("%s\n", buffer);

					for (size_t i = 0; i < MAX_FDS; i++) {
						sd = client_sockets[i];
						if (sd)
							send_sock_msg(sd, buffer, sizeof(buffer), 0);
					}

					break;
				}
			}
			/* Incoming data from client */
			for (size_t i = 0; i < MAX_FDS; i++) {
				sd = client_sockets[i];

				if (FD_ISSET(sd, &rdfs)) {
					cli_msg_len = read(sd, &cli_message[cli_msg_len_prev], sizeof(cli_message)-1);
					/* Somebody disconnected */
					if (cli_msg_len == 0) {
						printf("fd %d disconected\n", sd);
						close(sd);
						client_sockets[i] = 0;
					}
					else {
						if (cli_message[cli_msg_len+cli_msg_len_prev-1] == '\n') {
							cli_msg_len_prev = 0;
							printf("incoming message: %s", cli_message);
							processing_client_req(cli_message, &entries, sd);
							bzero(cli_message, sizeof(cli_message));
						}
						else {
							cli_msg_len_prev += cli_msg_len;
						}
					}
					break;
				}
			}
		}
	}

	for (size_t i = 0; i < MAX_FDS; i++) {
		if (client_sockets[i] != 0)
			close(client_sockets[i]);
	}
	close(master_socket);

out:
	for (size_t i = 0; i < chips.chip_num; i++) {
		gpiod_chip_close(chips.gpiochip[i]);
	}

	unlink(local.sun_path);
	free(socket_path);
	free(config_path);

	return 0;
}
