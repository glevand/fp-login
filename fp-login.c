/*
 *  Firepass VPN login client.
 *
 *  Copyright 2008 Geoff Levand
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License, Version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  Technical info on the Firepass VPN can be found at the F5 Networks
 *  developer site http://devcentral.f5.com/.
 */

/** --- todo ---
 * fix certificate check
 * seed rng?
 * config file comments
 * config file host sections
 * config file multiple pairs
 */

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif
#define _GNU_SOURCE
#include <assert.h>
#include <getopt.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/route.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>

#include "platform.h"

const char app_name[] = "fp-login";

#if defined(PACKAGE_VERSION) && defined(PACKAGE_NAME)
static const char app_version[] = "(" PACKAGE_NAME ") " PACKAGE_VERSION;
#else
static const char app_version[] = "";
#endif

#if defined(PACKAGE_BUGREPORT)
static const char app_bugreport[] = "Send bug reports to " PACKAGE_BUGREPORT;
#else
static const char app_bugreport[] = "";
#endif

static void print_version(void)
{
	printf("%s %s\n", app_name, app_version);
}

static void print_usage(void)
{
	fprintf(stderr, "%s %s\n", app_name, app_version);
	fprintf(stderr,
"SYNOPSIS\n"
"     fp-login [-a, --auth-format auth-format] [-c, --certificate certificate]\n"
"              [-C, --config config] [-f, --favorite-id favorite-id]\n"
"              [-h, --help] [-H, --host host] [-n, --nameserver nameserver]\n"
"              [-N, --network network] [-p, --port port] [-u, --user user]\n"
"              [-v, --verbose] [-V, --version]\n"
"DESCRIPTION\n"
"     The fp-login client is used to remotely log into a FirePass VPN server.\n"
"OPTIONS\n"
"     -a, --auth-format auth-format\n"
"             Specifies the format of the authentication data sent to the VPN\n"
"             server.  The default auth-format is ’U:P’.\n"
"     -c, --certificate certificate\n"
"             Use the x509 certificate file certificate.\n"
"     -C, --config config\n"
"             Use the configuration file config.  Use of this option will cause\n"
"             fp-login to bypass processing of its default configuration files.\n"
"     -f, --favorite-id favorite-id\n"
"             Connect to the FirePass VPN with the favorite ID favorite-id.\n"
"             The default favorite-id is ’Z=0,1’.  This will work for most\n"
"             VPNs.\n"
"     -h, --help\n"
"             Print a help message.\n"
"     -H, --host host\n"
"             Connect to the remote FirePass VPN server host.\n"
"     -n, --nameserver nameserver\n"
"             Add the name server nameserver to the local resolver configura-\n"
"             tion. This option specifies the DNS nameservers for the remote\n"
"             network, and can be specified multiple times.  The current imple-\n"
"             mentation only supports a single --nameserver option.\n"
"     -N, --network network\n"
"             Add the remote network network to the local routing tables for this\n"
"             VPN connection. Must be in the 'target/prefix' format.\n"
"     -p, --port port\n"
"             Use the remote FirePass server port port.  The default port value\n"
"             is 443 (https).\n"
"     -u, --user user\n"
"             Use the user login name user.\n"
"     -v, --verbose\n"
"             Program verbosity level. The level is additive. -vvv will give a\n"
"             verbose output.\n"
"     -V, --version\n"
"             Display the program version number.\n"
	);

	fprintf(stderr,
"     See the %s man page for more info.\n"
"     %s\n", app_name, app_bugreport);
}

/**
 * enum opt_value - Tri-state options variables.
 */

enum opt_value {opt_undef = 0, opt_yes, opt_no};

/**
 * struct opts - Values from command line options.
 */

struct opts {
	const char *auth_format;
	const char *certificate;
	const char *config;
	const char *favorite_id;
	enum opt_value show_help;
	const char *host;
	const char *nameserver;
	const char *network;
	const char *port;
	const char *user;
	unsigned int verbosity;
	enum opt_value show_version;
};

/**
 * default_values - Program default values.
 */

static const struct opts default_values = {
	.auth_format = "U:P",
	.favorite_id = "Z=0,1",
	.port = "443",
};

/**
 * opts_parse - Parse the command line options.
 */

static int opts_parse(struct opts* opts, int argc, char *argv[])
{
	static const struct option long_options[] = {
		{"auth-format", required_argument, NULL, 'a'},
		{"certificate", required_argument, NULL, 'c'},
		{"config",      required_argument, NULL, 'C'},
		{"favorite-id", required_argument, NULL, 'f'},
		{"help",        no_argument,       NULL, 'h'},
		{"host",        required_argument, NULL, 'H'},
		{"nameserver",  required_argument, NULL, 'n'},
		{"network",     required_argument, NULL, 'N'},
		{"port",        required_argument, NULL, 'p'},
		{"user",        required_argument, NULL, 'u'},
		{"verbose",     no_argument,       NULL, 'v'},
		{"version",     no_argument,       NULL, 'V'},
		{ NULL,         0,                 NULL, 0},
	};
	static const char short_options[] = "a:c:C:f:hH:n:N:p:u:vV";

	while(1) {
		int c = getopt_long(argc, argv, short_options, long_options,
			NULL);

		if (c == EOF)
			break;

		switch(c) {
		case 'a':
			opts->auth_format = optarg;
			break;
		case 'c':
			opts->certificate = optarg;
			break;
		case 'C':
			opts->config = optarg;
			break;
		case 'f':
			opts->favorite_id = optarg;
			break;
		case 'h':
			opts->show_help = opt_yes;
			break;
		case 'H':
			opts->host = optarg;
			break;
		case 'n':
			opts->nameserver = optarg;
			break;
		case 'N':
			opts->network = optarg;
			break;
		case 'p':
			opts->port = optarg;
			break;
		case 'u':
			opts->user = optarg;
			break;
		case 'v':
			opts->verbosity++;
			break;
		case 'V':
			opts->show_version = opt_yes;
			break;
		default:
			opts->show_help = opt_yes;
			return -1;
		}
	}

	return 0;
}

/**
 * struct sys_path - System programs and conf files.
 * @resolver: Resolver config file.
 *
 * These should be in the standard places.
 */

struct sys_path {
	char *chat;
	char *pppd;
	char *ssl;
	char *resolver;
};

static const struct sys_path sys_path = {
	.chat = "/usr/sbin/chat",
	.pppd = "/usr/sbin/pppd",
	.ssl = "/usr/bin/openssl",
	.resolver = "/etc/resolv.conf",
};

/**
 * enum echo_state - Whether or not to echo data to display.
 * @echo_on: Use with non-secret data.
 * @echo_off: Use with secrets.
 */

enum echo_state { echo_on = -1, echo_off = 0, };

/**
 * struct config_file_data - Values from configuration files.
 */

struct config_file_data {
	char *auth_format;
	char *certificate;
	char *favorite_id;
	char *host;
	char *nameserver;
	char *network;
	char *port;
	char *user;
};

/**
 * struct login_info - User login secrets.
 */

struct login_info {
	char *auth_format;
	char *user;
	char *pw;
	char *token;
};

/**
 * struct ss_info - SSL connection info.
 */

struct ss_info {
	char *certificate;
	char *host;
	char *port;
	BIO *bio;
	SSL_CTX *ctx;
	SSL *ssl;
	SSL_SESSION *session;
};

/**
 * struct fp_info - Firepass session info.
 * @favorite_id: User specified VPN favorite id from command line or
   conf file.
 * @session_id: Session id received from fp server.
 */

struct fp_info {
	char *favorite_id;
	char *session_id;
};

/**
 * struct route - IP routing info.
 * @dest: Routing table destination.
 * @mask: Routing table mask.
 * @gw: Routing table gateway.
 */

struct route {
	char *dest;
	char *mask;
	char *gw;
};

/**
 * route_from_prefix - Fill struct route from dest/prefix notation.
 */

static int route_from_prefix(struct route *route, const char *network)
{
	char *p;
	unsigned long prefix;
	struct in_addr in_addr;

	if (!network)
		return -EINVAL;

	route->dest = strdup(network);

	p = strchr(route->dest, '/');

	if (!p) {
		fprintf(stderr, "%s:%d: failed '%s'.\n", __func__,
			__LINE__, network);
		goto fail;
	}

	*p++ = 0;

	errno = 0;
	prefix = strtoul(p, &p, 0);

	if (errno || *p) {
		fprintf(stderr, "%s:%d: prefix failed '%s'.\n", __func__,
			__LINE__, network);
		perror(app_name);
		goto fail;
	}

	in_addr.s_addr = htonl(~(0xffffffffUL >> prefix));

	route->mask = strdup(inet_ntoa(in_addr));

	return 0;

fail:
	free(route->dest);
	route->dest = NULL;
	return -1;
}

enum route_op { route_op_add, route_op_delete, };

/**
 * route_do_op - Add/delete a route in the system routing tables.
 *
 * BSD4.4 variants use the AF_ROUTE socket to access the kernel routing tables.
 * Linux uses ioctl with the early BSD struct rtentry.
 */

#if (HAVE_STRUCT_RT_MSGHDR)
static int route_do_op(const struct route *route, enum route_op route_op)
{
	int result;
	int s;
	struct rt_msghdr *hdr;
	struct sockaddr_in *dest;
	struct sockaddr_in *gw;
	struct sockaddr_in *mask;
	static const unsigned int msg_len = sizeof(struct rt_msghdr)
		+ 3 * sizeof(struct sockaddr_in);

	assert(route->dest);
	assert(route->mask);
	assert(route->gw);

	s = socket(AF_ROUTE, SOCK_RAW, AF_UNSPEC);

	if (s < 0) {
		fprintf(stderr, "%s:%d: socket failed.\n", __func__, __LINE__);
		perror(app_name);
		return -1;
	}

	hdr = calloc(1, msg_len);

	if (!hdr) {
		fprintf(stderr, "%s:%d: calloc failed.\n", __func__, __LINE__);
		result = -1;
		goto done;
	}

	hdr->rtm_msglen = msg_len;
	hdr->rtm_version = RTM_VERSION;
	hdr->rtm_type = (route_op == route_op_add) ? RTM_ADD : RTM_DELETE;
	hdr->rtm_addrs = (RTA_DST | RTA_GATEWAY | RTA_NETMASK);
	hdr->rtm_flags = RTF_UP;
	hdr->rtm_rmx.rmx_hopcount = 1;
	hdr->rtm_pid = getpid();
	hdr->rtm_seq = 1;

	dest = (void *)(hdr + 1);
	dest->sin_family = AF_INET;
	dest->sin_len = sizeof(struct sockaddr_in);
	result = inet_aton(route->dest, &dest->sin_addr);

	if (!result) {
		fprintf(stderr, "%s:%d: inet_aton failed '%s'.\n", __func__,
			__LINE__, route->dest);
		result = -1;
		goto done;
	}

	gw = (void *)(dest + 1);
	gw->sin_family = AF_INET;
	gw->sin_len = sizeof(struct sockaddr_in);
	result = inet_aton(route->gw, &gw->sin_addr);

	if (!result) {
		fprintf(stderr, "%s:%d: inet_aton failed '%s'.\n", __func__,
			__LINE__, route->gw);
		result = -1;
		goto done;
	}

	mask = (void *)(gw + 1);
	mask->sin_family = AF_INET;
	mask->sin_len = sizeof(struct sockaddr_in);
	result = inet_aton(route->mask, &mask->sin_addr);

	if (!result) {
		fprintf(stderr, "%s:%d: inet_aton failed '%s'.\n", __func__,
			__LINE__, route->mask);
		result = -1;
		goto done;
	}

	result = write(s, hdr, hdr->rtm_msglen);

	if (result != hdr->rtm_msglen) {
		fprintf(stderr, "%s:%d: write failed.\n", __func__, __LINE__);
		perror(app_name);
		result = -1;
		goto done;
	}

	result = 0;

done:
	free(hdr);
	close(s);
	return result;
}
#elif (HAVE_STRUCT_RTENTRY)
static int route_do_op(const struct route *route, enum route_op route_op)
{
	int result;
	int s;
	struct rtentry e;
	struct sockaddr_in *dest;
	struct sockaddr_in *gw;
	struct sockaddr_in *mask;

	assert(route->dest);
	assert(route->mask);
	assert(route->gw);

	s = socket(AF_INET, SOCK_DGRAM, AF_UNSPEC);

	if (s < 0) {
		fprintf(stderr, "%s:%d: socket failed.\n", __func__, __LINE__);
		perror(app_name);
		return -1;
	}

	memset(&e, 0, sizeof(e));

	e.rt_flags = RTF_UP | RTF_GATEWAY;

	dest = (void *)&e.rt_dst;
	dest->sin_family = AF_INET;
	result = inet_aton(route->dest, &dest->sin_addr);

	if (!result) {
		fprintf(stderr, "%s:%d: inet_aton failed '%s'.\n", __func__,
			__LINE__, route->dest);
		result = -1;
		goto done;
	}

	gw = (void *)&e.rt_gateway;
	gw->sin_family = AF_INET;
	result = inet_aton(route->gw, &gw->sin_addr);

	if (!result) {
		fprintf(stderr, "%s:%d: inet_aton failed '%s'.\n", __func__,
			__LINE__, route->gw);
		result = -1;
		goto done;
	}

	mask = (void *)&e.rt_genmask;
	mask->sin_family = AF_INET;
	result = inet_aton(route->mask, &mask->sin_addr);

	if (!result) {
		fprintf(stderr, "%s:%d: inet_aton failed '%s'.\n", __func__,
			__LINE__, route->mask);
		result = -1;
		goto done;
	}

	result = ioctl(s, (route_op == route_op_add) ? SIOCADDRT : SIOCDELRT,
		&e);

	if (result < 0) {
		fprintf(stderr, "%s:%d: ioctl failed.\n", __func__, __LINE__);
		perror(app_name);
		result = -1;
		goto done;
	}

done:
	close(s);
	return result;
}
#else
#error Unknown route interface.
#endif /* (HAVE_STRUCT_RT_MSGHDR) */

static int route_add(const struct route *route)
{
	return route_do_op(route, route_op_add);
}

static int route_delete(const struct route *route)
{
	return route_do_op(route, route_op_delete);
}

/**
 * struct vpn - Remote network info.
 * @route: IP routing info.
 * @dns: Remote DNS info.
 */

struct vpn {
	struct route route;
	struct dns dns;
};

static volatile int global_abort;
static unsigned int _verbosity;

static int verbosity(unsigned int level)
{
	return (level <= _verbosity);
}

static void str_clean(char *s)
{
	if (!s)
		return;

	memset(s, 0, strlen(s));
	free(s);
}

static void login_info_clean(struct login_info *lii)
{
	assert(lii);

	str_clean(lii->user);
	str_clean(lii->token);
	str_clean(lii->pw);
	memset(lii, 0, sizeof(*lii));
}

static void ss_info_clean(struct ss_info *ssi)
{
	assert(ssi);

	str_clean(ssi->certificate);
	str_clean(ssi->host);
	str_clean(ssi->port);
	memset(ssi, 0, sizeof(*ssi));
}

static void fp_info_clean(struct fp_info *fpi)
{
	assert(fpi);

	str_clean(fpi->favorite_id);
	str_clean(fpi->session_id);
	memset(fpi, 0, sizeof(*fpi));
}

static void print_io_header(const char *out, int out_len, enum echo_state echo)
{
	if (echo != echo_on)
		return;

	if (verbosity(2))
		printf("%s: sending %u bytes.\n", app_name, out_len);
	if (verbosity(3)) {
		printf(">>===========================\n");
		printf(out);
		printf("===========================>>\n");
	}
}

static void print_io_trailer(const char *in, int in_bytes, enum echo_state echo)
{
	if (echo != echo_on)
		return;

	if (verbosity(2))
		printf("%s: recv'd %d bytes.\n", app_name, in_bytes);
	if (verbosity(3)) {
		printf("<<===========================\n");
		printf(in);
		if (in[in_bytes] != '\n')
			printf("\n");
		printf("===========================<<\n");
	}
}

static char *find_key_item(const char* key, const char* in)
{
	const char *item;
	int item_len;
	char *out;

	/* Finds the last occurance of key. */
	// need to handle comments!!!

	item = NULL;

	while (1) {
		in = strcasestr(in, key);

		if (!in) {
			if (!item) {
				//DBGS("'%s': not found.\n", key);
				return NULL;
			}
			break;
		}

		in += strlen(key);

		while (*in && (*in == ' ' || *in == '\t'))
			in++;

		if (*in != '=')
			continue;
		in++;

		while (*in && (*in == ' ' || *in == '\t'))
			in++;

		item = in;

		//DBGS("found item\n");

		while (*in && *in != ';' && *in != '\n' && *in != '\r')
			in++;

		item_len = in - item;
	}

	out = malloc(item_len + 1);

	if (!out) {
		DBGS("%s: no mem.\n", key);
		return NULL;
	}

	memcpy(out, item, item_len);
	out[item_len] = 0;

	//DBGS("found %s:'%s'\n", key, out);
	return out;
}

static ssize_t readline(char **lineptr, FILE *stream)
{
	char *p;
	char *end;

	*lineptr = malloc(MAXPATHLEN);

	if (!*lineptr)
		return -1;

	for (p = *lineptr, end = p + MAXPATHLEN; ; p++) {
		int c = getc(stream);

		if (c == EOF) {
			DBGS("EOF.\n");
			break;
		}

		if (p >= end - 1) {
			DBGS("buf full.\n");
			break;
		}

		*p = c;

		if (c == '\n' || c == '\r') {
			p++;
			break;
		}

	}

	*p = 0;

	if (p == *lineptr) {
		DBGS("no data.\n");
		return -1;
	}

	return (ssize_t)(p - *lineptr);
}

static void config_file_data_clean(struct config_file_data *cfd)
{
	assert(cfd);

	free(cfd->certificate);
	free(cfd->favorite_id);
	str_clean(cfd->host);
	free(cfd->auth_format);
	str_clean(cfd->nameserver);
	str_clean(cfd->network);
	free(cfd->port);
	str_clean(cfd->user);
	memset(cfd, 0, sizeof(*cfd));
}

static int config_file_data_read(struct config_file_data *cfd,
	const char* file_name)
{
	char buf[1024];
	size_t bytes;
	FILE *stream;

	stream = fopen(file_name, "r");

	if (!stream) {
		if (verbosity(3)) {
			printf("%s: fopen '%s' failed.\n", app_name, file_name);
			perror(NULL);
		}
		return -1;
	}

	bytes = fread(buf, 1, sizeof(buf), stream);

	if (bytes <= 0 || ferror(stream)) {
		if (verbosity(2)) {
			printf("%s: fread '%s' failed.\n", app_name, file_name);
			perror(app_name);
		}
		fclose(stream);
		return -1;
	}

	if (verbosity(3))
		printf("%s: found '%s'.\n", app_name, file_name);

	fclose(stream);

	buf[bytes] = 0;

	if (!cfd->certificate)
		cfd->certificate = find_key_item("certificate", buf);
	if (!cfd->favorite_id)
		cfd->favorite_id = find_key_item("favorite-id", buf);
	if (!cfd->host)
		cfd->host = find_key_item("host", buf);
	if (!cfd->auth_format)
		cfd->auth_format = find_key_item("auth-format", buf);
	if (!cfd->nameserver)
		cfd->nameserver = find_key_item("nameserver", buf);
	if (!cfd->network)
		cfd->network = find_key_item("network", buf);
	if (!cfd->port)
		cfd->port = find_key_item("port", buf);
	if (!cfd->user)
		cfd->user = find_key_item("user", buf);

	return 0;
}

static int prompt_user(const char *prompt, enum echo_state echo,
	FILE *stream, char **info)
{
	int result;
	struct termios old;
	struct termios new;
	int bytes;

	assert(!*info);

	if (echo != echo_on) {
		result = tcgetattr(fileno(stream), &old);

		if (result) {
			DBGS("tcgetattr failed.\n");
			perror(app_name);
			return -1;
		}

		new = old;
		new.c_lflag &= ~ECHO;

		fprintf(stdout, prompt);
		fflush(stdout);

		result = tcsetattr(fileno(stream), TCSAFLUSH, &new);

		if (result) {
			DBGS("tcsetattr failed.\n");
			perror(app_name);
			return -1;
		}

	} else {
		fprintf(stdout, prompt);
		fflush(stdout);
	}

	bytes = readline(info, stream);

	if (echo != echo_on) {
		tcsetattr(fileno(stream), TCSAFLUSH, &old);
		fprintf(stdout, "\n");
		fflush(stdout);
	}

	if (global_abort) {
		if (verbosity(1))
			fprintf(stderr, "%s: user abort.\n", app_name);
		str_clean(*info);
		*info = NULL;
		return -1;
	}

	 /* cleanup eol */

	if (bytes >= 0) {
		char *p = *info;
		char *end = p + bytes;

		while (p < end && *p != 0 && *p != '\n' && *p != '\r')
			p++;
		*p = 0;
	}

	 /* cleanup null string */

	if ((*info)[0] == 0) {
		free(*info);
		*info = NULL;
	}

	//DBGS("info  @%s@\n", *info);

	return 0;
}

static int get_user_config_file(char **user_config)
{
	int result;
	struct passwd pw;
	struct passwd* p;
	void *buf;
	long buf_size;
	char *path;

	if (verbosity(3)) {
		printf("%s: uid  %u\n", app_name, (unsigned int)getuid());
		printf("%s: euid %u\n", app_name, (unsigned int)geteuid());
	}

	buf_size = sysconf(_SC_GETPW_R_SIZE_MAX);

	buf = malloc(buf_size);

	if (buf)
		result = getpwuid_r(getuid(), &pw, buf, buf_size, &p);
	else
		result = 0;

	/* fall back to HOME env variable */

	path = result ? pw.pw_dir : getenv("HOME");

	result = asprintf(user_config, "%s/.%s.conf", path, app_name);

	free(buf);

	if (result == -1) {
		fprintf(stderr, "%s: asprintf failed\n", app_name);
		return result;
	}

	return 0;
}

static int fill_from_config_file(const char* config_file, struct ss_info *ssi,
	struct login_info *lii, struct fp_info *fpi, struct vpn *vpn)
{
	int result;
	struct config_file_data cfd;

	memset(&cfd, 0, sizeof(cfd));

	result = config_file_data_read(&cfd, config_file);

	if (result) {
		if (verbosity(2))
			printf("%s: parse '%s' failed.\n", app_name,
				config_file);
		return -1;
	}

	if (!ssi->certificate) {
		ssi->certificate = cfd.certificate;
		cfd.certificate = NULL;
	}
	if (!fpi->favorite_id) {
		fpi->favorite_id = cfd.favorite_id;
		cfd.favorite_id = NULL;
	}
	if (!ssi->host) {
		ssi->host = cfd.host;
		cfd.host = NULL;
	}
	if (!lii->auth_format) {
		lii->auth_format = cfd.auth_format;
		cfd.auth_format = NULL;
	}
	if (!vpn->dns.nameserver) {
		vpn->dns.nameserver = cfd.nameserver;
		cfd.nameserver = NULL;
	}
	if (!vpn->route.dest) {
		route_from_prefix(&vpn->route, cfd.network);
		cfd.network = NULL;
	}
	if (!ssi->port) {
		ssi->port = cfd.port;
		cfd.port = NULL;
	}
	if (!lii->user) {
		lii->user = cfd.user;
		cfd.user = NULL;
	}

	config_file_data_clean(&cfd);

	return 0;
}

/**
 * get_user_prefs - Get user's prefs.
 *
 * Tries to get the info from these sources:
 *   1) From command line opts.
 *   2) From a command line config file.
 *   3) From the user's config file.
 *   4) From the system config file.
 *   5) Program defaults.
 *   6) Prompt user.
 */

static int get_user_prefs(const struct opts *opts, struct ss_info *ssi,
	struct login_info *lii, struct fp_info *fpi, struct vpn *vpn)
{
	int result;

	assert(ssi);
	assert(lii);
	assert(!ssi->host);
	assert(!lii->user);

	/* First use opts on command line. */

	if (opts->certificate)
		ssi->certificate = strdup(opts->certificate);
	if (opts->favorite_id)
		fpi->favorite_id = strdup(opts->favorite_id);
	if (opts->host)
		ssi->host = strdup(opts->host);
	if (opts->auth_format)
		lii->auth_format = strdup(opts->auth_format);
	if (opts->nameserver)
		vpn->dns.nameserver = strdup(opts->nameserver);
	if (opts->network)
		route_from_prefix(&vpn->route, opts->network);
	if (opts->port)
		ssi->port = strdup(opts->port);
	if (opts->user)
		lii->user = strdup(opts->user);

	/* Next use opts->config or user config and system config. */

	if (opts->config) {
		result = fill_from_config_file(opts->config, ssi, lii, fpi,
			vpn);

		if (result) {
			fprintf(stderr, "%s: fill_from_config_file failed\n",
				app_name);
			goto fail;
		}
	} else {
		char *file;

		/* user config */

		result = get_user_config_file(&file);

		if (result) {
			fprintf(stderr, "%s: get_user_config_file failed\n",
				app_name);
			goto fail;
		}

		fill_from_config_file(file, ssi, lii, fpi, vpn);

		free(file);

		/* system config */

		result = asprintf(&file, "/etc/.%s.conf", app_name);

		if (result == -1) {
			fprintf(stderr, "%s: asprintf failed\n", app_name);
			goto fail;
		}

		fill_from_config_file(file, ssi, lii, fpi, vpn);

		free(file);
	}

	/* Then use program defaults. */

	if (!lii->auth_format)
		lii->auth_format = strdup(default_values.auth_format);

	if (!fpi->favorite_id)
		fpi->favorite_id = strdup(default_values.favorite_id);

	if (!ssi->port)
		ssi->port = strdup(default_values.port);

	/* Finally prompt user. */

	if (!ssi->certificate) {
		result = prompt_user("certificate: ", echo_on, stdin,
			&ssi->certificate);
		if (result)
			goto fail;
	} else if (verbosity(1))
		printf("certificate: %s\n", ssi->certificate);

	if (verbosity(1))
		printf("favorite-id: %s\n", fpi->favorite_id);

	if (!ssi->host) {
		result = prompt_user("host: ", echo_on, stdin, &ssi->host);
		if (result)
			goto fail;
	} else if (verbosity(1))
		printf("host: %s:%s\n", ssi->host, ssi->port);

	if (verbosity(1))
		printf("auth-format: %s\n", lii->auth_format);

	if (!vpn->dns.nameserver) {
		result = prompt_user("nameserver: ", echo_on, stdin,
			&vpn->dns.nameserver);
		if (result)
			goto fail;
	} else if (verbosity(1))
		printf("nameserver: %s\n", vpn->dns.nameserver);

	if (!vpn->route.dest) {
		char *network = NULL;

		result = prompt_user("network: ", echo_on, stdin,
			&network);
		if (result)
			goto fail;
		result = route_from_prefix(&vpn->route, network);
		free(network);
		if (result)
			goto fail;
	} else if (verbosity(1))
		printf("network: %s:%s\n", vpn->route.dest, vpn->route.mask);

	if (!lii->user) {
		result = prompt_user("user: ", echo_on, stdin, &lii->user);
		if (result)
			goto fail;
	} else if (verbosity(1))
		printf("user: %s\n", lii->user);

	result = prompt_user("password: ", echo_off, stdin, &lii->pw);

	if (result)
		goto fail;

	result = prompt_user("token: ", echo_off, stdin,  &lii->token);

	if (result)
		goto fail;

	return 0;

fail:
	login_info_clean(lii);
	return result;
}

static void ss_destroy(struct ss_info *ssi)
{
	SSL_CTX_free(ssi->ctx);
	ssi->ctx = NULL;
	ERR_free_strings();
	ss_info_clean(ssi);
}

static int ss_init(struct ss_info *ssi)
{
	int result;

	assert(!ssi->ctx);

	result =  SSL_library_init();

	if (!result) {
		fprintf(stderr, "%s:%d: SSL_library_init failed.\n", __func__,
			__LINE__);
		return -1;
	}

	SSL_load_error_strings();

	ssi->ctx = SSL_CTX_new(TLSv1_client_method());

	if (!ssi->ctx) {
		fprintf(stderr, "%s:%d: SSL_CTX_new failed.\n", __func__,
			__LINE__);
		result = -1;
		goto fail;
	}

	SSL_CTX_set_mode(ssi->ctx, SSL_MODE_AUTO_RETRY);

	//result = SSL_CTX_load_verify_locations(ssi->ctx, ssi->certificate, NULL);

	result = SSL_CTX_use_certificate_file(ssi->ctx, ssi->certificate,
		SSL_FILETYPE_PEM);

	if (0 && !result) {
		fprintf(stderr, "%s:%d: SSL_CTX_use_certificate_file failed.\n",
			__func__, __LINE__);
		result = -1;
		//goto fail; !!!
	}

	SSL_CTX_set_verify_depth(ssi->ctx, 1);

	return 0;

fail:
	ss_destroy(ssi);
	return result;
}

static int ss_connect(struct ss_info *ssi)
{
	int result;
	X509 *cert;

	assert(ssi->ctx);
	assert(ssi->host);
	assert(ssi->port);

	assert(!ssi->ssl);
	assert(!ssi->bio);

	ssi->bio = BIO_new_connect(ssi->host);

	if (!ssi->bio) {
		fprintf(stderr, "%s:%d: BIO_new_connect failed.\n", __func__,
			__LINE__);
		goto fail;
	}

	BIO_set_conn_port(ssi->bio, ssi->port);

	result = BIO_do_connect(ssi->bio);

	if (result <= 0) {
		fprintf(stderr, "%s:%d: BIO_do_connect failed.\n", __func__,
			__LINE__);
		goto fail;
	}

	ssi->ssl = SSL_new(ssi->ctx);

	if (!ssi->ssl) {
		fprintf(stderr, "%s:%d: SSL_new failed.\n", __func__, __LINE__);
		goto fail;
	}

	SSL_set_bio(ssi->ssl, ssi->bio, ssi->bio);

	if (ssi->session)
		SSL_set_session(ssi->ssl, ssi->session);

	SSL_set_connect_state(ssi->ssl);

	result = SSL_connect(ssi->ssl);

	if (result <= 0) {
		fprintf(stderr, "%s:%d: SSL_connect failed.\n", __func__,
			__LINE__);
		goto fail;
	}

	cert = SSL_get_peer_certificate(ssi->ssl);
	X509_free(cert);

	if (!cert) {
		fprintf(stderr, "%s:%d: SSL_get_peer_certificate failed.\n",
			__func__, __LINE__);
		goto fail;
	}

	result = SSL_get_verify_result(ssi->ssl);

	if (0 && result != X509_V_OK) {
		fprintf(stderr, "%s:%d: SSL_get_verify_result failed (%u).\n",
			__func__, __LINE__, result);
		//goto fail; !!!
	}

	return 0;

fail:
	ERR_print_errors_fp(stderr);

	SSL_SESSION_free(ssi->session);

	if (!ssi->ssl)
		BIO_free(ssi->bio);
	else {
		SSL_clear(ssi->ssl);
		SSL_free(ssi->ssl); /* frees bio */
	}

	ssi->session = NULL;
	ssi->ssl = NULL;
	ssi->bio = NULL;

	return result;
}

static void ss_close(struct ss_info *ssi)
{
	if (!SSL_shutdown(ssi->ssl)) {
		DBGS("SSL_shutdown retry.\n");
		SSL_shutdown(ssi->ssl);
	}

	ERR_print_errors_fp(stderr);

	SSL_SESSION_free(ssi->session);

	if (!ssi->ssl)
		BIO_free(ssi->bio);
	else {
		SSL_clear(ssi->ssl);
		SSL_free(ssi->ssl); /* frees bio */
	}

	ssi->session = NULL;
	ssi->ssl = NULL;
	ssi->bio = NULL;
}

static int ss_send_page(struct ss_info *ssi, const char *out, int out_len,
	char *in, int in_size, enum echo_state echo, int *in_bytes)
{
	int result;
	int e;

	assert(out_len > 0);

	result = ss_connect(ssi);

	if (result) {
		DBGS("connect failed.\n");
		return result;
	}

	print_io_header(out, out_len, echo);

	result = SSL_write(ssi->ssl, out, out_len);

	if (result < out_len) {
		int e = SSL_get_error(ssi->ssl, result);

		DBGS("SSL_write err: %d:%d\n", result, e);
		if (verbosity(1)) {
			fprintf(stderr, "%s:%d: SSL_write failed.\n", __func__,
				__LINE__);
			ERR_print_errors_fp(stderr);
		}
		ss_close(ssi);
		return -1;
	}

	assert(result == out_len);

	*in_bytes = 0;

	while (1) {
		result = SSL_read(ssi->ssl, in + *in_bytes, in_size
			- *in_bytes);

		if (result <= 0) {
			e = SSL_get_error(ssi->ssl, result);
			if (e == SSL_ERROR_SYSCALL && *in_bytes == in_size) {
				//DBGS("buff full\n");
				*in_bytes = 0;
				continue;
			}
			break;
		}

		*in_bytes += result;
		//DBGS("read: %d:%d\n", *in_bytes, result);
	}

	if (*in_bytes > 0) {
		in[*in_bytes < in_size ? *in_bytes : in_size - 1] = 0;
		print_io_trailer(in, *in_bytes, echo_on);
	}

	switch (e) {
	case SSL_ERROR_ZERO_RETURN:
		ssi->session = ssi->session ? SSL_get0_session(ssi->ssl)
			: SSL_get1_session(ssi->ssl);
		assert(ssi->session);
		result = 0;
		break;
	default:
		DBGS("SSL_read err: %d:%d\n", result, e);
		if (verbosity(1)) {
			fprintf(stderr, "%s:%d: SSL_read failed.\n", __func__,
				__LINE__);
			ERR_print_errors_fp(stderr);
		}
		result = -1;
		break;
	};

	ss_close(ssi);
	return result;
}

static int format_auth_page(const struct ss_info *ssi,
	const struct login_info *lii, char **page)
{
	char *data = 0;
	int data_len;
	int page_len;

	assert(ssi);
	assert(ssi->host);

	assert(lii);
	assert(lii->auth_format);
	assert(lii->user);
	assert(lii->pw);

	// FIXME: is asprintf safe on error???

	if (!strcmp(lii->auth_format, "U:P")) {
		data_len = asprintf(&data,
			"username=%s&password=%s&mrhlogonform=1",
			lii->user, lii->pw);
	} else if (!strcmp(lii->auth_format, "U:PT")) {
		data_len = asprintf(&data,
			"username=%s&password=%s%s&mrhlogonform=1",
			lii->user, lii->pw, lii->token);
	} else if (!strcmp(lii->auth_format, "U:P,T")) {
		data_len = asprintf(&data,
			"username=%s&password=%s,%s&mrhlogonform=1",
			lii->user, lii->pw, lii->token);
	} else if (!strcmp(lii->auth_format, "UT:P")) {
		data_len = asprintf(&data,
			"username=%s%s&password=%s&mrhlogonform=1",
			lii->user, lii->token, lii->pw);
	} else if (!strcmp(lii->auth_format, "U,T:P")) {
		data_len = asprintf(&data,
			"username=%s,%s&password=%s&mrhlogonform=1",
			lii->user, lii->token, lii->pw);
	} else {
		assert(0 && "unknown auth_format");
		fprintf(stderr, "%s:%d: unknown auth_format '%s'\n", __func__,
			__LINE__, lii->auth_format);
		return -1;
	}

	if (data_len <= 0)
		return -1;

	page_len = asprintf(page,
		"POST /my.activation.php3 HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"Content-Length: %u\r\n"
		"Connection: close\r\n"
		"\r\n"
		"%s\r\n", ssi->host, data_len, data);

	// DANGER: This will echo password.
	// DBGS("page @%s@\n", *page);

	memset(data, 0, data_len);
	return page_len;
}

static int get_session_id(struct ss_info *ssi, struct fp_info *fpi,
	const struct login_info *lii)
{
	int result;
	char *auth;
	int auth_len;
	char buf[16 * 1024];
	int buf_bytes;

	assert(fpi);
	assert(!fpi->session_id);

	auth_len = format_auth_page(ssi, lii, &auth);

	if (auth_len <= 0) {
		fprintf(stderr, "%s:%d: format_auth_page failed.\n",
			__func__, __LINE__);
		return -1;
	}

	if (verbosity(1)) {
		char *tmp;

		if (lii->pw)
			memset(lii->pw, '*', strlen(lii->pw));
		if (lii->token)
			memset(lii->token, '*', strlen(lii->token));
		format_auth_page(ssi, lii, &tmp);
		print_io_header(tmp, auth_len, echo_on);
		memset(tmp, 0, auth_len);
		free(tmp);
	}

	result = ss_send_page(ssi, auth, auth_len, buf, sizeof(buf),
		echo_off, &buf_bytes);

	memset(auth, 0, auth_len);
	free(auth);
	auth = NULL;

	if (result) {
		fprintf(stderr, "%s: check host name and/or port values.\n",
			app_name);
		return -1;
	}

	fpi->session_id = find_key_item("Set-Cookie: MRHSession", buf);

	memset(buf, 0, sizeof(buf));

	if (!fpi->session_id || !strcmp(fpi->session_id, "")) {
		fprintf(stderr, "%s: session_id not found.\n", app_name);
		free(fpi->session_id);
		fpi->session_id = NULL;
		return -1;
	}

	if (!strcmp(fpi->session_id, "deleted")) {
		fprintf(stderr, "%s: session_id deleted, check login "
			"credentials.\n", app_name);
		return -1;
	}

	return 0;
}

/**
 * vpn_setup - Server setup for making the VPN connection.
 */

static int vpn_setup(struct ss_info *ssi, struct fp_info *fpi)
{
	int result;
	char *page = NULL;
	int page_len;
	char buf[16 * 1024];
	int buf_bytes;

	page_len = asprintf(&page,
		"GET /vdesk/vpn/index.php3?outform=xml HTTP/1.0\r\n"
		"Cookie: MRHSession=%s\r\n"
		"\r\n", fpi->session_id);

	result = ss_send_page(ssi, page, page_len, buf, sizeof(buf),
		echo_on, &buf_bytes);

	if (result) {
		fprintf(stderr, "%s:%d: GET vpn index failed.\n", __func__,
			__LINE__);
		result = 1;
		goto done;
	}

	// FIXME: parse page to check for favorite_id here.
	// FIXME: add option favorite_name and parse for favorite_id.

	free(page);
	page = NULL;

	page_len = asprintf(&page,
		"GET /vdesk/ HTTP/1.00\r\n"
		"Cookie: MRHSession=%s\r\n"
		"\r\n", fpi->session_id);

	result = ss_send_page(ssi, page, page_len, buf, sizeof(buf), echo_on,
		&buf_bytes);

	if (result) {
		fprintf(stderr, "%s:%d: GET vdesk failed.\n", __func__,
			__LINE__);
		result = 1;
		goto done;
	}

	free(page);
	page = NULL;

	page_len = asprintf(&page,
		"GET /vdesk/vpn/connect.php3?%s HTTP/1.0\r\n"
		"Cookie: MRHSession=%s\r\n"
		"\r\n", fpi->favorite_id, fpi->session_id);

	result = ss_send_page(ssi, page, page_len, buf, sizeof(buf), echo_on,
		&buf_bytes);

	if (result) {
		fprintf(stderr, "%s:%d: vpn connect failed.\n", __func__,
			__LINE__);
		result = 1;
		goto done;
	}

done:
	memset(page, 0, page_len);
	free(page);

	return result;
}

/**
 * vpn_connect - Create the VPN connection.
 *
 * Creates an ssl encrypted ppp connection to the fp server.
 */

static int vpn_connect(struct ss_info *ssi, struct fp_info *fpi, pid_t *pppd,
	int *pppd_stdout)
{
	int result;
	char *pty;
	char *connect;
	int pfd[2];

	*pppd = -1;
	*pppd_stdout = -1;

	result = asprintf(&pty,  "%s s_client %s -ign_eof -connect %s:%s",
		sys_path.ssl, (verbosity(2) ? "" : "-quiet"),
		ssi->host, ssi->port);

	if (result < 0) {
		fprintf(stderr, "%s:%d: asprintf pty failed.\n", __func__,
			__LINE__);
		perror(app_name);
		goto done;
	}

	result = asprintf(&connect,  "%s %s'' '"
		"GET /myvpn?sess=%s HTTP/1.0\r\n"
		"Cookie: MRHSession=%s\r\n"
		"\r\n"
		"'",
		sys_path.chat, (verbosity(3) ? "-v -s -S " : ""),
		fpi->session_id, fpi->session_id);

	if (result < 0) {
		fprintf(stderr, "%s:%d: asprintf connect failed.\n", __func__,
			__LINE__);
		perror(app_name);
		goto done;
	}

	result = pipe(pfd);

	if (result) {
		fprintf(stderr, "%s:%d: pipe failed.\n", __func__,
			__LINE__);
		perror(app_name);
		goto done;
	}

	if (verbosity(3)) {
		DBGS("connect @%s@\n", connect);
		DBGS("pty @%s@\n", pty);
	}

	*pppd = fork();

	if (!*pppd) {
		close(pfd[0]);

		result = dup2(pfd[1], STDOUT_FILENO);

		if (result != STDOUT_FILENO) {
			fprintf(stderr, "%s:%d: dup2 failed.\n", __func__,
				__LINE__);
			perror(app_name);
		}

		close(pfd[1]);

		result = setuid(0);

		if (result) {
			fprintf(stderr, "%s:%d: setuid failed.\n", __func__,
				__LINE__);
			perror(app_name);
		}

		result = execl(sys_path.pppd, sys_path.pppd,
			"record", "/dev/null", // FIXME: needed this for mac
			"noauth",
			"nodefaultroute",
			"nodetach",
			"lcp-echo-interval", "60",
			"novj",
			"pty", pty,
			"connect", connect,
			NULL);

		fprintf(stderr, "%s:%d: exec pppd failed.\n", __func__,
			__LINE__);
		perror(app_name);

		str_clean(pty);
		str_clean(connect);

		_exit(EXIT_FAILURE);
	}

	close(pfd[1]);

	if (*pppd < 0) {
		fprintf(stderr, "%s:%d: fork failed.\n", __func__, __LINE__);
		perror(app_name);
		result = -1;
		close(pfd[0]);
		goto done;
	}

	result = 0;
	*pppd_stdout = pfd[0];

done:
	str_clean(pty);
	str_clean(connect);

	return result;
}

/**
 * parse_pppd - Helper to parse output of pppd.
 */

static char *parse_pppd(const char *str, const char *header)
{
	const char *start;
	const char *end;
	char *p;

	start = strstr(str, header);

	if (!start) {
		DBGS("find failed: '%s'\n", header);
		return NULL;
	}

	start += strlen(header);

	end = strchr(start, '\n');

	if (!end) {
		DBGS("find end failed: '%s'\n", header);
		return NULL;
	}

	p = malloc(end - start + 1);

	if (!p) {
		DBGS("malloc failed\n");
		return NULL;
	}

	memcpy(p, start, end - start);
	p[end - start] = 0;

	return p;
}

/**
 * get_pppd_info - Get route info from pppd.
 *
 * Loops waiting for pppd to print the remote gateway IP address.
 */

static int get_pppd_info(pid_t pppd, int pppd_stdout, struct route *route)
{
	int result;
	char buf[1024];
	int bytes = 0;
	char *device;
	char *local;

	assert(pppd);
	assert(pppd_stdout);
	assert(!route->gw);

	while (1) {
		sleep(3);

		if (global_abort) {
			if (verbosity(1))
				fprintf(stderr, "%s: user abort.\n", app_name);
			return -1;
		}

		/* check if pppd is still running. */

		result = waitpid(pppd, NULL, WNOHANG);

		if (result) {
			fprintf(stderr, "%s: pppd failed, check privileges.\n",
				app_name);
			return -1;
		}

		result = read(pppd_stdout, buf + bytes, sizeof(buf) - bytes);

		if (result < 0) {
			DBGS("pppd_stdout error.\n");
			return -1;
		}

		//write(STDOUT_FILENO, "@", 1);
		//write(STDOUT_FILENO, buf, result);
		//write(STDOUT_FILENO, "@", 1);

		bytes += result;
		buf[bytes] = '\n';
		buf[bytes + 1] = 0;

		device = parse_pppd(buf, "Using interface ");
		local = parse_pppd(buf, "local  IP address ");
		route->gw = parse_pppd(buf, "remote IP address ");

		if (route->gw)
			break;

		free(device);
		free(local);
		free(route->gw);
		route->gw = NULL;

		if (verbosity(2))
			fprintf(stderr, "%s: waiting for ppp device.\n",
				app_name);
	}

	if (verbosity(3))
		fprintf(stderr, "%s\n", buf);

	if (verbosity(2)) {
		fprintf(stderr, "%s: Using interface %s\n",
			app_name, device);
		fprintf(stderr, "%s: local  IP address %s\n",
			app_name, local);
		fprintf(stderr, "%s: remote IP address %s\n",
			app_name, route->gw);
	}

	free(device);
	free(local);
	return 0;
}

static void sig_handler(int signo)
{
	(void)signo;
	global_abort = 1;
}

int main(int argc, char *argv[])
{
	int result;
	static struct opts opts;
	static struct login_info lii;
	static struct fp_info fpi;
	static struct ss_info ssi;
	static struct vpn vpn;
	static struct sigaction sa;
	pid_t pppd;
	int pppd_stdout;

	sa.sa_handler = sig_handler,
	result = sigaction(SIGINT, &sa, NULL);
	result += sigaction(SIGHUP, &sa, NULL);
	result += sigaction(SIGTERM, &sa, NULL);

	if (result) {
		fprintf(stderr, "%s:%d: sigaction failed.\n", __func__,
			__LINE__);
		exit(1);
	}

	result = opts_parse(&opts, argc, argv);

	if (result) {
		print_usage();
		DBGS("failed.\n");
		exit(1);
	}

	_verbosity = opts.verbosity;

	if (opts.show_help) {
		print_usage();
		exit(0);
	}

	if (opts.show_version) {
		print_version();
		exit(0);
	}

	result = get_user_prefs(&opts, &ssi, &lii, &fpi, &vpn);

	if (result) {
		if (verbosity(2))
			fprintf(stderr, "%s: get_user_prefs failed.\n",
				app_name);
		result = 1;
		goto done;
	}

	if (verbosity(2))
		printf("%s: get_user_prefs OK\n", app_name);

	result = ss_init(&ssi);

	if (result) {
		fprintf(stderr, "%s: ss_init failed.\n", app_name);
		result = 1;
		goto done;
	}

	if (verbosity(1))
		printf("%s: connecting...\n", app_name);

	result = get_session_id(&ssi, &fpi, &lii);

	if (result) {
		if (verbosity(1))
			fprintf(stderr, "%s: get_session_id failed.\n",
				app_name);
		result = 1;
		goto done;
	}

	if (verbosity(2))
		printf("%s: get_session_id OK\n", app_name);

	login_info_clean(&lii);

	result = vpn_setup(&ssi, &fpi);

	if (result) {
		fprintf(stderr, "%s: vpn_setup failed.\n", app_name);
		result = 1;
		goto done;
	}

	if (verbosity(2))
		printf("%s: vpn_setup OK\n", app_name);

	if (verbosity(1))
		printf("%s: starting VPN...\n", app_name);

	result = vpn_connect(&ssi, &fpi, &pppd, &pppd_stdout);

	if (result) {
		fprintf(stderr, "%s: vpn_connect failed.\n", app_name);
		result = 1;
		goto done;
	}

	result = get_pppd_info(pppd, pppd_stdout, &vpn.route);

	if (result)
		fprintf(stderr, "%s: get_pppd_info failed.\n", app_name);

	result = route_add(&vpn.route);

	if (result)
		fprintf(stderr, "%s: route_add failed.\n", app_name);

	if (verbosity(2)) {
		printf("%s: vpn_connect OK\n", app_name);
	}

	vpn.dns.resolver = sys_path.resolver;

	result = dns_update(&vpn.dns);

	if (result)
		fprintf(stderr, "%s: dns_update failed.\n", app_name);
	else if (verbosity(2))
		printf("%s: dns_update OK\n", app_name);

	printf("%s: VPN connected, press ^C to disconnect.\n", app_name);

	result = waitpid(pppd, NULL, 0);

	printf("\n");
	fflush(stdout);

	if (verbosity(1)) {
		if (result != pppd)
			perror(app_name);
		printf("%s: VPN disconnected.\n", app_name);
	}

	dns_restore(&vpn.dns);
	route_delete(&vpn.route);

	fflush(stdout);
	fflush(stderr);
	sleep(2);
	sleep(2);

done:
	login_info_clean(&lii);
	fp_info_clean(&fpi);
	ss_destroy(&ssi);

	if (verbosity(1))
		printf("%s: done.\n", app_name);
	return !!result;
}
