/*
 *  Firepass VPN login client.
 *
 *  Copyright 2008 Geoff Levand
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License, Version 2 as
 *  published by the Free Software Foundation.
 */

#if defined(DEBUG)
#define DBG(_args...) do {fprintf(stderr, _args); fflush(stderr);} while(0)
#else
static inline int __attribute__ ((format (printf, 1, 2))) DBG(
	__attribute__((unused)) const char *fmt, ...) {return 0;}
#endif
#define DBGS(fmt, args...) DBG("%s:%d: " fmt, __func__, __LINE__, ## args)

extern const char app_name[];

/**
 * struct dns - DNS resolver info.
 * @nameserver: New name server IP string.
 * @resolver: Resolver config file.
 * @old_resolver: Dynamic buffer to hold old resolver config.
 * @old_resolver_size: Size of @old_resolver.
 */

struct dns {
	char *nameserver;
	const char *resolver;
	void *old_resolver;
	long old_resolver_size;
};

int dns_update(struct dns *dns);
int dns_restore(struct dns *dns);
