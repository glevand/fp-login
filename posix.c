/*
 *  Firepass VPN login client.
 *
 *  Copyright 2008 Geoff Levand
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License, Version 2 as
 *  published by the Free Software Foundation.
 */

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "platform.h"

int dns_restore(struct dns *dns)
{
	int result;
	FILE *stream;

	assert(dns->old_resolver);
	assert(dns->old_resolver_size);

	stream = fopen(dns->resolver, "w");

	if (!stream) {
		fprintf(stderr, "%s: fopen %s failed\n", app_name, dns->resolver);
		perror(app_name);
		/* just fall through to write */
	}

	result = fwrite(dns->old_resolver, dns->old_resolver_size, 1, stream);

	fclose(stream);

	free(dns->old_resolver);
	dns->old_resolver = NULL;
	dns->old_resolver_size = 0;

	if (result != 1) {
		perror(app_name);
		return -1;
	}

	return 0;
}

int dns_update(struct dns *dns)
{
	int result;
	FILE *stream;

	dns->old_resolver = NULL;
	dns->old_resolver_size = 0;

	stream = fopen(dns->resolver, "r+");

	if (!stream) {
		fprintf(stderr, "%s: fopen %s failed\n", app_name,
			dns->resolver);
		perror(app_name);
		goto fail;
	}

	result = fseek(stream, 0, SEEK_END);

	if (result) {
		perror(app_name);
		goto fail;
	}

	dns->old_resolver_size = ftell(stream);
	dns->old_resolver = malloc(dns->old_resolver_size);

	if (!dns->old_resolver) {
		perror(app_name);
		goto fail;
	}

	rewind(stream);

	result = fread(dns->old_resolver, dns->old_resolver_size, 1, stream);

	if (result != 1) {
		perror(app_name);
		goto fail;
	}

	rewind(stream);

	result = fprintf(stream, "# --- %s\n", app_name);

	if (result < 0) {
		perror(app_name);
		goto fail;
	}

	fprintf(stream, "nameserver %s\n", dns->nameserver);
	fprintf(stream, "# --- %s\n", app_name);
	fwrite(dns->old_resolver, dns->old_resolver_size, 1, stream);
	fclose(stream);

	return 0;

fail:
	fprintf(stderr, "%s: dns_update failed\n", app_name);
	fclose(stream);
	free(dns->old_resolver);
	dns->old_resolver = NULL;
	dns->old_resolver_size = 0;
	return -1;
}
