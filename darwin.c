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
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>

#include "platform.h"

int dns_restore(struct dns *dns)
{
	return -1;
}

int dns_update(struct dns *dns)
{
	int result = 0;
	CFMutableDictionaryRef dict = NULL;
	CFMutableArrayRef array = NULL;
	CFStringRef string = NULL;

	dict = CFDictionaryCreateMutable(NULL, 0,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks);

	if(!dict) {
		fprintf(stderr, "%s: CFDictionaryCreateMutable failed.\n",
			app_name);
		result = -1;
		goto done;
	}

	array = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);

	if(!array) {
		fprintf(stderr, "%s: CFArrayCreateMutable failed.\n", app_name);
		result = -1;
		goto done;
	}

	string = CFStringCreateWithCString(NULL, dns->nameserver,
		kCFStringEncodingASCII);

	if(!string) {
		fprintf(stderr, "%s: CFStringCreateWithCString failed.\n",
			app_name);
		result = -1;
		goto done;
	}

	CFArrayAppendValue(array, string);

	CFDictionaryAddValue(dict, kSCPropNetDNSServerAddresses, array);
	//CFDictionarySetValue(dict, kSCPropNetDNSServerAddresses, array);

done:
	CFRelease(string);
	CFRelease(array);
	CFRelease(dict);

	return result;
}
