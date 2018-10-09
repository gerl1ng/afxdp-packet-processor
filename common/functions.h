// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <linux/if_xdp.h>

/* This file contains the functions executed 
 * by the serverless framework. Please note that
 * the headers are already swapped. If a function
 * returns true, a packet will be sent with the 
 * content of pkt. If the application wants to 
 * use UDP Checksums, it can calculate them on their
 * own CPU time.
 */

typedef bool (*function)();

// Function 1232 reverses the content of the message
bool func_1232_reverseContent(
		char *pkt, unsigned int *length,
		const unsigned int header_length)
{	
	const int iterations = (*length - header_length) >> 1;
	char c = 0;
	for ( int i = 0; i < iterations; i++ ) {
		c = pkt[header_length + i];
		pkt[header_length + i] = pkt[*length -1 - i];
		pkt[*length -1 - i] = c;
	}
	return true;
}

function get_function(const unsigned int port)
{
	switch(port) {
	case 1232:
		return func_1232_reverseContent;
		break;
	default:
		return NULL;
		break;
	}
	return NULL;
}
