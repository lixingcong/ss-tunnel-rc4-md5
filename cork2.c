/*
 * cork2.cpp
 *
 * FIXME: 功能简要概述
 *
 * Created on: 2024年 12月 2日
 *
 * Author: lixingcong
 */

#include "cork2.h"

#include <stdio.h>
#include <endian.h>

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

#ifndef bool
#define bool int
#endif

static inline const char* cork_ipv4_parse(const char* str)
{
	const char*  ch                  = 0;
	bool         seen_digit_in_octet = false;
	unsigned int octets              = 0;
	unsigned int digit               = 0;

// #define PRINT_4_DIGITS
#ifdef PRINT_4_DIGITS
	unsigned char result[4]; // 输出四位数
#endif

	for (ch = str; *ch != '\0'; ch++) {
		if ('0' <= *ch && '9' >= *ch) {
			seen_digit_in_octet = true;
			digit *= 10;
			digit += (*ch - '0');
			if (digit > 255)
				goto parse_error;
		} else if ('.' == *ch) {
			/* If this would be the fourth octet, it can't have a trailing
                 * period. */
			if (octets == 3) {
				goto parse_error;
			}
#ifdef PRINT_4_DIGITS
			result[octets] = digit;
#endif
			digit = 0;
			octets++;
			seen_digit_in_octet = false;
		} else
			goto parse_error; /* Any other character is a parse error. */
	}

	if (seen_digit_in_octet && octets == 3) {
#ifdef PRINT_4_DIGITS
		result[octets] = digit;
#endif
		return ch;
	}

parse_error:
	return 0;
}

static bool cork_ipv6_init(const char *str)
{
	const char *ch;

	unsigned short  digit        = 0;
	unsigned int    before_count = 0;
	unsigned short  before_double_colon[8];
	unsigned short  after_double_colon[8];
	unsigned short *dest = before_double_colon;

	unsigned int digits_seen          = 0;
	unsigned int hextets_seen         = 0;
	bool         another_required     = true;
	bool         digit_allowed        = true;
	bool         colon_allowed        = true;
	bool         double_colon_allowed = true;
	bool         just_saw_colon       = false;

	for (ch = str; *ch != '\0'; ch++) {
		switch (*ch) {
#define process_digit(base) \
			/* Make sure a digit is allowed here. */ \
			    if (!digit_allowed) { \
				    goto parse_error; \
			} \
			    /* If we've already seen 4 digits, it's a parse error. */ \
			    if (digits_seen == 4) { \
				    goto parse_error; \
			} \
\
			    digits_seen++; \
			    colon_allowed  = true; \
			    just_saw_colon = false; \
			    digit <<= 4; \
			    digit |= (*ch - (base)); \

		    case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			process_digit('0');
			break;

		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
			process_digit('a' - 10);
			break;

		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
			process_digit('A' - 10);
			break;

#undef process_digit

		case ':':
			/* We can only see a colon immediately after a hextet or as part
                 * of a double-colon. */
			if (!colon_allowed) {
				goto parse_error;
			}

			/* If this is a double-colon, start parsing hextets into our
                 * second array. */
			if (just_saw_colon) {
				colon_allowed        = false;
				digit_allowed        = true;
				another_required     = false;
				double_colon_allowed = false;
				before_count         = hextets_seen;
				dest                 = after_double_colon;
				continue;
			}

			/* If this would end the eighth hextet (regardless of the
                 * placement of a double-colon), then there can't be a trailing
                 * colon. */
			if (hextets_seen == 8) {
				goto parse_error;
			}

			/* If this is the very beginning of the string, then we can only
                 * have a double-colon, not a single colon. */
			if (digits_seen == 0 && hextets_seen == 0) {
				colon_allowed    = true;
				digit_allowed    = false;
				just_saw_colon   = true;
				another_required = true;
				continue;
			}

			/* Otherwise this ends the current hextet. */
			*(dest++) = htobe16(digit);
			digit     = 0;
			hextets_seen++;
			digits_seen      = 0;
			colon_allowed    = double_colon_allowed;
			just_saw_colon   = true;
			another_required = true;
			break;

		case '.': {
			/* If we see a period, then we must be in the middle of an IPv4
                 * address at the end of the IPv6 address. */

			/* Ensure that we have space for the two hextets that the IPv4
                 * address will take up. */
			if (hextets_seen >= 7) {
				goto parse_error;
			}

			/* Parse the IPv4 address directly into our current hextet
                 * buffer. */
			ch = cork_ipv4_parse(ch - digits_seen);
			if (ch){
				hextets_seen += 2;
				digits_seen      = 0;
				another_required = false;

				/* ch now points at the NUL terminator, but we're about to
                     * increment ch. */
				ch--;
				break;
			}

			/* The IPv4 parse failed, so we have an IPv6 parse error. */
			goto parse_error;
		}

		default:
			/* Any other character is a parse error. */
			goto parse_error;
		}
	}

	/* If we have a valid hextet at the end, and we've either seen a
     * double-colon, or we have eight hextets in total, then we've got a valid
     * final parse. */
	if (digits_seen > 0) {
		/* If there are trailing digits that would form a ninth hextet
         * (regardless of the placement of a double-colon), then we have a parse
         * error. */
		if (hextets_seen == 8) {
			goto parse_error;
		}

		*(dest++) = htobe16(digit);
		hextets_seen++;
	} else if (another_required) {
		goto parse_error;
	}

	if (!double_colon_allowed) {
		/* We've seen a double-colon, so use 0000 for any hextets that weren't present */
		//unsigned int after_count = hextets_seen - before_count;
		return true;
	} else if (hextets_seen == 8) {
		/* No double-colon, so we must have exactly eight hextets. */
		return true;
	}

parse_error:
	return false;
}

int cork_check_ip_version(const char* str)
{
	if (cork_ipv4_parse(str))
		return 4;
	if (cork_ipv6_init(str))
		return 6;
	return -1; // invalid
}
