
#line 1 "base64.rl"
/*
 * Copyright (c) 2009-2011, Adrian Thurston <thurston@complang.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


#include "dsnp.h"
#include "error.h"
#include <string.h>

Allocated binToBase64( const u_char *data, long len )
{
	const char *index = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	long group;

	long lenRem = len % 3;
	long lenEven = len - lenRem;
	long allocLen = ( lenEven / 3 ) * 4 + ( lenRem > 0 ? 4 : 0 ) + 1;

	char *output = new char[allocLen];
	char *dest = output;

	for ( int i = 0; i < lenEven; i += 3 ) {
		group = (long)data[i] << 16;
		group |= (long)data[i+1] << 8;
		group |= (long)data[i+2];

		*dest++ = index[( group >> 18 ) & 0x3f];
		*dest++ = index[( group >> 12 ) & 0x3f];
		*dest++ = index[( group >> 6 ) & 0x3f];
		*dest++ = index[group & 0x3f];
	}

	if ( lenRem > 0 ) {
		group = (long)data[lenEven] << 16;
		if ( lenRem > 1 )
			group |= (long)data[lenEven+1] << 8;

		/* Always need the first two six-bit groups.  */
		*dest++ = index[( group >> 18 ) & 0x3f];
		*dest++ = index[( group >> 12 ) & 0x3f];
		if ( lenRem > 1 )
			*dest++ = index[( group >> 6 ) & 0x3f];
	}

	/* Compute the length, then null terminate. */
	int outLen = dest - output;
	*dest = 0;

	return Allocated( output, outLen );
}


#line 68 "base64.cc"
static const int base64_start = 2;
static const int base64_first_final = 2;
static const int base64_error = 0;

static const int base64_en_main = 2;


#line 67 "base64.rl"


Allocated base64ToBin( const char *src, long srcLen )
{
	long sixBits;
	long group;

	long lenRem = srcLen % 4;
	long lenEven = srcLen - lenRem;
	long allocLen = ( lenEven / 4 ) * 3 + ( lenRem > 0 ? 3 : 0 ) + 1;

	unsigned char *output = new u_char[allocLen];
	unsigned char *dest = output;

	/* Parser for response. */
	
#line 132 "base64.rl"


	/* Note: including the null. */
	const char *p = src;
	const char *pe = src + srcLen;
	const char *eof = pe;
	int cs;

	
#line 103 "base64.cc"
	{
	cs = base64_start;
	}

#line 141 "base64.rl"
	
#line 110 "base64.cc"
	{
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 2:
	switch( (*p) ) {
		case 45: goto tr6;
		case 95: goto tr9;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr7;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr10;
	} else
		goto tr8;
	goto st0;
st0:
cs = 0;
	goto _out;
tr6:
#line 86 "base64.rl"
	{ sixBits = 62; }
#line 96 "base64.rl"
	{
			group = sixBits << 18;
		}
	goto st1;
tr7:
#line 85 "base64.rl"
	{ sixBits = 52 + (*p - '0'); }
#line 96 "base64.rl"
	{
			group = sixBits << 18;
		}
	goto st1;
tr8:
#line 83 "base64.rl"
	{ sixBits = *p - 'A'; }
#line 96 "base64.rl"
	{
			group = sixBits << 18;
		}
	goto st1;
tr9:
#line 87 "base64.rl"
	{ sixBits = 63; }
#line 96 "base64.rl"
	{
			group = sixBits << 18;
		}
	goto st1;
tr10:
#line 84 "base64.rl"
	{ sixBits = 26 + (*p - 'a'); }
#line 96 "base64.rl"
	{
			group = sixBits << 18;
		}
	goto st1;
tr21:
#line 109 "base64.rl"
	{
			*dest++ = ( group >> 16 ) & 0xff;
			*dest++ = ( group >> 8 ) & 0xff;
			*dest++ = group & 0xff;
		}
#line 86 "base64.rl"
	{ sixBits = 62; }
#line 96 "base64.rl"
	{
			group = sixBits << 18;
		}
	goto st1;
tr22:
#line 109 "base64.rl"
	{
			*dest++ = ( group >> 16 ) & 0xff;
			*dest++ = ( group >> 8 ) & 0xff;
			*dest++ = group & 0xff;
		}
#line 85 "base64.rl"
	{ sixBits = 52 + (*p - '0'); }
#line 96 "base64.rl"
	{
			group = sixBits << 18;
		}
	goto st1;
tr23:
#line 109 "base64.rl"
	{
			*dest++ = ( group >> 16 ) & 0xff;
			*dest++ = ( group >> 8 ) & 0xff;
			*dest++ = group & 0xff;
		}
#line 83 "base64.rl"
	{ sixBits = *p - 'A'; }
#line 96 "base64.rl"
	{
			group = sixBits << 18;
		}
	goto st1;
tr24:
#line 109 "base64.rl"
	{
			*dest++ = ( group >> 16 ) & 0xff;
			*dest++ = ( group >> 8 ) & 0xff;
			*dest++ = group & 0xff;
		}
#line 87 "base64.rl"
	{ sixBits = 63; }
#line 96 "base64.rl"
	{
			group = sixBits << 18;
		}
	goto st1;
tr25:
#line 109 "base64.rl"
	{
			*dest++ = ( group >> 16 ) & 0xff;
			*dest++ = ( group >> 8 ) & 0xff;
			*dest++ = group & 0xff;
		}
#line 84 "base64.rl"
	{ sixBits = 26 + (*p - 'a'); }
#line 96 "base64.rl"
	{
			group = sixBits << 18;
		}
	goto st1;
st1:
	if ( ++p == pe )
		goto _test_eof1;
case 1:
#line 247 "base64.cc"
	switch( (*p) ) {
		case 45: goto tr0;
		case 95: goto tr4;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr2;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr5;
	} else
		goto tr3;
	goto st0;
tr0:
#line 86 "base64.rl"
	{ sixBits = 62; }
#line 99 "base64.rl"
	{
			group |= sixBits << 12;
		}
	goto st3;
tr2:
#line 85 "base64.rl"
	{ sixBits = 52 + (*p - '0'); }
#line 99 "base64.rl"
	{
			group |= sixBits << 12;
		}
	goto st3;
tr3:
#line 83 "base64.rl"
	{ sixBits = *p - 'A'; }
#line 99 "base64.rl"
	{
			group |= sixBits << 12;
		}
	goto st3;
tr4:
#line 87 "base64.rl"
	{ sixBits = 63; }
#line 99 "base64.rl"
	{
			group |= sixBits << 12;
		}
	goto st3;
tr5:
#line 84 "base64.rl"
	{ sixBits = 26 + (*p - 'a'); }
#line 99 "base64.rl"
	{
			group |= sixBits << 12;
		}
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 305 "base64.cc"
	switch( (*p) ) {
		case 45: goto tr11;
		case 95: goto tr14;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr12;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr15;
	} else
		goto tr13;
	goto st0;
tr11:
#line 86 "base64.rl"
	{ sixBits = 62; }
#line 102 "base64.rl"
	{
			group |= sixBits << 6;
		}
	goto st4;
tr12:
#line 85 "base64.rl"
	{ sixBits = 52 + (*p - '0'); }
#line 102 "base64.rl"
	{
			group |= sixBits << 6;
		}
	goto st4;
tr13:
#line 83 "base64.rl"
	{ sixBits = *p - 'A'; }
#line 102 "base64.rl"
	{
			group |= sixBits << 6;
		}
	goto st4;
tr14:
#line 87 "base64.rl"
	{ sixBits = 63; }
#line 102 "base64.rl"
	{
			group |= sixBits << 6;
		}
	goto st4;
tr15:
#line 84 "base64.rl"
	{ sixBits = 26 + (*p - 'a'); }
#line 102 "base64.rl"
	{
			group |= sixBits << 6;
		}
	goto st4;
st4:
	if ( ++p == pe )
		goto _test_eof4;
case 4:
#line 363 "base64.cc"
	switch( (*p) ) {
		case 45: goto tr16;
		case 95: goto tr19;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr17;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr20;
	} else
		goto tr18;
	goto st0;
tr16:
#line 86 "base64.rl"
	{ sixBits = 62; }
#line 105 "base64.rl"
	{
			group |= sixBits;
		}
	goto st5;
tr17:
#line 85 "base64.rl"
	{ sixBits = 52 + (*p - '0'); }
#line 105 "base64.rl"
	{
			group |= sixBits;
		}
	goto st5;
tr18:
#line 83 "base64.rl"
	{ sixBits = *p - 'A'; }
#line 105 "base64.rl"
	{
			group |= sixBits;
		}
	goto st5;
tr19:
#line 87 "base64.rl"
	{ sixBits = 63; }
#line 105 "base64.rl"
	{
			group |= sixBits;
		}
	goto st5;
tr20:
#line 84 "base64.rl"
	{ sixBits = 26 + (*p - 'a'); }
#line 105 "base64.rl"
	{
			group |= sixBits;
		}
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 421 "base64.cc"
	switch( (*p) ) {
		case 45: goto tr21;
		case 95: goto tr24;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr22;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr25;
	} else
		goto tr23;
	goto st0;
	}
	_test_eof1: cs = 1; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 

	_test_eof: {}
	if ( p == eof )
	{
	switch ( cs ) {
	case 5: 
#line 109 "base64.rl"
	{
			*dest++ = ( group >> 16 ) & 0xff;
			*dest++ = ( group >> 8 ) & 0xff;
			*dest++ = group & 0xff;
		}
	break;
	case 4: 
#line 114 "base64.rl"
	{
			*dest++ = ( group >> 16 ) & 0xff;
			*dest++ = ( group >> 8 ) & 0xff;
		}
	break;
	case 3: 
#line 118 "base64.rl"
	{
			*dest++ = ( group >> 16 ) & 0xff;
		}
	break;
#line 466 "base64.cc"
	}
	}

	_out: {}
	}

#line 142 "base64.rl"

	/* Did parsing succeed? */
	if ( cs < 
#line 477 "base64.cc"
2
#line 144 "base64.rl"
 )
		throw Base64ParseError();

	/* Compute the length, then null terminate. */
	int outLen = dest - output;
	*dest = 0;

	return Allocated( (char*)output, outLen );
}
