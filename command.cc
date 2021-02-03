
#line 1 "command.rl"
/*
 * Copyright (c) 2008-2011, Adrian Thurston <thurston@complang.org>
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
#include "string.h"
#include "error.h"
#include "encrypt.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_MSG_LEN 16384

#include <unistd.h>
#include <fcntl.h>

/*
 * Server Loop
 */



#line 54 "command.rl"



#line 49 "command.cc"
static const int command_parser_start = 24;
static const int command_parser_first_final = 24;
static const int command_parser_error = 0;

static const int command_parser_en_main = 24;


#line 57 "command.rl"

CommandParser::CommandParser( Server *server )
:
	retVal(0),
	mysql(0),
	tls(false),
	exit(false),
	versions(0),
	server(server)
{

	
#line 70 "command.cc"
	{
	cs = command_parser_start;
	}

#line 69 "command.rl"
}

Parser::Control CommandParser::data( const char *data, int dlen )
{
	const unsigned char *p = (u_char*)data;
	const unsigned char *pe = (u_char*)data + dlen;

	
#line 84 "command.cc"
	{
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
tr25:
#line 49 "command.rl"
	{
				message( "command: new_user %s %s %s\n", user(), privateName(), pass() );
				server->newUser( user, privateName, pass );
			}
	goto st24;
st24:
	if ( ++p == pe )
		goto _test_eof24;
case 24:
#line 101 "command.cc"
	if ( (*p) == 110u )
		goto st1;
	goto st0;
st0:
cs = 0;
	goto _out;
st1:
	if ( ++p == pe )
		goto _test_eof1;
case 1:
	if ( (*p) == 101u )
		goto st2;
	goto st0;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 119u )
		goto st3;
	goto st0;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
	if ( (*p) == 45u )
		goto st4;
	goto st0;
st4:
	if ( ++p == pe )
		goto _test_eof4;
case 4:
	if ( (*p) == 117u )
		goto st5;
	goto st0;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
	if ( (*p) == 115u )
		goto st6;
	goto st0;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
	if ( (*p) == 101u )
		goto st7;
	goto st0;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
	if ( (*p) == 114u )
		goto st8;
	goto st0;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
	if ( (*p) == 0u )
		goto st9;
	goto st0;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
	if ( (*p) == 100u )
		goto tr9;
	goto st0;
tr9:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st10;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
#line 181 "command.cc"
	if ( (*p) == 115u )
		goto tr10;
	goto st0;
tr10:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st11;
st11:
	if ( ++p == pe )
		goto _test_eof11;
case 11:
#line 193 "command.cc"
	if ( (*p) == 110u )
		goto tr11;
	goto st0;
tr11:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st12;
st12:
	if ( ++p == pe )
		goto _test_eof12;
case 12:
#line 205 "command.cc"
	if ( (*p) == 112u )
		goto tr12;
	goto st0;
tr12:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st13;
st13:
	if ( ++p == pe )
		goto _test_eof13;
case 13:
#line 217 "command.cc"
	if ( (*p) == 58u )
		goto tr13;
	goto st0;
tr13:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st14;
st14:
	if ( ++p == pe )
		goto _test_eof14;
case 14:
#line 229 "command.cc"
	if ( (*p) == 47u )
		goto tr14;
	goto st0;
tr14:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st15;
st15:
	if ( ++p == pe )
		goto _test_eof15;
case 15:
#line 241 "command.cc"
	if ( (*p) == 47u )
		goto tr15;
	goto st0;
tr15:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st16;
st16:
	if ( ++p == pe )
		goto _test_eof16;
case 16:
#line 253 "command.cc"
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr16;
	} else if ( (*p) >= 33u )
		goto tr16;
	goto st0;
tr16:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st17;
st17:
	if ( ++p == pe )
		goto _test_eof17;
case 17:
#line 268 "command.cc"
	if ( (*p) == 47u )
		goto tr17;
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr16;
	goto st0;
tr17:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st18;
st18:
	if ( ++p == pe )
		goto _test_eof18;
case 18:
#line 282 "command.cc"
	if ( (*p) == 0u )
		goto tr18;
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr16;
	} else if ( (*p) >= 33u )
		goto tr16;
	goto st0;
tr18:
#line 102 "common.rl"
	{ user.set(buf); }
	goto st19;
st19:
	if ( ++p == pe )
		goto _test_eof19;
case 19:
#line 299 "command.cc"
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr19;
	goto st0;
tr19:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st20;
tr21:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st20;
st20:
	if ( ++p == pe )
		goto _test_eof20;
case 20:
#line 317 "command.cc"
	if ( (*p) == 0u )
		goto tr20;
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr21;
	goto st0;
tr20:
#line 82 "common.rl"
	{ privateName.set(buf); }
	goto st21;
st21:
	if ( ++p == pe )
		goto _test_eof21;
case 21:
#line 331 "command.cc"
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr22;
	goto st0;
tr22:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st22;
tr24:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st22;
st22:
	if ( ++p == pe )
		goto _test_eof22;
case 22:
#line 349 "command.cc"
	if ( (*p) == 0u )
		goto tr23;
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr24;
	goto st0;
tr23:
#line 71 "common.rl"
	{ pass.set(buf); }
	goto st23;
st23:
	if ( ++p == pe )
		goto _test_eof23;
case 23:
#line 363 "command.cc"
	if ( (*p) == 0u )
		goto tr25;
	goto st0;
	}
	_test_eof24: cs = 24; goto _test_eof; 
	_test_eof1: cs = 1; goto _test_eof; 
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof11: cs = 11; goto _test_eof; 
	_test_eof12: cs = 12; goto _test_eof; 
	_test_eof13: cs = 13; goto _test_eof; 
	_test_eof14: cs = 14; goto _test_eof; 
	_test_eof15: cs = 15; goto _test_eof; 
	_test_eof16: cs = 16; goto _test_eof; 
	_test_eof17: cs = 17; goto _test_eof; 
	_test_eof18: cs = 18; goto _test_eof; 
	_test_eof19: cs = 19; goto _test_eof; 
	_test_eof20: cs = 20; goto _test_eof; 
	_test_eof21: cs = 21; goto _test_eof; 
	_test_eof22: cs = 22; goto _test_eof; 
	_test_eof23: cs = 23; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 77 "command.rl"

	if ( exit && cs >= 
#line 400 "command.cc"
24
#line 78 "command.rl"
 )
		return Stop;

	/* Did parsing succeed? */
	if ( cs == 
#line 408 "command.cc"
0
#line 82 "command.rl"
 )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}


