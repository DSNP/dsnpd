
#line 1 "parser.rl"
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

/* FIXME: check all scanned lengths for overflow. */

/* Need this for the time being. */
u_char *writeExact( u_char *dest, const String &s )
{
	memcpy( dest, s(), s.length );
	dest += s.length;
	return dest;
}


/*
 * Identity::parse()
 */


#line 55 "parser.cc"
static const int identity_start = 1;
static const int identity_first_final = 10;
static const int identity_error = 0;

static const int identity_en_main = 1;


#line 54 "parser.rl"


long Identity::parse()
{
	const u_char *p = (u_char*)iduri.data;
	const u_char *pe = p + iduri.length;

	const u_char *h1, *h2;

	/* Parser for response. */
	
#line 69 "parser.rl"


	long result = 0, cs;

	
#line 81 "parser.cc"
	{
	cs = identity_start;
	}

#line 74 "parser.rl"
	
#line 88 "parser.cc"
	{
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) == 100u )
		goto st2;
	goto st0;
st0:
cs = 0;
	goto _out;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 115u )
		goto st3;
	goto st0;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
	if ( (*p) == 110u )
		goto st4;
	goto st0;
st4:
	if ( ++p == pe )
		goto _test_eof4;
case 4:
	if ( (*p) == 112u )
		goto st5;
	goto st0;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
	if ( (*p) == 58u )
		goto st6;
	goto st0;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
	if ( (*p) == 47u )
		goto st7;
	goto st0;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
	if ( (*p) == 47u )
		goto st8;
	goto st0;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr8;
	} else if ( (*p) >= 33u )
		goto tr8;
	goto st0;
tr8:
#line 68 "parser.rl"
	{h1=p;}
	goto st9;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
#line 161 "parser.cc"
	if ( (*p) == 47u )
		goto tr10;
	if ( 33u <= (*p) && (*p) <= 126u )
		goto st9;
	goto st0;
tr10:
#line 68 "parser.rl"
	{h2=p;}
	goto st10;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
#line 175 "parser.cc"
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto st11;
	} else if ( (*p) >= 33u )
		goto st11;
	goto st0;
st11:
	if ( ++p == pe )
		goto _test_eof11;
case 11:
	if ( (*p) == 47u )
		goto st10;
	if ( 33u <= (*p) && (*p) <= 126u )
		goto st11;
	goto st0;
	}
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

	_test_eof: {}
	_out: {}
	}

#line 75 "parser.rl"

	/* Did parsing succeed? */
	if ( cs < 
#line 211 "parser.cc"
10
#line 77 "parser.rl"
 )
		throw ParseError( __FILE__, __LINE__ );
	
	_host.set( (const char*)h1, (const char*)h2 );

	/* We can use the start of the last path part to get the site. */
	parsed = true;
	return result;
}

/*
 * Server Loop
 */



#line 201 "parser.rl"


#define CMD_PUBLIC_KEY                 50
#define CMD_FETCH_REQUESTED_RELID      51
#define CMD_FETCH_RESPONSE_RELID       52
#define CMD_FETCH_FTOKEN               53
#define CMD_MESSAGE                    54
#define CMD_FOF_MESSAGE                55
#define CMD_BROADCAST_RECIPIENT        56
#define CMD_BROADCAST                  57

Allocated consPublicKey( const String &user )
{
	long length = 1 + 
			stringLength( user );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, CMD_PUBLIC_KEY );
	dest = writeString( dest, user );

	return packet.relinquish();
}

Allocated consFetchRequestedRelid( const String &reqid )
{
	long length = 1 + 
			stringLength( reqid );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, CMD_FETCH_REQUESTED_RELID );
	dest = writeString( dest, reqid );

	return packet.relinquish();
}

Allocated consFetchResponseRelid( const String &reqid )
{
	long length = 1 + 
			stringLength( reqid );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, CMD_FETCH_RESPONSE_RELID );
	dest = writeString( dest, reqid );

	return packet.relinquish();
}

Allocated consFetchFtoken( const String &reqid )
{
	long length = 1 + 
			stringLength( reqid );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, CMD_FETCH_FTOKEN );
	dest = writeString( dest, reqid );

	return packet.relinquish();
}

Allocated consMessage( const String &relid, const String &msg )
{
	long length = 1 +
			stringLength( relid ) +
			binLength( msg );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, CMD_MESSAGE );
	dest = writeString( dest, relid );
	dest = writeBin( dest, msg );

	return packet.relinquish();
}

Allocated consFofMessage( const String &relid, const String &msg )
{
	long length = 1 + 
			stringLength( relid ) +
			binLength( msg );

	message( "CONSING relid: %s\n", relid() );
	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, CMD_FOF_MESSAGE );
	dest = writeString( dest, relid );
	dest = writeBin( dest, msg );

	return packet.relinquish();
}

Allocated consBroadcastRecipient( const String &relid )
{
	long length = 1 + 
			stringLength( relid );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, CMD_BROADCAST_RECIPIENT );
	dest = writeString( dest, relid );

	return packet.relinquish();
}

Allocated consBroadcast( const String &network, long long keyGen, 
		const String &msg )
{
	long length = 1 + 
			stringLength( network ) +
			sixtyFourBitLength() +
			binLength( msg );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, CMD_BROADCAST );
	dest = writeString( dest, network );
	dest = write64Bit( dest, keyGen );
	dest = writeBin( dest, msg );

	return packet.relinquish();
}


#line 429 "parser.rl"



#line 369 "parser.cc"
static const int server_loop_start = 1;
static const int server_loop_first_final = 372;
static const int server_loop_error = 0;

static const int server_loop_en_commands_local = 373;
static const int server_loop_en_commands_tls = 374;
static const int server_loop_en_main = 1;


#line 432 "parser.rl"

ServerParser::ServerParser( Server *server )
:
	retVal(0),
	mysql(0),
	tls(false),
	exit(false),
	versions(0),
	server(server)
{

	
#line 392 "parser.cc"
	{
	cs = server_loop_start;
	}

#line 444 "parser.rl"
}

Parser::Control ServerParser::data( const char *data, int dlen )
{
	const unsigned char *p = (u_char*)data;
	const unsigned char *pe = (u_char*)data + dlen;

	
#line 406 "parser.cc"
	{
	short _widec;
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) == 68u )
		goto st2;
	goto st0;
st0:
cs = 0;
	goto _out;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 83u )
		goto st3;
	goto st0;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
	if ( (*p) == 78u )
		goto st4;
	goto st0;
st4:
	if ( ++p == pe )
		goto _test_eof4;
case 4:
	if ( (*p) == 80u )
		goto st5;
	goto st0;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
	if ( (*p) == 32u )
		goto st6;
	goto st0;
tr15:
#line 29 "common.rl"
	{
			v = VERSION_MASK_0_1;
		}
#line 63 "common.rl"
	{
		if ( versions & v )
			throw VersionAlreadyGiven();

		versions |= v;
	}
	goto st6;
tr42:
#line 34 "common.rl"
	{
			v = VERSION_MASK_0_2;
		}
#line 63 "common.rl"
	{
		if ( versions & v )
			throw VersionAlreadyGiven();

		versions |= v;
	}
	goto st6;
tr44:
#line 39 "common.rl"
	{
			v = VERSION_MASK_0_3;
		}
#line 63 "common.rl"
	{
		if ( versions & v )
			throw VersionAlreadyGiven();

		versions |= v;
	}
	goto st6;
tr46:
#line 44 "common.rl"
	{
			v = VERSION_MASK_0_4;
		}
#line 63 "common.rl"
	{
		if ( versions & v )
			throw VersionAlreadyGiven();

		versions |= v;
	}
	goto st6;
tr48:
#line 49 "common.rl"
	{
			v = VERSION_MASK_0_5;
		}
#line 63 "common.rl"
	{
		if ( versions & v )
			throw VersionAlreadyGiven();

		versions |= v;
	}
	goto st6;
tr50:
#line 54 "common.rl"
	{
			v = VERSION_MASK_0_6;
		}
#line 63 "common.rl"
	{
		if ( versions & v )
			throw VersionAlreadyGiven();

		versions |= v;
	}
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 530 "parser.cc"
	if ( (*p) == 48u )
		goto st7;
	goto st0;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
	if ( (*p) == 46u )
		goto st8;
	goto st0;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
	switch( (*p) ) {
		case 49u: goto st9;
		case 50u: goto st30;
		case 51u: goto st31;
		case 52u: goto st32;
		case 53u: goto st33;
		case 54u: goto st34;
	}
	goto st0;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
	switch( (*p) ) {
		case 32u: goto tr14;
		case 124u: goto tr15;
	}
	goto st0;
tr14:
#line 29 "common.rl"
	{
			v = VERSION_MASK_0_1;
		}
#line 63 "common.rl"
	{
		if ( versions & v )
			throw VersionAlreadyGiven();

		versions |= v;
	}
	goto st10;
tr41:
#line 34 "common.rl"
	{
			v = VERSION_MASK_0_2;
		}
#line 63 "common.rl"
	{
		if ( versions & v )
			throw VersionAlreadyGiven();

		versions |= v;
	}
	goto st10;
tr43:
#line 39 "common.rl"
	{
			v = VERSION_MASK_0_3;
		}
#line 63 "common.rl"
	{
		if ( versions & v )
			throw VersionAlreadyGiven();

		versions |= v;
	}
	goto st10;
tr45:
#line 44 "common.rl"
	{
			v = VERSION_MASK_0_4;
		}
#line 63 "common.rl"
	{
		if ( versions & v )
			throw VersionAlreadyGiven();

		versions |= v;
	}
	goto st10;
tr47:
#line 49 "common.rl"
	{
			v = VERSION_MASK_0_5;
		}
#line 63 "common.rl"
	{
		if ( versions & v )
			throw VersionAlreadyGiven();

		versions |= v;
	}
	goto st10;
tr49:
#line 54 "common.rl"
	{
			v = VERSION_MASK_0_6;
		}
#line 63 "common.rl"
	{
		if ( versions & v )
			throw VersionAlreadyGiven();

		versions |= v;
	}
	goto st10;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
#line 645 "parser.cc"
	switch( (*p) ) {
		case 76u: goto st11;
		case 83u: goto st19;
		case 108u: goto st11;
		case 115u: goto st19;
	}
	goto st0;
st11:
	if ( ++p == pe )
		goto _test_eof11;
case 11:
	switch( (*p) ) {
		case 79u: goto st12;
		case 111u: goto st12;
	}
	goto st0;
st12:
	if ( ++p == pe )
		goto _test_eof12;
case 12:
	switch( (*p) ) {
		case 67u: goto st13;
		case 99u: goto st13;
	}
	goto st0;
st13:
	if ( ++p == pe )
		goto _test_eof13;
case 13:
	switch( (*p) ) {
		case 65u: goto st14;
		case 97u: goto st14;
	}
	goto st0;
st14:
	if ( ++p == pe )
		goto _test_eof14;
case 14:
	switch( (*p) ) {
		case 76u: goto st15;
		case 108u: goto st15;
	}
	goto st0;
st15:
	if ( ++p == pe )
		goto _test_eof15;
case 15:
	if ( (*p) == 32u )
		goto st16;
	goto st0;
st16:
	if ( ++p == pe )
		goto _test_eof16;
case 16:
	switch( (*p) ) {
		case 45u: goto tr23;
		case 95u: goto tr23;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr23;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr23;
	} else
		goto tr23;
	goto st0;
tr23:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st17;
tr26:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st17;
st17:
	if ( ++p == pe )
		goto _test_eof17;
case 17:
#line 727 "parser.cc"
	switch( (*p) ) {
		case 10u: goto tr24;
		case 13u: goto tr25;
		case 45u: goto tr26;
		case 95u: goto tr26;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr26;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr26;
	} else
		goto tr26;
	goto st0;
tr24:
#line 74 "common.rl"
	{ key.set(buf); }
#line 422 "parser.rl"
	{
				server->negotiation( versions, tls, host, key );
				if ( !tls )
					{goto st373;}
				else
					{goto st374;}
			}
	goto st372;
tr27:
#line 422 "parser.rl"
	{
				server->negotiation( versions, tls, host, key );
				if ( !tls )
					{goto st373;}
				else
					{goto st374;}
			}
	goto st372;
tr38:
#line 110 "common.rl"
	{ host.set(buf); }
#line 416 "parser.rl"
	{ tls = true; }
#line 422 "parser.rl"
	{
				server->negotiation( versions, tls, host, key );
				if ( !tls )
					{goto st373;}
				else
					{goto st374;}
			}
	goto st372;
st372:
	if ( ++p == pe )
		goto _test_eof372;
case 372:
#line 783 "parser.cc"
	goto st0;
tr25:
#line 74 "common.rl"
	{ key.set(buf); }
	goto st18;
tr39:
#line 110 "common.rl"
	{ host.set(buf); }
#line 416 "parser.rl"
	{ tls = true; }
	goto st18;
st18:
	if ( ++p == pe )
		goto _test_eof18;
case 18:
#line 799 "parser.cc"
	if ( (*p) == 10u )
		goto tr27;
	goto st0;
st19:
	if ( ++p == pe )
		goto _test_eof19;
case 19:
	switch( (*p) ) {
		case 84u: goto st20;
		case 116u: goto st20;
	}
	goto st0;
st20:
	if ( ++p == pe )
		goto _test_eof20;
case 20:
	switch( (*p) ) {
		case 65u: goto st21;
		case 97u: goto st21;
	}
	goto st0;
st21:
	if ( ++p == pe )
		goto _test_eof21;
case 21:
	switch( (*p) ) {
		case 82u: goto st22;
		case 114u: goto st22;
	}
	goto st0;
st22:
	if ( ++p == pe )
		goto _test_eof22;
case 22:
	switch( (*p) ) {
		case 84u: goto st23;
		case 116u: goto st23;
	}
	goto st0;
st23:
	if ( ++p == pe )
		goto _test_eof23;
case 23:
	if ( (*p) == 95u )
		goto st24;
	goto st0;
st24:
	if ( ++p == pe )
		goto _test_eof24;
case 24:
	switch( (*p) ) {
		case 84u: goto st25;
		case 116u: goto st25;
	}
	goto st0;
st25:
	if ( ++p == pe )
		goto _test_eof25;
case 25:
	switch( (*p) ) {
		case 76u: goto st26;
		case 108u: goto st26;
	}
	goto st0;
st26:
	if ( ++p == pe )
		goto _test_eof26;
case 26:
	switch( (*p) ) {
		case 83u: goto st27;
		case 115u: goto st27;
	}
	goto st0;
st27:
	if ( ++p == pe )
		goto _test_eof27;
case 27:
	if ( (*p) == 32u )
		goto st28;
	goto st0;
st28:
	if ( ++p == pe )
		goto _test_eof28;
case 28:
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr37;
	} else if ( (*p) >= 33u )
		goto tr37;
	goto st0;
tr37:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st29;
tr40:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st29;
st29:
	if ( ++p == pe )
		goto _test_eof29;
case 29:
#line 904 "parser.cc"
	switch( (*p) ) {
		case 10u: goto tr38;
		case 13u: goto tr39;
	}
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr40;
	} else if ( (*p) >= 33u )
		goto tr40;
	goto st0;
st30:
	if ( ++p == pe )
		goto _test_eof30;
case 30:
	switch( (*p) ) {
		case 32u: goto tr41;
		case 124u: goto tr42;
	}
	goto st0;
st31:
	if ( ++p == pe )
		goto _test_eof31;
case 31:
	switch( (*p) ) {
		case 32u: goto tr43;
		case 124u: goto tr44;
	}
	goto st0;
st32:
	if ( ++p == pe )
		goto _test_eof32;
case 32:
	switch( (*p) ) {
		case 32u: goto tr45;
		case 124u: goto tr46;
	}
	goto st0;
st33:
	if ( ++p == pe )
		goto _test_eof33;
case 33:
	switch( (*p) ) {
		case 32u: goto tr47;
		case 124u: goto tr48;
	}
	goto st0;
st34:
	if ( ++p == pe )
		goto _test_eof34;
case 34:
	switch( (*p) ) {
		case 32u: goto tr49;
		case 124u: goto tr50;
	}
	goto st0;
tr68:
#line 72 "common.rl"
	{ reqid.set(buf); }
#line 131 "parser.rl"
	{
				message( "command: accept_friend %s %s\n", loginToken(), reqid() );
				server->acceptFriend( loginToken, reqid );
			}
	goto st373;
tr71:
#line 131 "parser.rl"
	{
				message( "command: accept_friend %s %s\n", loginToken(), reqid() );
				server->acceptFriend( loginToken, reqid );
			}
	goto st373;
tr108:
#line 101 "common.rl"
	{ iduri.set(buf); }
#line 122 "parser.rl"
	{
				message( "command: friend_final %s %s %s\n", user(), reqid(), iduri() );
				server->friendFinal( user, reqid, iduri );
			}
	goto st373;
tr111:
#line 122 "parser.rl"
	{
				message( "command: friend_final %s %s %s\n", user(), reqid(), iduri() );
				server->friendFinal( user, reqid, iduri );
			}
	goto st373;
tr138:
#line 73 "common.rl"
	{ hash.set(buf); }
#line 140 "parser.rl"
	{
				message( "command: ftoken_request %s %s\n", user(), hash() );
				server->ftokenRequest( user, hash );
			}
	goto st373;
tr141:
#line 140 "parser.rl"
	{
				message( "command: ftoken_request %s %s\n", user(), hash() );
				server->ftokenRequest( user, hash );
			}
	goto st373;
tr155:
#line 72 "common.rl"
	{ reqid.set(buf); }
#line 146 "parser.rl"
	{
				message( "command: ftoken_response %s %s %s\n", loginToken(), hash(), reqid() );
				server->ftokenResponse( loginToken, hash, reqid );
			}
	goto st373;
tr158:
#line 146 "parser.rl"
	{
				message( "command: ftoken_response %s %s %s\n", loginToken(), hash(), reqid() );
				server->ftokenResponse( loginToken, hash, reqid );
			}
	goto st373;
tr179:
#line 83 "common.rl"
	{ sessionId.set(buf); }
#line 99 "parser.rl"
	{
				message( "command: login %s <pass>\n", user() );
				server->login( user, pass, sessionId );
			}
	goto st373;
tr182:
#line 99 "parser.rl"
	{
				message( "command: login %s <pass>\n", user() );
				server->login( user, pass, sessionId );
			}
	goto st373;
tr218:
#line 101 "common.rl"
	{ iduri.set(buf); }
#line 108 "parser.rl"
	{
				message( "command: relid_request %s %s\n", user(), iduri() );
				server->relidRequest( user, iduri );
			}
	goto st373;
tr221:
#line 108 "parser.rl"
	{
				message( "command: relid_request %s %s\n", user(), iduri() );
				server->relidRequest( user, iduri );
			}
	goto st373;
tr243:
#line 101 "common.rl"
	{ iduri.set(buf); }
#line 115 "parser.rl"
	{
				message( "command: relid_response %s %s %s\n", 
						loginToken(), reqid(), iduri() );
				server->relidResponse( loginToken, reqid, iduri );
			}
	goto st373;
tr246:
#line 115 "parser.rl"
	{
				message( "command: relid_response %s %s %s\n", 
						loginToken(), reqid(), iduri() );
				server->relidResponse( loginToken, reqid, iduri );
			}
	goto st373;
tr272:
#line 72 "common.rl"
	{ reqid.set(buf); }
#line 195 "parser.rl"
	{
				message( "command: remote_broadcast_final %s %s\n",
						floginToken(), reqid() );
				server->remoteBroadcastFinal( floginToken, reqid );
			}
	goto st373;
tr275:
#line 195 "parser.rl"
	{
				message( "command: remote_broadcast_final %s %s\n",
						floginToken(), reqid() );
				server->remoteBroadcastFinal( floginToken, reqid );
			}
	goto st373;
tr294:
#line 156 "common.rl"
	{
		/* Take from the buf and reset the buf's limit. */
		body.set( buf );
		buf.clear();
		buf.limit = buf.defaultLimit;
	}
#line 181 "parser.rl"
	{
				message( "command: remote_broadcast_request %s %ld\n",
						floginToken(), length );
				server->remoteBroadcastRequest( floginToken, body );
			}
	goto st373;
tr296:
#line 181 "parser.rl"
	{
				message( "command: remote_broadcast_request %s %ld\n",
						floginToken(), length );
				server->remoteBroadcastRequest( floginToken, body );
			}
	goto st373;
tr310:
#line 72 "common.rl"
	{ reqid.set(buf); }
#line 188 "parser.rl"
	{
				message( "command: remote_broadcast_response %s %s\n",
						loginToken(), reqid() );
				server->remoteBroadcastResponse( loginToken, reqid );
			}
	goto st373;
tr313:
#line 188 "parser.rl"
	{
				message( "command: remote_broadcast_response %s %s\n",
						loginToken(), reqid() );
				server->remoteBroadcastResponse( loginToken, reqid );
			}
	goto st373;
tr342:
#line 156 "common.rl"
	{
		/* Take from the buf and reset the buf's limit. */
		body.set( buf );
		buf.clear();
		buf.limit = buf.defaultLimit;
	}
#line 172 "parser.rl"
	{
				message( "command: submit_broadcast %s %ld\n", loginToken(), length );
				server->submitBroadcast( loginToken, body );
			}
	goto st373;
tr344:
#line 172 "parser.rl"
	{
				message( "command: submit_broadcast %s %ld\n", loginToken(), length );
				server->submitBroadcast( loginToken, body );
			}
	goto st373;
tr358:
#line 83 "common.rl"
	{ sessionId.set(buf); }
#line 152 "parser.rl"
	{
				message( "command: submit_ftoken %s\n", token() );
				server->submitFtoken( token, sessionId );
			}
	goto st373;
tr361:
#line 152 "parser.rl"
	{
				message( "command: submit_ftoken %s\n", token() );
				server->submitFtoken( token, sessionId );
			}
	goto st373;
tr390:
#line 156 "common.rl"
	{
		/* Take from the buf and reset the buf's limit. */
		body.set( buf );
		buf.clear();
		buf.limit = buf.defaultLimit;
	}
#line 163 "parser.rl"
	{
				message( "command: submit_message %s %s %ld\n", loginToken(), iduri(), length );
				server->submitMessage( loginToken, iduri, body );
			}
	goto st373;
tr392:
#line 163 "parser.rl"
	{
				message( "command: submit_message %s %s %ld\n", loginToken(), iduri(), length );
				server->submitMessage( loginToken, iduri, body );
			}
	goto st373;
st373:
	if ( ++p == pe )
		goto _test_eof373;
case 373:
#line 1195 "parser.cc"
	switch( (*p) ) {
		case 65u: goto st35;
		case 70u: goto st53;
		case 76u: goto st130;
		case 82u: goto st151;
		case 83u: goto st262;
		case 97u: goto st35;
		case 102u: goto st53;
		case 108u: goto st130;
		case 114u: goto st151;
		case 115u: goto st262;
	}
	goto st0;
st35:
	if ( ++p == pe )
		goto _test_eof35;
case 35:
	switch( (*p) ) {
		case 67u: goto st36;
		case 99u: goto st36;
	}
	goto st0;
st36:
	if ( ++p == pe )
		goto _test_eof36;
case 36:
	switch( (*p) ) {
		case 67u: goto st37;
		case 99u: goto st37;
	}
	goto st0;
st37:
	if ( ++p == pe )
		goto _test_eof37;
case 37:
	switch( (*p) ) {
		case 69u: goto st38;
		case 101u: goto st38;
	}
	goto st0;
st38:
	if ( ++p == pe )
		goto _test_eof38;
case 38:
	switch( (*p) ) {
		case 80u: goto st39;
		case 112u: goto st39;
	}
	goto st0;
st39:
	if ( ++p == pe )
		goto _test_eof39;
case 39:
	switch( (*p) ) {
		case 84u: goto st40;
		case 116u: goto st40;
	}
	goto st0;
st40:
	if ( ++p == pe )
		goto _test_eof40;
case 40:
	if ( (*p) == 95u )
		goto st41;
	goto st0;
st41:
	if ( ++p == pe )
		goto _test_eof41;
case 41:
	switch( (*p) ) {
		case 70u: goto st42;
		case 102u: goto st42;
	}
	goto st0;
st42:
	if ( ++p == pe )
		goto _test_eof42;
case 42:
	switch( (*p) ) {
		case 82u: goto st43;
		case 114u: goto st43;
	}
	goto st0;
st43:
	if ( ++p == pe )
		goto _test_eof43;
case 43:
	switch( (*p) ) {
		case 73u: goto st44;
		case 105u: goto st44;
	}
	goto st0;
st44:
	if ( ++p == pe )
		goto _test_eof44;
case 44:
	switch( (*p) ) {
		case 69u: goto st45;
		case 101u: goto st45;
	}
	goto st0;
st45:
	if ( ++p == pe )
		goto _test_eof45;
case 45:
	switch( (*p) ) {
		case 78u: goto st46;
		case 110u: goto st46;
	}
	goto st0;
st46:
	if ( ++p == pe )
		goto _test_eof46;
case 46:
	switch( (*p) ) {
		case 68u: goto st47;
		case 100u: goto st47;
	}
	goto st0;
st47:
	if ( ++p == pe )
		goto _test_eof47;
case 47:
	if ( (*p) == 32u )
		goto st48;
	goto st0;
st48:
	if ( ++p == pe )
		goto _test_eof48;
case 48:
	switch( (*p) ) {
		case 45u: goto tr64;
		case 95u: goto tr64;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr64;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr64;
	} else
		goto tr64;
	goto st0;
tr64:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st49;
tr66:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st49;
st49:
	if ( ++p == pe )
		goto _test_eof49;
case 49:
#line 1353 "parser.cc"
	switch( (*p) ) {
		case 32u: goto tr65;
		case 45u: goto tr66;
		case 95u: goto tr66;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr66;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr66;
	} else
		goto tr66;
	goto st0;
tr65:
#line 78 "common.rl"
	{ loginToken.set(buf); }
	goto st50;
st50:
	if ( ++p == pe )
		goto _test_eof50;
case 50:
#line 1376 "parser.cc"
	switch( (*p) ) {
		case 45u: goto tr67;
		case 95u: goto tr67;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr67;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr67;
	} else
		goto tr67;
	goto st0;
tr67:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st51;
tr70:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st51;
st51:
	if ( ++p == pe )
		goto _test_eof51;
case 51:
#line 1404 "parser.cc"
	switch( (*p) ) {
		case 10u: goto tr68;
		case 13u: goto tr69;
		case 45u: goto tr70;
		case 95u: goto tr70;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr70;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr70;
	} else
		goto tr70;
	goto st0;
tr69:
#line 72 "common.rl"
	{ reqid.set(buf); }
	goto st52;
st52:
	if ( ++p == pe )
		goto _test_eof52;
case 52:
#line 1428 "parser.cc"
	if ( (*p) == 10u )
		goto tr71;
	goto st0;
st53:
	if ( ++p == pe )
		goto _test_eof53;
case 53:
	switch( (*p) ) {
		case 82u: goto st54;
		case 84u: goto st90;
		case 114u: goto st54;
		case 116u: goto st90;
	}
	goto st0;
st54:
	if ( ++p == pe )
		goto _test_eof54;
case 54:
	switch( (*p) ) {
		case 73u: goto st55;
		case 105u: goto st55;
	}
	goto st0;
st55:
	if ( ++p == pe )
		goto _test_eof55;
case 55:
	switch( (*p) ) {
		case 69u: goto st56;
		case 101u: goto st56;
	}
	goto st0;
st56:
	if ( ++p == pe )
		goto _test_eof56;
case 56:
	switch( (*p) ) {
		case 78u: goto st57;
		case 110u: goto st57;
	}
	goto st0;
st57:
	if ( ++p == pe )
		goto _test_eof57;
case 57:
	switch( (*p) ) {
		case 68u: goto st58;
		case 100u: goto st58;
	}
	goto st0;
st58:
	if ( ++p == pe )
		goto _test_eof58;
case 58:
	if ( (*p) == 95u )
		goto st59;
	goto st0;
st59:
	if ( ++p == pe )
		goto _test_eof59;
case 59:
	switch( (*p) ) {
		case 70u: goto st60;
		case 102u: goto st60;
	}
	goto st0;
st60:
	if ( ++p == pe )
		goto _test_eof60;
case 60:
	switch( (*p) ) {
		case 73u: goto st61;
		case 105u: goto st61;
	}
	goto st0;
st61:
	if ( ++p == pe )
		goto _test_eof61;
case 61:
	switch( (*p) ) {
		case 78u: goto st62;
		case 110u: goto st62;
	}
	goto st0;
st62:
	if ( ++p == pe )
		goto _test_eof62;
case 62:
	switch( (*p) ) {
		case 65u: goto st63;
		case 97u: goto st63;
	}
	goto st0;
st63:
	if ( ++p == pe )
		goto _test_eof63;
case 63:
	switch( (*p) ) {
		case 76u: goto st64;
		case 108u: goto st64;
	}
	goto st0;
st64:
	if ( ++p == pe )
		goto _test_eof64;
case 64:
	if ( (*p) == 32u )
		goto st65;
	goto st0;
st65:
	if ( ++p == pe )
		goto _test_eof65;
case 65:
	if ( (*p) == 100u )
		goto tr85;
	goto st0;
tr85:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st66;
st66:
	if ( ++p == pe )
		goto _test_eof66;
case 66:
#line 1555 "parser.cc"
	if ( (*p) == 115u )
		goto tr86;
	goto st0;
tr86:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st67;
st67:
	if ( ++p == pe )
		goto _test_eof67;
case 67:
#line 1567 "parser.cc"
	if ( (*p) == 110u )
		goto tr87;
	goto st0;
tr87:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st68;
st68:
	if ( ++p == pe )
		goto _test_eof68;
case 68:
#line 1579 "parser.cc"
	if ( (*p) == 112u )
		goto tr88;
	goto st0;
tr88:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st69;
st69:
	if ( ++p == pe )
		goto _test_eof69;
case 69:
#line 1591 "parser.cc"
	if ( (*p) == 58u )
		goto tr89;
	goto st0;
tr89:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st70;
st70:
	if ( ++p == pe )
		goto _test_eof70;
case 70:
#line 1603 "parser.cc"
	if ( (*p) == 47u )
		goto tr90;
	goto st0;
tr90:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st71;
st71:
	if ( ++p == pe )
		goto _test_eof71;
case 71:
#line 1615 "parser.cc"
	if ( (*p) == 47u )
		goto tr91;
	goto st0;
tr91:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st72;
st72:
	if ( ++p == pe )
		goto _test_eof72;
case 72:
#line 1627 "parser.cc"
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr92;
	} else if ( (*p) >= 33u )
		goto tr92;
	goto st0;
tr92:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st73;
st73:
	if ( ++p == pe )
		goto _test_eof73;
case 73:
#line 1642 "parser.cc"
	if ( (*p) == 47u )
		goto tr93;
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr92;
	goto st0;
tr93:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st74;
st74:
	if ( ++p == pe )
		goto _test_eof74;
case 74:
#line 1656 "parser.cc"
	if ( (*p) == 32u )
		goto tr94;
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr95;
	} else if ( (*p) >= 33u )
		goto tr95;
	goto st0;
tr94:
#line 104 "common.rl"
	{ user.set(buf); }
	goto st75;
st75:
	if ( ++p == pe )
		goto _test_eof75;
case 75:
#line 1673 "parser.cc"
	switch( (*p) ) {
		case 45u: goto tr96;
		case 95u: goto tr96;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr96;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr96;
	} else
		goto tr96;
	goto st0;
tr96:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st76;
tr98:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st76;
st76:
	if ( ++p == pe )
		goto _test_eof76;
case 76:
#line 1701 "parser.cc"
	switch( (*p) ) {
		case 32u: goto tr97;
		case 45u: goto tr98;
		case 95u: goto tr98;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr98;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr98;
	} else
		goto tr98;
	goto st0;
tr97:
#line 72 "common.rl"
	{ reqid.set(buf); }
	goto st77;
st77:
	if ( ++p == pe )
		goto _test_eof77;
case 77:
#line 1724 "parser.cc"
	if ( (*p) == 100u )
		goto tr99;
	goto st0;
tr99:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st78;
st78:
	if ( ++p == pe )
		goto _test_eof78;
case 78:
#line 1738 "parser.cc"
	if ( (*p) == 115u )
		goto tr100;
	goto st0;
tr100:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st79;
st79:
	if ( ++p == pe )
		goto _test_eof79;
case 79:
#line 1750 "parser.cc"
	if ( (*p) == 110u )
		goto tr101;
	goto st0;
tr101:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st80;
st80:
	if ( ++p == pe )
		goto _test_eof80;
case 80:
#line 1762 "parser.cc"
	if ( (*p) == 112u )
		goto tr102;
	goto st0;
tr102:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st81;
st81:
	if ( ++p == pe )
		goto _test_eof81;
case 81:
#line 1774 "parser.cc"
	if ( (*p) == 58u )
		goto tr103;
	goto st0;
tr103:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st82;
st82:
	if ( ++p == pe )
		goto _test_eof82;
case 82:
#line 1786 "parser.cc"
	if ( (*p) == 47u )
		goto tr104;
	goto st0;
tr104:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st83;
st83:
	if ( ++p == pe )
		goto _test_eof83;
case 83:
#line 1798 "parser.cc"
	if ( (*p) == 47u )
		goto tr105;
	goto st0;
tr105:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st84;
st84:
	if ( ++p == pe )
		goto _test_eof84;
case 84:
#line 1810 "parser.cc"
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr106;
	} else if ( (*p) >= 33u )
		goto tr106;
	goto st0;
tr106:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st85;
st85:
	if ( ++p == pe )
		goto _test_eof85;
case 85:
#line 1825 "parser.cc"
	if ( (*p) == 47u )
		goto tr107;
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr106;
	goto st0;
tr107:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st86;
st86:
	if ( ++p == pe )
		goto _test_eof86;
case 86:
#line 1839 "parser.cc"
	switch( (*p) ) {
		case 10u: goto tr108;
		case 13u: goto tr109;
	}
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr110;
	} else if ( (*p) >= 33u )
		goto tr110;
	goto st0;
tr109:
#line 101 "common.rl"
	{ iduri.set(buf); }
	goto st87;
st87:
	if ( ++p == pe )
		goto _test_eof87;
case 87:
#line 1858 "parser.cc"
	if ( (*p) == 10u )
		goto tr111;
	goto st0;
tr110:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st88;
st88:
	if ( ++p == pe )
		goto _test_eof88;
case 88:
#line 1870 "parser.cc"
	switch( (*p) ) {
		case 10u: goto tr108;
		case 13u: goto tr109;
		case 47u: goto tr107;
	}
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr110;
	goto st0;
tr95:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st89;
st89:
	if ( ++p == pe )
		goto _test_eof89;
case 89:
#line 1887 "parser.cc"
	switch( (*p) ) {
		case 32u: goto tr94;
		case 47u: goto tr93;
	}
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr95;
	goto st0;
st90:
	if ( ++p == pe )
		goto _test_eof90;
case 90:
	switch( (*p) ) {
		case 79u: goto st91;
		case 111u: goto st91;
	}
	goto st0;
st91:
	if ( ++p == pe )
		goto _test_eof91;
case 91:
	switch( (*p) ) {
		case 75u: goto st92;
		case 107u: goto st92;
	}
	goto st0;
st92:
	if ( ++p == pe )
		goto _test_eof92;
case 92:
	switch( (*p) ) {
		case 69u: goto st93;
		case 101u: goto st93;
	}
	goto st0;
st93:
	if ( ++p == pe )
		goto _test_eof93;
case 93:
	switch( (*p) ) {
		case 78u: goto st94;
		case 110u: goto st94;
	}
	goto st0;
st94:
	if ( ++p == pe )
		goto _test_eof94;
case 94:
	if ( (*p) == 95u )
		goto st95;
	goto st0;
st95:
	if ( ++p == pe )
		goto _test_eof95;
case 95:
	switch( (*p) ) {
		case 82u: goto st96;
		case 114u: goto st96;
	}
	goto st0;
st96:
	if ( ++p == pe )
		goto _test_eof96;
case 96:
	switch( (*p) ) {
		case 69u: goto st97;
		case 101u: goto st97;
	}
	goto st0;
st97:
	if ( ++p == pe )
		goto _test_eof97;
case 97:
	switch( (*p) ) {
		case 81u: goto st98;
		case 83u: goto st117;
		case 113u: goto st98;
		case 115u: goto st117;
	}
	goto st0;
st98:
	if ( ++p == pe )
		goto _test_eof98;
case 98:
	switch( (*p) ) {
		case 85u: goto st99;
		case 117u: goto st99;
	}
	goto st0;
st99:
	if ( ++p == pe )
		goto _test_eof99;
case 99:
	switch( (*p) ) {
		case 69u: goto st100;
		case 101u: goto st100;
	}
	goto st0;
st100:
	if ( ++p == pe )
		goto _test_eof100;
case 100:
	switch( (*p) ) {
		case 83u: goto st101;
		case 115u: goto st101;
	}
	goto st0;
st101:
	if ( ++p == pe )
		goto _test_eof101;
case 101:
	switch( (*p) ) {
		case 84u: goto st102;
		case 116u: goto st102;
	}
	goto st0;
st102:
	if ( ++p == pe )
		goto _test_eof102;
case 102:
	if ( (*p) == 32u )
		goto st103;
	goto st0;
st103:
	if ( ++p == pe )
		goto _test_eof103;
case 103:
	if ( (*p) == 100u )
		goto tr126;
	goto st0;
tr126:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st104;
st104:
	if ( ++p == pe )
		goto _test_eof104;
case 104:
#line 2027 "parser.cc"
	if ( (*p) == 115u )
		goto tr127;
	goto st0;
tr127:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st105;
st105:
	if ( ++p == pe )
		goto _test_eof105;
case 105:
#line 2039 "parser.cc"
	if ( (*p) == 110u )
		goto tr128;
	goto st0;
tr128:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st106;
st106:
	if ( ++p == pe )
		goto _test_eof106;
case 106:
#line 2051 "parser.cc"
	if ( (*p) == 112u )
		goto tr129;
	goto st0;
tr129:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st107;
st107:
	if ( ++p == pe )
		goto _test_eof107;
case 107:
#line 2063 "parser.cc"
	if ( (*p) == 58u )
		goto tr130;
	goto st0;
tr130:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st108;
st108:
	if ( ++p == pe )
		goto _test_eof108;
case 108:
#line 2075 "parser.cc"
	if ( (*p) == 47u )
		goto tr131;
	goto st0;
tr131:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st109;
st109:
	if ( ++p == pe )
		goto _test_eof109;
case 109:
#line 2087 "parser.cc"
	if ( (*p) == 47u )
		goto tr132;
	goto st0;
tr132:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st110;
st110:
	if ( ++p == pe )
		goto _test_eof110;
case 110:
#line 2099 "parser.cc"
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr133;
	} else if ( (*p) >= 33u )
		goto tr133;
	goto st0;
tr133:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st111;
st111:
	if ( ++p == pe )
		goto _test_eof111;
case 111:
#line 2114 "parser.cc"
	if ( (*p) == 47u )
		goto tr134;
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr133;
	goto st0;
tr134:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st112;
st112:
	if ( ++p == pe )
		goto _test_eof112;
case 112:
#line 2128 "parser.cc"
	if ( (*p) == 32u )
		goto tr135;
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr136;
	} else if ( (*p) >= 33u )
		goto tr136;
	goto st0;
tr135:
#line 104 "common.rl"
	{ user.set(buf); }
	goto st113;
st113:
	if ( ++p == pe )
		goto _test_eof113;
case 113:
#line 2145 "parser.cc"
	switch( (*p) ) {
		case 45u: goto tr137;
		case 95u: goto tr137;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr137;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr137;
	} else
		goto tr137;
	goto st0;
tr137:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st114;
tr140:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st114;
st114:
	if ( ++p == pe )
		goto _test_eof114;
case 114:
#line 2173 "parser.cc"
	switch( (*p) ) {
		case 10u: goto tr138;
		case 13u: goto tr139;
		case 45u: goto tr140;
		case 95u: goto tr140;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr140;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr140;
	} else
		goto tr140;
	goto st0;
tr139:
#line 73 "common.rl"
	{ hash.set(buf); }
	goto st115;
st115:
	if ( ++p == pe )
		goto _test_eof115;
case 115:
#line 2197 "parser.cc"
	if ( (*p) == 10u )
		goto tr141;
	goto st0;
tr136:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st116;
st116:
	if ( ++p == pe )
		goto _test_eof116;
case 116:
#line 2209 "parser.cc"
	switch( (*p) ) {
		case 32u: goto tr135;
		case 47u: goto tr134;
	}
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr136;
	goto st0;
st117:
	if ( ++p == pe )
		goto _test_eof117;
case 117:
	switch( (*p) ) {
		case 80u: goto st118;
		case 112u: goto st118;
	}
	goto st0;
st118:
	if ( ++p == pe )
		goto _test_eof118;
case 118:
	switch( (*p) ) {
		case 79u: goto st119;
		case 111u: goto st119;
	}
	goto st0;
st119:
	if ( ++p == pe )
		goto _test_eof119;
case 119:
	switch( (*p) ) {
		case 78u: goto st120;
		case 110u: goto st120;
	}
	goto st0;
st120:
	if ( ++p == pe )
		goto _test_eof120;
case 120:
	switch( (*p) ) {
		case 83u: goto st121;
		case 115u: goto st121;
	}
	goto st0;
st121:
	if ( ++p == pe )
		goto _test_eof121;
case 121:
	switch( (*p) ) {
		case 69u: goto st122;
		case 101u: goto st122;
	}
	goto st0;
st122:
	if ( ++p == pe )
		goto _test_eof122;
case 122:
	if ( (*p) == 32u )
		goto st123;
	goto st0;
st123:
	if ( ++p == pe )
		goto _test_eof123;
case 123:
	switch( (*p) ) {
		case 45u: goto tr148;
		case 95u: goto tr148;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr148;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr148;
	} else
		goto tr148;
	goto st0;
tr148:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st124;
tr150:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st124;
st124:
	if ( ++p == pe )
		goto _test_eof124;
case 124:
#line 2300 "parser.cc"
	switch( (*p) ) {
		case 32u: goto tr149;
		case 45u: goto tr150;
		case 95u: goto tr150;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr150;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr150;
	} else
		goto tr150;
	goto st0;
tr149:
#line 78 "common.rl"
	{ loginToken.set(buf); }
	goto st125;
st125:
	if ( ++p == pe )
		goto _test_eof125;
case 125:
#line 2323 "parser.cc"
	switch( (*p) ) {
		case 45u: goto tr151;
		case 95u: goto tr151;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr151;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr151;
	} else
		goto tr151;
	goto st0;
tr151:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st126;
tr153:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st126;
st126:
	if ( ++p == pe )
		goto _test_eof126;
case 126:
#line 2351 "parser.cc"
	switch( (*p) ) {
		case 32u: goto tr152;
		case 45u: goto tr153;
		case 95u: goto tr153;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr153;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr153;
	} else
		goto tr153;
	goto st0;
tr152:
#line 73 "common.rl"
	{ hash.set(buf); }
	goto st127;
st127:
	if ( ++p == pe )
		goto _test_eof127;
case 127:
#line 2374 "parser.cc"
	switch( (*p) ) {
		case 45u: goto tr154;
		case 95u: goto tr154;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr154;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr154;
	} else
		goto tr154;
	goto st0;
tr154:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st128;
tr157:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st128;
st128:
	if ( ++p == pe )
		goto _test_eof128;
case 128:
#line 2402 "parser.cc"
	switch( (*p) ) {
		case 10u: goto tr155;
		case 13u: goto tr156;
		case 45u: goto tr157;
		case 95u: goto tr157;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr157;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr157;
	} else
		goto tr157;
	goto st0;
tr156:
#line 72 "common.rl"
	{ reqid.set(buf); }
	goto st129;
st129:
	if ( ++p == pe )
		goto _test_eof129;
case 129:
#line 2426 "parser.cc"
	if ( (*p) == 10u )
		goto tr158;
	goto st0;
st130:
	if ( ++p == pe )
		goto _test_eof130;
case 130:
	switch( (*p) ) {
		case 79u: goto st131;
		case 111u: goto st131;
	}
	goto st0;
st131:
	if ( ++p == pe )
		goto _test_eof131;
case 131:
	switch( (*p) ) {
		case 71u: goto st132;
		case 103u: goto st132;
	}
	goto st0;
st132:
	if ( ++p == pe )
		goto _test_eof132;
case 132:
	switch( (*p) ) {
		case 73u: goto st133;
		case 105u: goto st133;
	}
	goto st0;
st133:
	if ( ++p == pe )
		goto _test_eof133;
case 133:
	switch( (*p) ) {
		case 78u: goto st134;
		case 110u: goto st134;
	}
	goto st0;
st134:
	if ( ++p == pe )
		goto _test_eof134;
case 134:
	if ( (*p) == 32u )
		goto st135;
	goto st0;
st135:
	if ( ++p == pe )
		goto _test_eof135;
case 135:
	if ( (*p) == 100u )
		goto tr164;
	goto st0;
tr164:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st136;
st136:
	if ( ++p == pe )
		goto _test_eof136;
case 136:
#line 2490 "parser.cc"
	if ( (*p) == 115u )
		goto tr165;
	goto st0;
tr165:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st137;
st137:
	if ( ++p == pe )
		goto _test_eof137;
case 137:
#line 2502 "parser.cc"
	if ( (*p) == 110u )
		goto tr166;
	goto st0;
tr166:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st138;
st138:
	if ( ++p == pe )
		goto _test_eof138;
case 138:
#line 2514 "parser.cc"
	if ( (*p) == 112u )
		goto tr167;
	goto st0;
tr167:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st139;
st139:
	if ( ++p == pe )
		goto _test_eof139;
case 139:
#line 2526 "parser.cc"
	if ( (*p) == 58u )
		goto tr168;
	goto st0;
tr168:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st140;
st140:
	if ( ++p == pe )
		goto _test_eof140;
case 140:
#line 2538 "parser.cc"
	if ( (*p) == 47u )
		goto tr169;
	goto st0;
tr169:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st141;
st141:
	if ( ++p == pe )
		goto _test_eof141;
case 141:
#line 2550 "parser.cc"
	if ( (*p) == 47u )
		goto tr170;
	goto st0;
tr170:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st142;
st142:
	if ( ++p == pe )
		goto _test_eof142;
case 142:
#line 2562 "parser.cc"
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr171;
	} else if ( (*p) >= 33u )
		goto tr171;
	goto st0;
tr171:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st143;
st143:
	if ( ++p == pe )
		goto _test_eof143;
case 143:
#line 2577 "parser.cc"
	if ( (*p) == 47u )
		goto tr172;
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr171;
	goto st0;
tr172:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st144;
st144:
	if ( ++p == pe )
		goto _test_eof144;
case 144:
#line 2591 "parser.cc"
	if ( (*p) == 32u )
		goto tr173;
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr174;
	} else if ( (*p) >= 33u )
		goto tr174;
	goto st0;
tr173:
#line 104 "common.rl"
	{ user.set(buf); }
	goto st145;
st145:
	if ( ++p == pe )
		goto _test_eof145;
case 145:
#line 2608 "parser.cc"
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr175;
	goto st0;
tr175:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st146;
tr177:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st146;
st146:
	if ( ++p == pe )
		goto _test_eof146;
case 146:
#line 2626 "parser.cc"
	if ( (*p) == 32u )
		goto tr176;
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr177;
	goto st0;
tr176:
#line 71 "common.rl"
	{ pass.set(buf); }
	goto st147;
st147:
	if ( ++p == pe )
		goto _test_eof147;
case 147:
#line 2640 "parser.cc"
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr178;
	goto st0;
tr178:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st148;
tr181:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st148;
st148:
	if ( ++p == pe )
		goto _test_eof148;
case 148:
#line 2658 "parser.cc"
	switch( (*p) ) {
		case 10u: goto tr179;
		case 13u: goto tr180;
	}
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr181;
	goto st0;
tr180:
#line 83 "common.rl"
	{ sessionId.set(buf); }
	goto st149;
st149:
	if ( ++p == pe )
		goto _test_eof149;
case 149:
#line 2674 "parser.cc"
	if ( (*p) == 10u )
		goto tr182;
	goto st0;
tr174:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st150;
st150:
	if ( ++p == pe )
		goto _test_eof150;
case 150:
#line 2686 "parser.cc"
	switch( (*p) ) {
		case 32u: goto tr173;
		case 47u: goto tr172;
	}
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr174;
	goto st0;
st151:
	if ( ++p == pe )
		goto _test_eof151;
case 151:
	switch( (*p) ) {
		case 69u: goto st152;
		case 101u: goto st152;
	}
	goto st0;
st152:
	if ( ++p == pe )
		goto _test_eof152;
case 152:
	switch( (*p) ) {
		case 76u: goto st153;
		case 77u: goto st209;
		case 108u: goto st153;
		case 109u: goto st209;
	}
	goto st0;
st153:
	if ( ++p == pe )
		goto _test_eof153;
case 153:
	switch( (*p) ) {
		case 73u: goto st154;
		case 105u: goto st154;
	}
	goto st0;
st154:
	if ( ++p == pe )
		goto _test_eof154;
case 154:
	switch( (*p) ) {
		case 68u: goto st155;
		case 100u: goto st155;
	}
	goto st0;
st155:
	if ( ++p == pe )
		goto _test_eof155;
case 155:
	if ( (*p) == 95u )
		goto st156;
	goto st0;
st156:
	if ( ++p == pe )
		goto _test_eof156;
case 156:
	switch( (*p) ) {
		case 82u: goto st157;
		case 114u: goto st157;
	}
	goto st0;
st157:
	if ( ++p == pe )
		goto _test_eof157;
case 157:
	switch( (*p) ) {
		case 69u: goto st158;
		case 101u: goto st158;
	}
	goto st0;
st158:
	if ( ++p == pe )
		goto _test_eof158;
case 158:
	switch( (*p) ) {
		case 81u: goto st159;
		case 83u: goto st187;
		case 113u: goto st159;
		case 115u: goto st187;
	}
	goto st0;
st159:
	if ( ++p == pe )
		goto _test_eof159;
case 159:
	switch( (*p) ) {
		case 85u: goto st160;
		case 117u: goto st160;
	}
	goto st0;
st160:
	if ( ++p == pe )
		goto _test_eof160;
case 160:
	switch( (*p) ) {
		case 69u: goto st161;
		case 101u: goto st161;
	}
	goto st0;
st161:
	if ( ++p == pe )
		goto _test_eof161;
case 161:
	switch( (*p) ) {
		case 83u: goto st162;
		case 115u: goto st162;
	}
	goto st0;
st162:
	if ( ++p == pe )
		goto _test_eof162;
case 162:
	switch( (*p) ) {
		case 84u: goto st163;
		case 116u: goto st163;
	}
	goto st0;
st163:
	if ( ++p == pe )
		goto _test_eof163;
case 163:
	if ( (*p) == 32u )
		goto st164;
	goto st0;
st164:
	if ( ++p == pe )
		goto _test_eof164;
case 164:
	if ( (*p) == 100u )
		goto tr198;
	goto st0;
tr198:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st165;
st165:
	if ( ++p == pe )
		goto _test_eof165;
case 165:
#line 2828 "parser.cc"
	if ( (*p) == 115u )
		goto tr199;
	goto st0;
tr199:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st166;
st166:
	if ( ++p == pe )
		goto _test_eof166;
case 166:
#line 2840 "parser.cc"
	if ( (*p) == 110u )
		goto tr200;
	goto st0;
tr200:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st167;
st167:
	if ( ++p == pe )
		goto _test_eof167;
case 167:
#line 2852 "parser.cc"
	if ( (*p) == 112u )
		goto tr201;
	goto st0;
tr201:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st168;
st168:
	if ( ++p == pe )
		goto _test_eof168;
case 168:
#line 2864 "parser.cc"
	if ( (*p) == 58u )
		goto tr202;
	goto st0;
tr202:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st169;
st169:
	if ( ++p == pe )
		goto _test_eof169;
case 169:
#line 2876 "parser.cc"
	if ( (*p) == 47u )
		goto tr203;
	goto st0;
tr203:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st170;
st170:
	if ( ++p == pe )
		goto _test_eof170;
case 170:
#line 2888 "parser.cc"
	if ( (*p) == 47u )
		goto tr204;
	goto st0;
tr204:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st171;
st171:
	if ( ++p == pe )
		goto _test_eof171;
case 171:
#line 2900 "parser.cc"
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr205;
	} else if ( (*p) >= 33u )
		goto tr205;
	goto st0;
tr205:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st172;
st172:
	if ( ++p == pe )
		goto _test_eof172;
case 172:
#line 2915 "parser.cc"
	if ( (*p) == 47u )
		goto tr206;
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr205;
	goto st0;
tr206:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st173;
st173:
	if ( ++p == pe )
		goto _test_eof173;
case 173:
#line 2929 "parser.cc"
	if ( (*p) == 32u )
		goto tr207;
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr208;
	} else if ( (*p) >= 33u )
		goto tr208;
	goto st0;
tr207:
#line 104 "common.rl"
	{ user.set(buf); }
	goto st174;
st174:
	if ( ++p == pe )
		goto _test_eof174;
case 174:
#line 2946 "parser.cc"
	if ( (*p) == 100u )
		goto tr209;
	goto st0;
tr209:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st175;
st175:
	if ( ++p == pe )
		goto _test_eof175;
case 175:
#line 2960 "parser.cc"
	if ( (*p) == 115u )
		goto tr210;
	goto st0;
tr210:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st176;
st176:
	if ( ++p == pe )
		goto _test_eof176;
case 176:
#line 2972 "parser.cc"
	if ( (*p) == 110u )
		goto tr211;
	goto st0;
tr211:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st177;
st177:
	if ( ++p == pe )
		goto _test_eof177;
case 177:
#line 2984 "parser.cc"
	if ( (*p) == 112u )
		goto tr212;
	goto st0;
tr212:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st178;
st178:
	if ( ++p == pe )
		goto _test_eof178;
case 178:
#line 2996 "parser.cc"
	if ( (*p) == 58u )
		goto tr213;
	goto st0;
tr213:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st179;
st179:
	if ( ++p == pe )
		goto _test_eof179;
case 179:
#line 3008 "parser.cc"
	if ( (*p) == 47u )
		goto tr214;
	goto st0;
tr214:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st180;
st180:
	if ( ++p == pe )
		goto _test_eof180;
case 180:
#line 3020 "parser.cc"
	if ( (*p) == 47u )
		goto tr215;
	goto st0;
tr215:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st181;
st181:
	if ( ++p == pe )
		goto _test_eof181;
case 181:
#line 3032 "parser.cc"
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr216;
	} else if ( (*p) >= 33u )
		goto tr216;
	goto st0;
tr216:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st182;
st182:
	if ( ++p == pe )
		goto _test_eof182;
case 182:
#line 3047 "parser.cc"
	if ( (*p) == 47u )
		goto tr217;
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr216;
	goto st0;
tr217:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st183;
st183:
	if ( ++p == pe )
		goto _test_eof183;
case 183:
#line 3061 "parser.cc"
	switch( (*p) ) {
		case 10u: goto tr218;
		case 13u: goto tr219;
	}
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr220;
	} else if ( (*p) >= 33u )
		goto tr220;
	goto st0;
tr219:
#line 101 "common.rl"
	{ iduri.set(buf); }
	goto st184;
st184:
	if ( ++p == pe )
		goto _test_eof184;
case 184:
#line 3080 "parser.cc"
	if ( (*p) == 10u )
		goto tr221;
	goto st0;
tr220:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st185;
st185:
	if ( ++p == pe )
		goto _test_eof185;
case 185:
#line 3092 "parser.cc"
	switch( (*p) ) {
		case 10u: goto tr218;
		case 13u: goto tr219;
		case 47u: goto tr217;
	}
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr220;
	goto st0;
tr208:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st186;
st186:
	if ( ++p == pe )
		goto _test_eof186;
case 186:
#line 3109 "parser.cc"
	switch( (*p) ) {
		case 32u: goto tr207;
		case 47u: goto tr206;
	}
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr208;
	goto st0;
st187:
	if ( ++p == pe )
		goto _test_eof187;
case 187:
	switch( (*p) ) {
		case 80u: goto st188;
		case 112u: goto st188;
	}
	goto st0;
st188:
	if ( ++p == pe )
		goto _test_eof188;
case 188:
	switch( (*p) ) {
		case 79u: goto st189;
		case 111u: goto st189;
	}
	goto st0;
st189:
	if ( ++p == pe )
		goto _test_eof189;
case 189:
	switch( (*p) ) {
		case 78u: goto st190;
		case 110u: goto st190;
	}
	goto st0;
st190:
	if ( ++p == pe )
		goto _test_eof190;
case 190:
	switch( (*p) ) {
		case 83u: goto st191;
		case 115u: goto st191;
	}
	goto st0;
st191:
	if ( ++p == pe )
		goto _test_eof191;
case 191:
	switch( (*p) ) {
		case 69u: goto st192;
		case 101u: goto st192;
	}
	goto st0;
st192:
	if ( ++p == pe )
		goto _test_eof192;
case 192:
	if ( (*p) == 32u )
		goto st193;
	goto st0;
st193:
	if ( ++p == pe )
		goto _test_eof193;
case 193:
	switch( (*p) ) {
		case 45u: goto tr228;
		case 95u: goto tr228;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr228;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr228;
	} else
		goto tr228;
	goto st0;
tr228:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st194;
tr230:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st194;
st194:
	if ( ++p == pe )
		goto _test_eof194;
case 194:
#line 3200 "parser.cc"
	switch( (*p) ) {
		case 32u: goto tr229;
		case 45u: goto tr230;
		case 95u: goto tr230;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr230;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr230;
	} else
		goto tr230;
	goto st0;
tr229:
#line 78 "common.rl"
	{ loginToken.set(buf); }
	goto st195;
st195:
	if ( ++p == pe )
		goto _test_eof195;
case 195:
#line 3223 "parser.cc"
	switch( (*p) ) {
		case 45u: goto tr231;
		case 95u: goto tr231;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr231;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr231;
	} else
		goto tr231;
	goto st0;
tr231:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st196;
tr233:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st196;
st196:
	if ( ++p == pe )
		goto _test_eof196;
case 196:
#line 3251 "parser.cc"
	switch( (*p) ) {
		case 32u: goto tr232;
		case 45u: goto tr233;
		case 95u: goto tr233;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr233;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr233;
	} else
		goto tr233;
	goto st0;
tr232:
#line 72 "common.rl"
	{ reqid.set(buf); }
	goto st197;
st197:
	if ( ++p == pe )
		goto _test_eof197;
case 197:
#line 3274 "parser.cc"
	if ( (*p) == 100u )
		goto tr234;
	goto st0;
tr234:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st198;
st198:
	if ( ++p == pe )
		goto _test_eof198;
case 198:
#line 3288 "parser.cc"
	if ( (*p) == 115u )
		goto tr235;
	goto st0;
tr235:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st199;
st199:
	if ( ++p == pe )
		goto _test_eof199;
case 199:
#line 3300 "parser.cc"
	if ( (*p) == 110u )
		goto tr236;
	goto st0;
tr236:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st200;
st200:
	if ( ++p == pe )
		goto _test_eof200;
case 200:
#line 3312 "parser.cc"
	if ( (*p) == 112u )
		goto tr237;
	goto st0;
tr237:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st201;
st201:
	if ( ++p == pe )
		goto _test_eof201;
case 201:
#line 3324 "parser.cc"
	if ( (*p) == 58u )
		goto tr238;
	goto st0;
tr238:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st202;
st202:
	if ( ++p == pe )
		goto _test_eof202;
case 202:
#line 3336 "parser.cc"
	if ( (*p) == 47u )
		goto tr239;
	goto st0;
tr239:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st203;
st203:
	if ( ++p == pe )
		goto _test_eof203;
case 203:
#line 3348 "parser.cc"
	if ( (*p) == 47u )
		goto tr240;
	goto st0;
tr240:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st204;
st204:
	if ( ++p == pe )
		goto _test_eof204;
case 204:
#line 3360 "parser.cc"
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr241;
	} else if ( (*p) >= 33u )
		goto tr241;
	goto st0;
tr241:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st205;
st205:
	if ( ++p == pe )
		goto _test_eof205;
case 205:
#line 3375 "parser.cc"
	if ( (*p) == 47u )
		goto tr242;
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr241;
	goto st0;
tr242:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st206;
st206:
	if ( ++p == pe )
		goto _test_eof206;
case 206:
#line 3389 "parser.cc"
	switch( (*p) ) {
		case 10u: goto tr243;
		case 13u: goto tr244;
	}
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr245;
	} else if ( (*p) >= 33u )
		goto tr245;
	goto st0;
tr244:
#line 101 "common.rl"
	{ iduri.set(buf); }
	goto st207;
st207:
	if ( ++p == pe )
		goto _test_eof207;
case 207:
#line 3408 "parser.cc"
	if ( (*p) == 10u )
		goto tr246;
	goto st0;
tr245:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st208;
st208:
	if ( ++p == pe )
		goto _test_eof208;
case 208:
#line 3420 "parser.cc"
	switch( (*p) ) {
		case 10u: goto tr243;
		case 13u: goto tr244;
		case 47u: goto tr242;
	}
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr245;
	goto st0;
st209:
	if ( ++p == pe )
		goto _test_eof209;
case 209:
	switch( (*p) ) {
		case 79u: goto st210;
		case 111u: goto st210;
	}
	goto st0;
st210:
	if ( ++p == pe )
		goto _test_eof210;
case 210:
	switch( (*p) ) {
		case 84u: goto st211;
		case 116u: goto st211;
	}
	goto st0;
st211:
	if ( ++p == pe )
		goto _test_eof211;
case 211:
	switch( (*p) ) {
		case 69u: goto st212;
		case 101u: goto st212;
	}
	goto st0;
st212:
	if ( ++p == pe )
		goto _test_eof212;
case 212:
	if ( (*p) == 95u )
		goto st213;
	goto st0;
st213:
	if ( ++p == pe )
		goto _test_eof213;
case 213:
	switch( (*p) ) {
		case 66u: goto st214;
		case 98u: goto st214;
	}
	goto st0;
st214:
	if ( ++p == pe )
		goto _test_eof214;
case 214:
	switch( (*p) ) {
		case 82u: goto st215;
		case 114u: goto st215;
	}
	goto st0;
st215:
	if ( ++p == pe )
		goto _test_eof215;
case 215:
	switch( (*p) ) {
		case 79u: goto st216;
		case 111u: goto st216;
	}
	goto st0;
st216:
	if ( ++p == pe )
		goto _test_eof216;
case 216:
	switch( (*p) ) {
		case 65u: goto st217;
		case 97u: goto st217;
	}
	goto st0;
st217:
	if ( ++p == pe )
		goto _test_eof217;
case 217:
	switch( (*p) ) {
		case 68u: goto st218;
		case 100u: goto st218;
	}
	goto st0;
st218:
	if ( ++p == pe )
		goto _test_eof218;
case 218:
	switch( (*p) ) {
		case 67u: goto st219;
		case 99u: goto st219;
	}
	goto st0;
st219:
	if ( ++p == pe )
		goto _test_eof219;
case 219:
	switch( (*p) ) {
		case 65u: goto st220;
		case 97u: goto st220;
	}
	goto st0;
st220:
	if ( ++p == pe )
		goto _test_eof220;
case 220:
	switch( (*p) ) {
		case 83u: goto st221;
		case 115u: goto st221;
	}
	goto st0;
st221:
	if ( ++p == pe )
		goto _test_eof221;
case 221:
	switch( (*p) ) {
		case 84u: goto st222;
		case 116u: goto st222;
	}
	goto st0;
st222:
	if ( ++p == pe )
		goto _test_eof222;
case 222:
	if ( (*p) == 95u )
		goto st223;
	goto st0;
st223:
	if ( ++p == pe )
		goto _test_eof223;
case 223:
	switch( (*p) ) {
		case 70u: goto st224;
		case 82u: goto st234;
		case 102u: goto st224;
		case 114u: goto st234;
	}
	goto st0;
st224:
	if ( ++p == pe )
		goto _test_eof224;
case 224:
	switch( (*p) ) {
		case 73u: goto st225;
		case 105u: goto st225;
	}
	goto st0;
st225:
	if ( ++p == pe )
		goto _test_eof225;
case 225:
	switch( (*p) ) {
		case 78u: goto st226;
		case 110u: goto st226;
	}
	goto st0;
st226:
	if ( ++p == pe )
		goto _test_eof226;
case 226:
	switch( (*p) ) {
		case 65u: goto st227;
		case 97u: goto st227;
	}
	goto st0;
st227:
	if ( ++p == pe )
		goto _test_eof227;
case 227:
	switch( (*p) ) {
		case 76u: goto st228;
		case 108u: goto st228;
	}
	goto st0;
st228:
	if ( ++p == pe )
		goto _test_eof228;
case 228:
	if ( (*p) == 32u )
		goto st229;
	goto st0;
st229:
	if ( ++p == pe )
		goto _test_eof229;
case 229:
	switch( (*p) ) {
		case 45u: goto tr268;
		case 95u: goto tr268;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr268;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr268;
	} else
		goto tr268;
	goto st0;
tr268:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st230;
tr270:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st230;
st230:
	if ( ++p == pe )
		goto _test_eof230;
case 230:
#line 3636 "parser.cc"
	switch( (*p) ) {
		case 32u: goto tr269;
		case 45u: goto tr270;
		case 95u: goto tr270;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr270;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr270;
	} else
		goto tr270;
	goto st0;
tr269:
#line 79 "common.rl"
	{ floginToken.set(buf); }
	goto st231;
st231:
	if ( ++p == pe )
		goto _test_eof231;
case 231:
#line 3659 "parser.cc"
	switch( (*p) ) {
		case 45u: goto tr271;
		case 95u: goto tr271;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr271;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr271;
	} else
		goto tr271;
	goto st0;
tr271:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st232;
tr274:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st232;
st232:
	if ( ++p == pe )
		goto _test_eof232;
case 232:
#line 3687 "parser.cc"
	switch( (*p) ) {
		case 10u: goto tr272;
		case 13u: goto tr273;
		case 45u: goto tr274;
		case 95u: goto tr274;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr274;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr274;
	} else
		goto tr274;
	goto st0;
tr273:
#line 72 "common.rl"
	{ reqid.set(buf); }
	goto st233;
st233:
	if ( ++p == pe )
		goto _test_eof233;
case 233:
#line 3711 "parser.cc"
	if ( (*p) == 10u )
		goto tr275;
	goto st0;
st234:
	if ( ++p == pe )
		goto _test_eof234;
case 234:
	switch( (*p) ) {
		case 69u: goto st235;
		case 101u: goto st235;
	}
	goto st0;
st235:
	if ( ++p == pe )
		goto _test_eof235;
case 235:
	switch( (*p) ) {
		case 81u: goto st236;
		case 83u: goto st251;
		case 113u: goto st236;
		case 115u: goto st251;
	}
	goto st0;
st236:
	if ( ++p == pe )
		goto _test_eof236;
case 236:
	switch( (*p) ) {
		case 85u: goto st237;
		case 117u: goto st237;
	}
	goto st0;
st237:
	if ( ++p == pe )
		goto _test_eof237;
case 237:
	switch( (*p) ) {
		case 69u: goto st238;
		case 101u: goto st238;
	}
	goto st0;
st238:
	if ( ++p == pe )
		goto _test_eof238;
case 238:
	switch( (*p) ) {
		case 83u: goto st239;
		case 115u: goto st239;
	}
	goto st0;
st239:
	if ( ++p == pe )
		goto _test_eof239;
case 239:
	switch( (*p) ) {
		case 84u: goto st240;
		case 116u: goto st240;
	}
	goto st0;
st240:
	if ( ++p == pe )
		goto _test_eof240;
case 240:
	if ( (*p) == 32u )
		goto st241;
	goto st0;
st241:
	if ( ++p == pe )
		goto _test_eof241;
case 241:
	switch( (*p) ) {
		case 45u: goto tr284;
		case 95u: goto tr284;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr284;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr284;
	} else
		goto tr284;
	goto st0;
tr284:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st242;
tr286:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st242;
st242:
	if ( ++p == pe )
		goto _test_eof242;
case 242:
#line 3809 "parser.cc"
	switch( (*p) ) {
		case 32u: goto tr285;
		case 45u: goto tr286;
		case 95u: goto tr286;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr286;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr286;
	} else
		goto tr286;
	goto st0;
tr285:
#line 79 "common.rl"
	{ floginToken.set(buf); }
	goto st243;
st243:
	if ( ++p == pe )
		goto _test_eof243;
case 243:
#line 3832 "parser.cc"
	if ( (*p) == 48u )
		goto tr287;
	if ( 49u <= (*p) && (*p) <= 57u )
		goto tr288;
	goto st0;
tr287:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st244;
st244:
	if ( ++p == pe )
		goto _test_eof244;
case 244:
#line 3848 "parser.cc"
	if ( 48u <= (*p) && (*p) <= 57u )
		goto tr289;
	goto st0;
tr288:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st245;
tr289:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st245;
st245:
	if ( ++p == pe )
		goto _test_eof245;
case 245:
#line 3866 "parser.cc"
	switch( (*p) ) {
		case 10u: goto tr290;
		case 13u: goto tr291;
	}
	if ( 48u <= (*p) && (*p) <= 57u )
		goto tr289;
	goto st0;
tr290:
#line 142 "common.rl"
	{
			/* Note we must set counter here as well. All lengths are followed
			 * by some block of input. */
			buf.append( 0 );
			length = counter = parseLength( buf.data );

			/* Set the buffer limit temporarily. */
			buf.limit = length;
		}
	goto st246;
st246:
	if ( ++p == pe )
		goto _test_eof246;
case 246:
#line 3890 "parser.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr293;
	} else if ( _widec >= 256 )
		goto tr292;
	goto st0;
tr292:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st247;
tr297:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st247;
st247:
	if ( ++p == pe )
		goto _test_eof247;
case 247:
#line 3916 "parser.cc"
	switch( (*p) ) {
		case 10u: goto tr294;
		case 13u: goto tr295;
	}
	goto st0;
tr295:
#line 156 "common.rl"
	{
		/* Take from the buf and reset the buf's limit. */
		body.set( buf );
		buf.clear();
		buf.limit = buf.defaultLimit;
	}
	goto st248;
st248:
	if ( ++p == pe )
		goto _test_eof248;
case 248:
#line 3935 "parser.cc"
	if ( (*p) == 10u )
		goto tr296;
	goto st0;
tr293:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st249;
tr298:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st249;
st249:
	if ( ++p == pe )
		goto _test_eof249;
case 249:
#line 3953 "parser.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr298;
	} else if ( _widec >= 256 )
		goto tr297;
	goto st0;
tr291:
#line 142 "common.rl"
	{
			/* Note we must set counter here as well. All lengths are followed
			 * by some block of input. */
			buf.append( 0 );
			length = counter = parseLength( buf.data );

			/* Set the buffer limit temporarily. */
			buf.limit = length;
		}
	goto st250;
st250:
	if ( ++p == pe )
		goto _test_eof250;
case 250:
#line 3981 "parser.cc"
	if ( (*p) == 10u )
		goto st246;
	goto st0;
st251:
	if ( ++p == pe )
		goto _test_eof251;
case 251:
	switch( (*p) ) {
		case 80u: goto st252;
		case 112u: goto st252;
	}
	goto st0;
st252:
	if ( ++p == pe )
		goto _test_eof252;
case 252:
	switch( (*p) ) {
		case 79u: goto st253;
		case 111u: goto st253;
	}
	goto st0;
st253:
	if ( ++p == pe )
		goto _test_eof253;
case 253:
	switch( (*p) ) {
		case 78u: goto st254;
		case 110u: goto st254;
	}
	goto st0;
st254:
	if ( ++p == pe )
		goto _test_eof254;
case 254:
	switch( (*p) ) {
		case 83u: goto st255;
		case 115u: goto st255;
	}
	goto st0;
st255:
	if ( ++p == pe )
		goto _test_eof255;
case 255:
	switch( (*p) ) {
		case 69u: goto st256;
		case 101u: goto st256;
	}
	goto st0;
st256:
	if ( ++p == pe )
		goto _test_eof256;
case 256:
	if ( (*p) == 32u )
		goto st257;
	goto st0;
st257:
	if ( ++p == pe )
		goto _test_eof257;
case 257:
	switch( (*p) ) {
		case 45u: goto tr306;
		case 95u: goto tr306;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr306;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr306;
	} else
		goto tr306;
	goto st0;
tr306:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st258;
tr308:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st258;
st258:
	if ( ++p == pe )
		goto _test_eof258;
case 258:
#line 4068 "parser.cc"
	switch( (*p) ) {
		case 32u: goto tr307;
		case 45u: goto tr308;
		case 95u: goto tr308;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr308;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr308;
	} else
		goto tr308;
	goto st0;
tr307:
#line 78 "common.rl"
	{ loginToken.set(buf); }
	goto st259;
st259:
	if ( ++p == pe )
		goto _test_eof259;
case 259:
#line 4091 "parser.cc"
	switch( (*p) ) {
		case 45u: goto tr309;
		case 95u: goto tr309;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr309;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr309;
	} else
		goto tr309;
	goto st0;
tr309:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st260;
tr312:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st260;
st260:
	if ( ++p == pe )
		goto _test_eof260;
case 260:
#line 4119 "parser.cc"
	switch( (*p) ) {
		case 10u: goto tr310;
		case 13u: goto tr311;
		case 45u: goto tr312;
		case 95u: goto tr312;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr312;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr312;
	} else
		goto tr312;
	goto st0;
tr311:
#line 72 "common.rl"
	{ reqid.set(buf); }
	goto st261;
st261:
	if ( ++p == pe )
		goto _test_eof261;
case 261:
#line 4143 "parser.cc"
	if ( (*p) == 10u )
		goto tr313;
	goto st0;
st262:
	if ( ++p == pe )
		goto _test_eof262;
case 262:
	switch( (*p) ) {
		case 85u: goto st263;
		case 117u: goto st263;
	}
	goto st0;
st263:
	if ( ++p == pe )
		goto _test_eof263;
case 263:
	switch( (*p) ) {
		case 66u: goto st264;
		case 98u: goto st264;
	}
	goto st0;
st264:
	if ( ++p == pe )
		goto _test_eof264;
case 264:
	switch( (*p) ) {
		case 77u: goto st265;
		case 109u: goto st265;
	}
	goto st0;
st265:
	if ( ++p == pe )
		goto _test_eof265;
case 265:
	switch( (*p) ) {
		case 73u: goto st266;
		case 105u: goto st266;
	}
	goto st0;
st266:
	if ( ++p == pe )
		goto _test_eof266;
case 266:
	switch( (*p) ) {
		case 84u: goto st267;
		case 116u: goto st267;
	}
	goto st0;
st267:
	if ( ++p == pe )
		goto _test_eof267;
case 267:
	if ( (*p) == 95u )
		goto st268;
	goto st0;
st268:
	if ( ++p == pe )
		goto _test_eof268;
case 268:
	switch( (*p) ) {
		case 66u: goto st269;
		case 70u: goto st288;
		case 77u: goto st299;
		case 98u: goto st269;
		case 102u: goto st288;
		case 109u: goto st299;
	}
	goto st0;
st269:
	if ( ++p == pe )
		goto _test_eof269;
case 269:
	switch( (*p) ) {
		case 82u: goto st270;
		case 114u: goto st270;
	}
	goto st0;
st270:
	if ( ++p == pe )
		goto _test_eof270;
case 270:
	switch( (*p) ) {
		case 79u: goto st271;
		case 111u: goto st271;
	}
	goto st0;
st271:
	if ( ++p == pe )
		goto _test_eof271;
case 271:
	switch( (*p) ) {
		case 65u: goto st272;
		case 97u: goto st272;
	}
	goto st0;
st272:
	if ( ++p == pe )
		goto _test_eof272;
case 272:
	switch( (*p) ) {
		case 68u: goto st273;
		case 100u: goto st273;
	}
	goto st0;
st273:
	if ( ++p == pe )
		goto _test_eof273;
case 273:
	switch( (*p) ) {
		case 67u: goto st274;
		case 99u: goto st274;
	}
	goto st0;
st274:
	if ( ++p == pe )
		goto _test_eof274;
case 274:
	switch( (*p) ) {
		case 65u: goto st275;
		case 97u: goto st275;
	}
	goto st0;
st275:
	if ( ++p == pe )
		goto _test_eof275;
case 275:
	switch( (*p) ) {
		case 83u: goto st276;
		case 115u: goto st276;
	}
	goto st0;
st276:
	if ( ++p == pe )
		goto _test_eof276;
case 276:
	switch( (*p) ) {
		case 84u: goto st277;
		case 116u: goto st277;
	}
	goto st0;
st277:
	if ( ++p == pe )
		goto _test_eof277;
case 277:
	if ( (*p) == 32u )
		goto st278;
	goto st0;
st278:
	if ( ++p == pe )
		goto _test_eof278;
case 278:
	switch( (*p) ) {
		case 45u: goto tr332;
		case 95u: goto tr332;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr332;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr332;
	} else
		goto tr332;
	goto st0;
tr332:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st279;
tr334:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st279;
st279:
	if ( ++p == pe )
		goto _test_eof279;
case 279:
#line 4322 "parser.cc"
	switch( (*p) ) {
		case 32u: goto tr333;
		case 45u: goto tr334;
		case 95u: goto tr334;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr334;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr334;
	} else
		goto tr334;
	goto st0;
tr333:
#line 78 "common.rl"
	{ loginToken.set(buf); }
	goto st280;
st280:
	if ( ++p == pe )
		goto _test_eof280;
case 280:
#line 4345 "parser.cc"
	if ( (*p) == 48u )
		goto tr335;
	if ( 49u <= (*p) && (*p) <= 57u )
		goto tr336;
	goto st0;
tr335:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st281;
st281:
	if ( ++p == pe )
		goto _test_eof281;
case 281:
#line 4361 "parser.cc"
	if ( 48u <= (*p) && (*p) <= 57u )
		goto tr337;
	goto st0;
tr336:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st282;
tr337:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st282;
st282:
	if ( ++p == pe )
		goto _test_eof282;
case 282:
#line 4379 "parser.cc"
	switch( (*p) ) {
		case 10u: goto tr338;
		case 13u: goto tr339;
	}
	if ( 48u <= (*p) && (*p) <= 57u )
		goto tr337;
	goto st0;
tr338:
#line 142 "common.rl"
	{
			/* Note we must set counter here as well. All lengths are followed
			 * by some block of input. */
			buf.append( 0 );
			length = counter = parseLength( buf.data );

			/* Set the buffer limit temporarily. */
			buf.limit = length;
		}
	goto st283;
st283:
	if ( ++p == pe )
		goto _test_eof283;
case 283:
#line 4403 "parser.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr341;
	} else if ( _widec >= 256 )
		goto tr340;
	goto st0;
tr340:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st284;
tr345:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st284;
st284:
	if ( ++p == pe )
		goto _test_eof284;
case 284:
#line 4429 "parser.cc"
	switch( (*p) ) {
		case 10u: goto tr342;
		case 13u: goto tr343;
	}
	goto st0;
tr343:
#line 156 "common.rl"
	{
		/* Take from the buf and reset the buf's limit. */
		body.set( buf );
		buf.clear();
		buf.limit = buf.defaultLimit;
	}
	goto st285;
st285:
	if ( ++p == pe )
		goto _test_eof285;
case 285:
#line 4448 "parser.cc"
	if ( (*p) == 10u )
		goto tr344;
	goto st0;
tr341:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st286;
tr346:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st286;
st286:
	if ( ++p == pe )
		goto _test_eof286;
case 286:
#line 4466 "parser.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr346;
	} else if ( _widec >= 256 )
		goto tr345;
	goto st0;
tr339:
#line 142 "common.rl"
	{
			/* Note we must set counter here as well. All lengths are followed
			 * by some block of input. */
			buf.append( 0 );
			length = counter = parseLength( buf.data );

			/* Set the buffer limit temporarily. */
			buf.limit = length;
		}
	goto st287;
st287:
	if ( ++p == pe )
		goto _test_eof287;
case 287:
#line 4494 "parser.cc"
	if ( (*p) == 10u )
		goto st283;
	goto st0;
st288:
	if ( ++p == pe )
		goto _test_eof288;
case 288:
	switch( (*p) ) {
		case 84u: goto st289;
		case 116u: goto st289;
	}
	goto st0;
st289:
	if ( ++p == pe )
		goto _test_eof289;
case 289:
	switch( (*p) ) {
		case 79u: goto st290;
		case 111u: goto st290;
	}
	goto st0;
st290:
	if ( ++p == pe )
		goto _test_eof290;
case 290:
	switch( (*p) ) {
		case 75u: goto st291;
		case 107u: goto st291;
	}
	goto st0;
st291:
	if ( ++p == pe )
		goto _test_eof291;
case 291:
	switch( (*p) ) {
		case 69u: goto st292;
		case 101u: goto st292;
	}
	goto st0;
st292:
	if ( ++p == pe )
		goto _test_eof292;
case 292:
	switch( (*p) ) {
		case 78u: goto st293;
		case 110u: goto st293;
	}
	goto st0;
st293:
	if ( ++p == pe )
		goto _test_eof293;
case 293:
	if ( (*p) == 32u )
		goto st294;
	goto st0;
st294:
	if ( ++p == pe )
		goto _test_eof294;
case 294:
	switch( (*p) ) {
		case 45u: goto tr354;
		case 95u: goto tr354;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr354;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr354;
	} else
		goto tr354;
	goto st0;
tr354:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st295;
tr356:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st295;
st295:
	if ( ++p == pe )
		goto _test_eof295;
case 295:
#line 4581 "parser.cc"
	switch( (*p) ) {
		case 32u: goto tr355;
		case 45u: goto tr356;
		case 95u: goto tr356;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr356;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr356;
	} else
		goto tr356;
	goto st0;
tr355:
#line 77 "common.rl"
	{ token.set(buf); }
	goto st296;
st296:
	if ( ++p == pe )
		goto _test_eof296;
case 296:
#line 4604 "parser.cc"
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr357;
	goto st0;
tr357:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st297;
tr360:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st297;
st297:
	if ( ++p == pe )
		goto _test_eof297;
case 297:
#line 4622 "parser.cc"
	switch( (*p) ) {
		case 10u: goto tr358;
		case 13u: goto tr359;
	}
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr360;
	goto st0;
tr359:
#line 83 "common.rl"
	{ sessionId.set(buf); }
	goto st298;
st298:
	if ( ++p == pe )
		goto _test_eof298;
case 298:
#line 4638 "parser.cc"
	if ( (*p) == 10u )
		goto tr361;
	goto st0;
st299:
	if ( ++p == pe )
		goto _test_eof299;
case 299:
	switch( (*p) ) {
		case 69u: goto st300;
		case 101u: goto st300;
	}
	goto st0;
st300:
	if ( ++p == pe )
		goto _test_eof300;
case 300:
	switch( (*p) ) {
		case 83u: goto st301;
		case 115u: goto st301;
	}
	goto st0;
st301:
	if ( ++p == pe )
		goto _test_eof301;
case 301:
	switch( (*p) ) {
		case 83u: goto st302;
		case 115u: goto st302;
	}
	goto st0;
st302:
	if ( ++p == pe )
		goto _test_eof302;
case 302:
	switch( (*p) ) {
		case 65u: goto st303;
		case 97u: goto st303;
	}
	goto st0;
st303:
	if ( ++p == pe )
		goto _test_eof303;
case 303:
	switch( (*p) ) {
		case 71u: goto st304;
		case 103u: goto st304;
	}
	goto st0;
st304:
	if ( ++p == pe )
		goto _test_eof304;
case 304:
	switch( (*p) ) {
		case 69u: goto st305;
		case 101u: goto st305;
	}
	goto st0;
st305:
	if ( ++p == pe )
		goto _test_eof305;
case 305:
	if ( (*p) == 32u )
		goto st306;
	goto st0;
st306:
	if ( ++p == pe )
		goto _test_eof306;
case 306:
	switch( (*p) ) {
		case 45u: goto tr369;
		case 95u: goto tr369;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr369;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr369;
	} else
		goto tr369;
	goto st0;
tr369:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st307;
tr371:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st307;
st307:
	if ( ++p == pe )
		goto _test_eof307;
case 307:
#line 4734 "parser.cc"
	switch( (*p) ) {
		case 32u: goto tr370;
		case 45u: goto tr371;
		case 95u: goto tr371;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr371;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr371;
	} else
		goto tr371;
	goto st0;
tr370:
#line 78 "common.rl"
	{ loginToken.set(buf); }
	goto st308;
st308:
	if ( ++p == pe )
		goto _test_eof308;
case 308:
#line 4757 "parser.cc"
	if ( (*p) == 100u )
		goto tr372;
	goto st0;
tr372:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st309;
st309:
	if ( ++p == pe )
		goto _test_eof309;
case 309:
#line 4771 "parser.cc"
	if ( (*p) == 115u )
		goto tr373;
	goto st0;
tr373:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st310;
st310:
	if ( ++p == pe )
		goto _test_eof310;
case 310:
#line 4783 "parser.cc"
	if ( (*p) == 110u )
		goto tr374;
	goto st0;
tr374:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st311;
st311:
	if ( ++p == pe )
		goto _test_eof311;
case 311:
#line 4795 "parser.cc"
	if ( (*p) == 112u )
		goto tr375;
	goto st0;
tr375:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st312;
st312:
	if ( ++p == pe )
		goto _test_eof312;
case 312:
#line 4807 "parser.cc"
	if ( (*p) == 58u )
		goto tr376;
	goto st0;
tr376:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st313;
st313:
	if ( ++p == pe )
		goto _test_eof313;
case 313:
#line 4819 "parser.cc"
	if ( (*p) == 47u )
		goto tr377;
	goto st0;
tr377:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st314;
st314:
	if ( ++p == pe )
		goto _test_eof314;
case 314:
#line 4831 "parser.cc"
	if ( (*p) == 47u )
		goto tr378;
	goto st0;
tr378:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st315;
st315:
	if ( ++p == pe )
		goto _test_eof315;
case 315:
#line 4843 "parser.cc"
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr379;
	} else if ( (*p) >= 33u )
		goto tr379;
	goto st0;
tr379:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st316;
st316:
	if ( ++p == pe )
		goto _test_eof316;
case 316:
#line 4858 "parser.cc"
	if ( (*p) == 47u )
		goto tr380;
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr379;
	goto st0;
tr380:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st317;
st317:
	if ( ++p == pe )
		goto _test_eof317;
case 317:
#line 4872 "parser.cc"
	if ( (*p) == 32u )
		goto tr381;
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr382;
	} else if ( (*p) >= 33u )
		goto tr382;
	goto st0;
tr381:
#line 101 "common.rl"
	{ iduri.set(buf); }
	goto st318;
st318:
	if ( ++p == pe )
		goto _test_eof318;
case 318:
#line 4889 "parser.cc"
	if ( (*p) == 48u )
		goto tr383;
	if ( 49u <= (*p) && (*p) <= 57u )
		goto tr384;
	goto st0;
tr383:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st319;
st319:
	if ( ++p == pe )
		goto _test_eof319;
case 319:
#line 4905 "parser.cc"
	if ( 48u <= (*p) && (*p) <= 57u )
		goto tr385;
	goto st0;
tr384:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st320;
tr385:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st320;
st320:
	if ( ++p == pe )
		goto _test_eof320;
case 320:
#line 4923 "parser.cc"
	switch( (*p) ) {
		case 10u: goto tr386;
		case 13u: goto tr387;
	}
	if ( 48u <= (*p) && (*p) <= 57u )
		goto tr385;
	goto st0;
tr386:
#line 142 "common.rl"
	{
			/* Note we must set counter here as well. All lengths are followed
			 * by some block of input. */
			buf.append( 0 );
			length = counter = parseLength( buf.data );

			/* Set the buffer limit temporarily. */
			buf.limit = length;
		}
	goto st321;
st321:
	if ( ++p == pe )
		goto _test_eof321;
case 321:
#line 4947 "parser.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr389;
	} else if ( _widec >= 256 )
		goto tr388;
	goto st0;
tr388:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st322;
tr393:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st322;
st322:
	if ( ++p == pe )
		goto _test_eof322;
case 322:
#line 4973 "parser.cc"
	switch( (*p) ) {
		case 10u: goto tr390;
		case 13u: goto tr391;
	}
	goto st0;
tr391:
#line 156 "common.rl"
	{
		/* Take from the buf and reset the buf's limit. */
		body.set( buf );
		buf.clear();
		buf.limit = buf.defaultLimit;
	}
	goto st323;
st323:
	if ( ++p == pe )
		goto _test_eof323;
case 323:
#line 4992 "parser.cc"
	if ( (*p) == 10u )
		goto tr392;
	goto st0;
tr389:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st324;
tr394:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st324;
st324:
	if ( ++p == pe )
		goto _test_eof324;
case 324:
#line 5010 "parser.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr394;
	} else if ( _widec >= 256 )
		goto tr393;
	goto st0;
tr387:
#line 142 "common.rl"
	{
			/* Note we must set counter here as well. All lengths are followed
			 * by some block of input. */
			buf.append( 0 );
			length = counter = parseLength( buf.data );

			/* Set the buffer limit temporarily. */
			buf.limit = length;
		}
	goto st325;
st325:
	if ( ++p == pe )
		goto _test_eof325;
case 325:
#line 5038 "parser.cc"
	if ( (*p) == 10u )
		goto st321;
	goto st0;
tr382:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st326;
st326:
	if ( ++p == pe )
		goto _test_eof326;
case 326:
#line 5050 "parser.cc"
	switch( (*p) ) {
		case 32u: goto tr381;
		case 47u: goto tr380;
	}
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr382;
	goto st0;
tr405:
#line 222 "common.rl"
	{ user.set(buf); }
#line 349 "parser.rl"
	{
				message( "command: public_key %s\n", user() );
				server->publicKey( user );
			}
	goto st374;
tr408:
#line 202 "common.rl"
	{ reqid.set( buf ); }
#line 359 "parser.rl"
	{
				message( "command: fetch_requested_relid %s\n", reqid() );
				server->fetchRequestedRelid( reqid );
			}
	goto st374;
tr411:
#line 202 "common.rl"
	{ reqid.set( buf ); }
#line 365 "parser.rl"
	{
				message( "command: fetch_response_relid %s\n", reqid() ) ;
				server->fetchResponseRelid( reqid );
			}
	goto st374;
tr414:
#line 202 "common.rl"
	{ reqid.set( buf ); }
#line 375 "parser.rl"
	{
				message( "command: fetch_ftoken %s\n", reqid() );
				server->fetchFtoken( reqid );
			}
	goto st374;
tr422:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 191 "common.rl"
	{ body.set( buf ); }
#line 384 "parser.rl"
	{
				message( "command: message %s %ld\n", relid(), length );
				server->receiveMessage( relid, body );
			}
	goto st374;
tr431:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 191 "common.rl"
	{ body.set( buf ); }
#line 390 "parser.rl"
	{
				message( "command: fof_message %s %ld\n", relid(), length );
				server->receiveFofMessage( relid, body );
			}
	goto st374;
tr435:
#line 203 "common.rl"
	{ relid.set( buf ); }
#line 396 "parser.rl"
	{
				message( "command: broadcast_recipient %s\n", relid() );
				server->broadcastReceipient( recipientList, relid );
			}
	goto st374;
tr451:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 191 "common.rl"
	{ body.set( buf ); }
#line 402 "parser.rl"
	{
				message( "command: broadcast %s %lld %ld\n", distName(), generation, length );
				server->receiveBroadcastList( recipientList, distName, generation, body );
				recipientList.clear();
			}
	goto st374;
st374:
	if ( ++p == pe )
		goto _test_eof374;
case 374:
#line 5141 "parser.cc"
	switch( (*p) ) {
		case 50u: goto st327;
		case 51u: goto st338;
		case 52u: goto st340;
		case 53u: goto st342;
		case 54u: goto st344;
		case 55u: goto st350;
		case 56u: goto st356;
		case 57u: goto st358;
	}
	goto st0;
st327:
	if ( ++p == pe )
		goto _test_eof327;
case 327:
	if ( (*p) == 100u )
		goto tr396;
	goto st0;
tr396:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st328;
st328:
	if ( ++p == pe )
		goto _test_eof328;
case 328:
#line 5170 "parser.cc"
	if ( (*p) == 115u )
		goto tr397;
	goto st0;
tr397:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st329;
st329:
	if ( ++p == pe )
		goto _test_eof329;
case 329:
#line 5182 "parser.cc"
	if ( (*p) == 110u )
		goto tr398;
	goto st0;
tr398:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st330;
st330:
	if ( ++p == pe )
		goto _test_eof330;
case 330:
#line 5194 "parser.cc"
	if ( (*p) == 112u )
		goto tr399;
	goto st0;
tr399:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st331;
st331:
	if ( ++p == pe )
		goto _test_eof331;
case 331:
#line 5206 "parser.cc"
	if ( (*p) == 58u )
		goto tr400;
	goto st0;
tr400:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st332;
st332:
	if ( ++p == pe )
		goto _test_eof332;
case 332:
#line 5218 "parser.cc"
	if ( (*p) == 47u )
		goto tr401;
	goto st0;
tr401:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st333;
st333:
	if ( ++p == pe )
		goto _test_eof333;
case 333:
#line 5230 "parser.cc"
	if ( (*p) == 47u )
		goto tr402;
	goto st0;
tr402:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st334;
st334:
	if ( ++p == pe )
		goto _test_eof334;
case 334:
#line 5242 "parser.cc"
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr403;
	} else if ( (*p) >= 33u )
		goto tr403;
	goto st0;
tr403:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st335;
st335:
	if ( ++p == pe )
		goto _test_eof335;
case 335:
#line 5257 "parser.cc"
	if ( (*p) == 47u )
		goto tr404;
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr403;
	goto st0;
tr404:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st336;
st336:
	if ( ++p == pe )
		goto _test_eof336;
case 336:
#line 5271 "parser.cc"
	if ( (*p) == 0u )
		goto tr405;
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr406;
	} else if ( (*p) >= 33u )
		goto tr406;
	goto st0;
tr406:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st337;
st337:
	if ( ++p == pe )
		goto _test_eof337;
case 337:
#line 5288 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr405;
		case 47u: goto tr404;
	}
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr406;
	goto st0;
st338:
	if ( ++p == pe )
		goto _test_eof338;
case 338:
	switch( (*p) ) {
		case 45u: goto tr407;
		case 95u: goto tr407;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr407;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr407;
	} else
		goto tr407;
	goto st0;
tr407:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st339;
tr409:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st339;
st339:
	if ( ++p == pe )
		goto _test_eof339;
case 339:
#line 5327 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr408;
		case 45u: goto tr409;
		case 95u: goto tr409;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr409;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr409;
	} else
		goto tr409;
	goto st0;
st340:
	if ( ++p == pe )
		goto _test_eof340;
case 340:
	switch( (*p) ) {
		case 45u: goto tr410;
		case 95u: goto tr410;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr410;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr410;
	} else
		goto tr410;
	goto st0;
tr410:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st341;
tr412:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st341;
st341:
	if ( ++p == pe )
		goto _test_eof341;
case 341:
#line 5373 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr411;
		case 45u: goto tr412;
		case 95u: goto tr412;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr412;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr412;
	} else
		goto tr412;
	goto st0;
st342:
	if ( ++p == pe )
		goto _test_eof342;
case 342:
	switch( (*p) ) {
		case 45u: goto tr413;
		case 95u: goto tr413;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr413;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr413;
	} else
		goto tr413;
	goto st0;
tr413:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st343;
tr415:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st343;
st343:
	if ( ++p == pe )
		goto _test_eof343;
case 343:
#line 5419 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr414;
		case 45u: goto tr415;
		case 95u: goto tr415;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr415;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr415;
	} else
		goto tr415;
	goto st0;
st344:
	if ( ++p == pe )
		goto _test_eof344;
case 344:
	switch( (*p) ) {
		case 45u: goto tr416;
		case 95u: goto tr416;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr416;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr416;
	} else
		goto tr416;
	goto st0;
tr416:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st345;
tr418:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st345;
st345:
	if ( ++p == pe )
		goto _test_eof345;
case 345:
#line 5465 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr417;
		case 45u: goto tr418;
		case 95u: goto tr418;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr418;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr418;
	} else
		goto tr418;
	goto st0;
tr417:
#line 203 "common.rl"
	{ relid.set( buf ); }
	goto st346;
st346:
	if ( ++p == pe )
		goto _test_eof346;
case 346:
#line 5488 "parser.cc"
	if ( (*p) == 0u )
		goto tr419;
	goto tr420;
tr419:
#line 175 "common.rl"
	{ val = 0; }
	goto st347;
st347:
	if ( ++p == pe )
		goto _test_eof347;
case 347:
#line 5500 "parser.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr421;
tr421:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st348;
tr423:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st348;
tr424:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st348;
st348:
	if ( ++p == pe )
		goto _test_eof348;
case 348:
#line 5532 "parser.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr423;
	} else if ( _widec >= 256 )
		goto tr422;
	goto st0;
tr420:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st349;
st349:
	if ( ++p == pe )
		goto _test_eof349;
case 349:
#line 5552 "parser.cc"
	goto tr424;
st350:
	if ( ++p == pe )
		goto _test_eof350;
case 350:
	switch( (*p) ) {
		case 45u: goto tr425;
		case 95u: goto tr425;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr425;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr425;
	} else
		goto tr425;
	goto st0;
tr425:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st351;
tr427:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st351;
st351:
	if ( ++p == pe )
		goto _test_eof351;
case 351:
#line 5585 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr426;
		case 45u: goto tr427;
		case 95u: goto tr427;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr427;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr427;
	} else
		goto tr427;
	goto st0;
tr426:
#line 203 "common.rl"
	{ relid.set( buf ); }
	goto st352;
st352:
	if ( ++p == pe )
		goto _test_eof352;
case 352:
#line 5608 "parser.cc"
	if ( (*p) == 0u )
		goto tr428;
	goto tr429;
tr428:
#line 175 "common.rl"
	{ val = 0; }
	goto st353;
st353:
	if ( ++p == pe )
		goto _test_eof353;
case 353:
#line 5620 "parser.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr430;
tr430:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st354;
tr432:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st354;
tr433:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st354;
st354:
	if ( ++p == pe )
		goto _test_eof354;
case 354:
#line 5652 "parser.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr432;
	} else if ( _widec >= 256 )
		goto tr431;
	goto st0;
tr429:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st355;
st355:
	if ( ++p == pe )
		goto _test_eof355;
case 355:
#line 5672 "parser.cc"
	goto tr433;
st356:
	if ( ++p == pe )
		goto _test_eof356;
case 356:
	switch( (*p) ) {
		case 45u: goto tr434;
		case 95u: goto tr434;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr434;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr434;
	} else
		goto tr434;
	goto st0;
tr434:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st357;
tr436:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st357;
st357:
	if ( ++p == pe )
		goto _test_eof357;
case 357:
#line 5705 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr435;
		case 45u: goto tr436;
		case 95u: goto tr436;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr436;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr436;
	} else
		goto tr436;
	goto st0;
st358:
	if ( ++p == pe )
		goto _test_eof358;
case 358:
	switch( (*p) ) {
		case 45u: goto tr437;
		case 95u: goto tr437;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr437;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr437;
	} else
		goto tr437;
	goto st0;
tr437:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st359;
tr439:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st359;
st359:
	if ( ++p == pe )
		goto _test_eof359;
case 359:
#line 5751 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr438;
		case 45u: goto tr439;
		case 95u: goto tr439;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr439;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr439;
	} else
		goto tr439;
	goto st0;
tr438:
#line 201 "common.rl"
	{ distName.set( buf ); }
	goto st360;
st360:
	if ( ++p == pe )
		goto _test_eof360;
case 360:
#line 5774 "parser.cc"
	goto tr440;
tr440:
#line 195 "common.rl"
	{ generation = 0; }
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st361;
st361:
	if ( ++p == pe )
		goto _test_eof361;
case 361:
#line 5789 "parser.cc"
	goto tr441;
tr441:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st362;
st362:
	if ( ++p == pe )
		goto _test_eof362;
case 362:
#line 5802 "parser.cc"
	goto tr442;
tr442:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st363;
st363:
	if ( ++p == pe )
		goto _test_eof363;
case 363:
#line 5815 "parser.cc"
	goto tr443;
tr443:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st364;
st364:
	if ( ++p == pe )
		goto _test_eof364;
case 364:
#line 5828 "parser.cc"
	goto tr444;
tr444:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st365;
st365:
	if ( ++p == pe )
		goto _test_eof365;
case 365:
#line 5841 "parser.cc"
	goto tr445;
tr445:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st366;
st366:
	if ( ++p == pe )
		goto _test_eof366;
case 366:
#line 5854 "parser.cc"
	goto tr446;
tr446:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st367;
st367:
	if ( ++p == pe )
		goto _test_eof367;
case 367:
#line 5867 "parser.cc"
	goto tr447;
tr447:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st368;
st368:
	if ( ++p == pe )
		goto _test_eof368;
case 368:
#line 5880 "parser.cc"
	if ( (*p) == 0u )
		goto tr448;
	goto tr449;
tr448:
#line 175 "common.rl"
	{ val = 0; }
	goto st369;
st369:
	if ( ++p == pe )
		goto _test_eof369;
case 369:
#line 5892 "parser.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr450;
tr450:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st370;
tr452:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st370;
tr453:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st370;
st370:
	if ( ++p == pe )
		goto _test_eof370;
case 370:
#line 5924 "parser.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr452;
	} else if ( _widec >= 256 )
		goto tr451;
	goto st0;
tr449:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st371;
st371:
	if ( ++p == pe )
		goto _test_eof371;
case 371:
#line 5944 "parser.cc"
	goto tr453;
	}
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
	_test_eof372: cs = 372; goto _test_eof; 
	_test_eof18: cs = 18; goto _test_eof; 
	_test_eof19: cs = 19; goto _test_eof; 
	_test_eof20: cs = 20; goto _test_eof; 
	_test_eof21: cs = 21; goto _test_eof; 
	_test_eof22: cs = 22; goto _test_eof; 
	_test_eof23: cs = 23; goto _test_eof; 
	_test_eof24: cs = 24; goto _test_eof; 
	_test_eof25: cs = 25; goto _test_eof; 
	_test_eof26: cs = 26; goto _test_eof; 
	_test_eof27: cs = 27; goto _test_eof; 
	_test_eof28: cs = 28; goto _test_eof; 
	_test_eof29: cs = 29; goto _test_eof; 
	_test_eof30: cs = 30; goto _test_eof; 
	_test_eof31: cs = 31; goto _test_eof; 
	_test_eof32: cs = 32; goto _test_eof; 
	_test_eof33: cs = 33; goto _test_eof; 
	_test_eof34: cs = 34; goto _test_eof; 
	_test_eof373: cs = 373; goto _test_eof; 
	_test_eof35: cs = 35; goto _test_eof; 
	_test_eof36: cs = 36; goto _test_eof; 
	_test_eof37: cs = 37; goto _test_eof; 
	_test_eof38: cs = 38; goto _test_eof; 
	_test_eof39: cs = 39; goto _test_eof; 
	_test_eof40: cs = 40; goto _test_eof; 
	_test_eof41: cs = 41; goto _test_eof; 
	_test_eof42: cs = 42; goto _test_eof; 
	_test_eof43: cs = 43; goto _test_eof; 
	_test_eof44: cs = 44; goto _test_eof; 
	_test_eof45: cs = 45; goto _test_eof; 
	_test_eof46: cs = 46; goto _test_eof; 
	_test_eof47: cs = 47; goto _test_eof; 
	_test_eof48: cs = 48; goto _test_eof; 
	_test_eof49: cs = 49; goto _test_eof; 
	_test_eof50: cs = 50; goto _test_eof; 
	_test_eof51: cs = 51; goto _test_eof; 
	_test_eof52: cs = 52; goto _test_eof; 
	_test_eof53: cs = 53; goto _test_eof; 
	_test_eof54: cs = 54; goto _test_eof; 
	_test_eof55: cs = 55; goto _test_eof; 
	_test_eof56: cs = 56; goto _test_eof; 
	_test_eof57: cs = 57; goto _test_eof; 
	_test_eof58: cs = 58; goto _test_eof; 
	_test_eof59: cs = 59; goto _test_eof; 
	_test_eof60: cs = 60; goto _test_eof; 
	_test_eof61: cs = 61; goto _test_eof; 
	_test_eof62: cs = 62; goto _test_eof; 
	_test_eof63: cs = 63; goto _test_eof; 
	_test_eof64: cs = 64; goto _test_eof; 
	_test_eof65: cs = 65; goto _test_eof; 
	_test_eof66: cs = 66; goto _test_eof; 
	_test_eof67: cs = 67; goto _test_eof; 
	_test_eof68: cs = 68; goto _test_eof; 
	_test_eof69: cs = 69; goto _test_eof; 
	_test_eof70: cs = 70; goto _test_eof; 
	_test_eof71: cs = 71; goto _test_eof; 
	_test_eof72: cs = 72; goto _test_eof; 
	_test_eof73: cs = 73; goto _test_eof; 
	_test_eof74: cs = 74; goto _test_eof; 
	_test_eof75: cs = 75; goto _test_eof; 
	_test_eof76: cs = 76; goto _test_eof; 
	_test_eof77: cs = 77; goto _test_eof; 
	_test_eof78: cs = 78; goto _test_eof; 
	_test_eof79: cs = 79; goto _test_eof; 
	_test_eof80: cs = 80; goto _test_eof; 
	_test_eof81: cs = 81; goto _test_eof; 
	_test_eof82: cs = 82; goto _test_eof; 
	_test_eof83: cs = 83; goto _test_eof; 
	_test_eof84: cs = 84; goto _test_eof; 
	_test_eof85: cs = 85; goto _test_eof; 
	_test_eof86: cs = 86; goto _test_eof; 
	_test_eof87: cs = 87; goto _test_eof; 
	_test_eof88: cs = 88; goto _test_eof; 
	_test_eof89: cs = 89; goto _test_eof; 
	_test_eof90: cs = 90; goto _test_eof; 
	_test_eof91: cs = 91; goto _test_eof; 
	_test_eof92: cs = 92; goto _test_eof; 
	_test_eof93: cs = 93; goto _test_eof; 
	_test_eof94: cs = 94; goto _test_eof; 
	_test_eof95: cs = 95; goto _test_eof; 
	_test_eof96: cs = 96; goto _test_eof; 
	_test_eof97: cs = 97; goto _test_eof; 
	_test_eof98: cs = 98; goto _test_eof; 
	_test_eof99: cs = 99; goto _test_eof; 
	_test_eof100: cs = 100; goto _test_eof; 
	_test_eof101: cs = 101; goto _test_eof; 
	_test_eof102: cs = 102; goto _test_eof; 
	_test_eof103: cs = 103; goto _test_eof; 
	_test_eof104: cs = 104; goto _test_eof; 
	_test_eof105: cs = 105; goto _test_eof; 
	_test_eof106: cs = 106; goto _test_eof; 
	_test_eof107: cs = 107; goto _test_eof; 
	_test_eof108: cs = 108; goto _test_eof; 
	_test_eof109: cs = 109; goto _test_eof; 
	_test_eof110: cs = 110; goto _test_eof; 
	_test_eof111: cs = 111; goto _test_eof; 
	_test_eof112: cs = 112; goto _test_eof; 
	_test_eof113: cs = 113; goto _test_eof; 
	_test_eof114: cs = 114; goto _test_eof; 
	_test_eof115: cs = 115; goto _test_eof; 
	_test_eof116: cs = 116; goto _test_eof; 
	_test_eof117: cs = 117; goto _test_eof; 
	_test_eof118: cs = 118; goto _test_eof; 
	_test_eof119: cs = 119; goto _test_eof; 
	_test_eof120: cs = 120; goto _test_eof; 
	_test_eof121: cs = 121; goto _test_eof; 
	_test_eof122: cs = 122; goto _test_eof; 
	_test_eof123: cs = 123; goto _test_eof; 
	_test_eof124: cs = 124; goto _test_eof; 
	_test_eof125: cs = 125; goto _test_eof; 
	_test_eof126: cs = 126; goto _test_eof; 
	_test_eof127: cs = 127; goto _test_eof; 
	_test_eof128: cs = 128; goto _test_eof; 
	_test_eof129: cs = 129; goto _test_eof; 
	_test_eof130: cs = 130; goto _test_eof; 
	_test_eof131: cs = 131; goto _test_eof; 
	_test_eof132: cs = 132; goto _test_eof; 
	_test_eof133: cs = 133; goto _test_eof; 
	_test_eof134: cs = 134; goto _test_eof; 
	_test_eof135: cs = 135; goto _test_eof; 
	_test_eof136: cs = 136; goto _test_eof; 
	_test_eof137: cs = 137; goto _test_eof; 
	_test_eof138: cs = 138; goto _test_eof; 
	_test_eof139: cs = 139; goto _test_eof; 
	_test_eof140: cs = 140; goto _test_eof; 
	_test_eof141: cs = 141; goto _test_eof; 
	_test_eof142: cs = 142; goto _test_eof; 
	_test_eof143: cs = 143; goto _test_eof; 
	_test_eof144: cs = 144; goto _test_eof; 
	_test_eof145: cs = 145; goto _test_eof; 
	_test_eof146: cs = 146; goto _test_eof; 
	_test_eof147: cs = 147; goto _test_eof; 
	_test_eof148: cs = 148; goto _test_eof; 
	_test_eof149: cs = 149; goto _test_eof; 
	_test_eof150: cs = 150; goto _test_eof; 
	_test_eof151: cs = 151; goto _test_eof; 
	_test_eof152: cs = 152; goto _test_eof; 
	_test_eof153: cs = 153; goto _test_eof; 
	_test_eof154: cs = 154; goto _test_eof; 
	_test_eof155: cs = 155; goto _test_eof; 
	_test_eof156: cs = 156; goto _test_eof; 
	_test_eof157: cs = 157; goto _test_eof; 
	_test_eof158: cs = 158; goto _test_eof; 
	_test_eof159: cs = 159; goto _test_eof; 
	_test_eof160: cs = 160; goto _test_eof; 
	_test_eof161: cs = 161; goto _test_eof; 
	_test_eof162: cs = 162; goto _test_eof; 
	_test_eof163: cs = 163; goto _test_eof; 
	_test_eof164: cs = 164; goto _test_eof; 
	_test_eof165: cs = 165; goto _test_eof; 
	_test_eof166: cs = 166; goto _test_eof; 
	_test_eof167: cs = 167; goto _test_eof; 
	_test_eof168: cs = 168; goto _test_eof; 
	_test_eof169: cs = 169; goto _test_eof; 
	_test_eof170: cs = 170; goto _test_eof; 
	_test_eof171: cs = 171; goto _test_eof; 
	_test_eof172: cs = 172; goto _test_eof; 
	_test_eof173: cs = 173; goto _test_eof; 
	_test_eof174: cs = 174; goto _test_eof; 
	_test_eof175: cs = 175; goto _test_eof; 
	_test_eof176: cs = 176; goto _test_eof; 
	_test_eof177: cs = 177; goto _test_eof; 
	_test_eof178: cs = 178; goto _test_eof; 
	_test_eof179: cs = 179; goto _test_eof; 
	_test_eof180: cs = 180; goto _test_eof; 
	_test_eof181: cs = 181; goto _test_eof; 
	_test_eof182: cs = 182; goto _test_eof; 
	_test_eof183: cs = 183; goto _test_eof; 
	_test_eof184: cs = 184; goto _test_eof; 
	_test_eof185: cs = 185; goto _test_eof; 
	_test_eof186: cs = 186; goto _test_eof; 
	_test_eof187: cs = 187; goto _test_eof; 
	_test_eof188: cs = 188; goto _test_eof; 
	_test_eof189: cs = 189; goto _test_eof; 
	_test_eof190: cs = 190; goto _test_eof; 
	_test_eof191: cs = 191; goto _test_eof; 
	_test_eof192: cs = 192; goto _test_eof; 
	_test_eof193: cs = 193; goto _test_eof; 
	_test_eof194: cs = 194; goto _test_eof; 
	_test_eof195: cs = 195; goto _test_eof; 
	_test_eof196: cs = 196; goto _test_eof; 
	_test_eof197: cs = 197; goto _test_eof; 
	_test_eof198: cs = 198; goto _test_eof; 
	_test_eof199: cs = 199; goto _test_eof; 
	_test_eof200: cs = 200; goto _test_eof; 
	_test_eof201: cs = 201; goto _test_eof; 
	_test_eof202: cs = 202; goto _test_eof; 
	_test_eof203: cs = 203; goto _test_eof; 
	_test_eof204: cs = 204; goto _test_eof; 
	_test_eof205: cs = 205; goto _test_eof; 
	_test_eof206: cs = 206; goto _test_eof; 
	_test_eof207: cs = 207; goto _test_eof; 
	_test_eof208: cs = 208; goto _test_eof; 
	_test_eof209: cs = 209; goto _test_eof; 
	_test_eof210: cs = 210; goto _test_eof; 
	_test_eof211: cs = 211; goto _test_eof; 
	_test_eof212: cs = 212; goto _test_eof; 
	_test_eof213: cs = 213; goto _test_eof; 
	_test_eof214: cs = 214; goto _test_eof; 
	_test_eof215: cs = 215; goto _test_eof; 
	_test_eof216: cs = 216; goto _test_eof; 
	_test_eof217: cs = 217; goto _test_eof; 
	_test_eof218: cs = 218; goto _test_eof; 
	_test_eof219: cs = 219; goto _test_eof; 
	_test_eof220: cs = 220; goto _test_eof; 
	_test_eof221: cs = 221; goto _test_eof; 
	_test_eof222: cs = 222; goto _test_eof; 
	_test_eof223: cs = 223; goto _test_eof; 
	_test_eof224: cs = 224; goto _test_eof; 
	_test_eof225: cs = 225; goto _test_eof; 
	_test_eof226: cs = 226; goto _test_eof; 
	_test_eof227: cs = 227; goto _test_eof; 
	_test_eof228: cs = 228; goto _test_eof; 
	_test_eof229: cs = 229; goto _test_eof; 
	_test_eof230: cs = 230; goto _test_eof; 
	_test_eof231: cs = 231; goto _test_eof; 
	_test_eof232: cs = 232; goto _test_eof; 
	_test_eof233: cs = 233; goto _test_eof; 
	_test_eof234: cs = 234; goto _test_eof; 
	_test_eof235: cs = 235; goto _test_eof; 
	_test_eof236: cs = 236; goto _test_eof; 
	_test_eof237: cs = 237; goto _test_eof; 
	_test_eof238: cs = 238; goto _test_eof; 
	_test_eof239: cs = 239; goto _test_eof; 
	_test_eof240: cs = 240; goto _test_eof; 
	_test_eof241: cs = 241; goto _test_eof; 
	_test_eof242: cs = 242; goto _test_eof; 
	_test_eof243: cs = 243; goto _test_eof; 
	_test_eof244: cs = 244; goto _test_eof; 
	_test_eof245: cs = 245; goto _test_eof; 
	_test_eof246: cs = 246; goto _test_eof; 
	_test_eof247: cs = 247; goto _test_eof; 
	_test_eof248: cs = 248; goto _test_eof; 
	_test_eof249: cs = 249; goto _test_eof; 
	_test_eof250: cs = 250; goto _test_eof; 
	_test_eof251: cs = 251; goto _test_eof; 
	_test_eof252: cs = 252; goto _test_eof; 
	_test_eof253: cs = 253; goto _test_eof; 
	_test_eof254: cs = 254; goto _test_eof; 
	_test_eof255: cs = 255; goto _test_eof; 
	_test_eof256: cs = 256; goto _test_eof; 
	_test_eof257: cs = 257; goto _test_eof; 
	_test_eof258: cs = 258; goto _test_eof; 
	_test_eof259: cs = 259; goto _test_eof; 
	_test_eof260: cs = 260; goto _test_eof; 
	_test_eof261: cs = 261; goto _test_eof; 
	_test_eof262: cs = 262; goto _test_eof; 
	_test_eof263: cs = 263; goto _test_eof; 
	_test_eof264: cs = 264; goto _test_eof; 
	_test_eof265: cs = 265; goto _test_eof; 
	_test_eof266: cs = 266; goto _test_eof; 
	_test_eof267: cs = 267; goto _test_eof; 
	_test_eof268: cs = 268; goto _test_eof; 
	_test_eof269: cs = 269; goto _test_eof; 
	_test_eof270: cs = 270; goto _test_eof; 
	_test_eof271: cs = 271; goto _test_eof; 
	_test_eof272: cs = 272; goto _test_eof; 
	_test_eof273: cs = 273; goto _test_eof; 
	_test_eof274: cs = 274; goto _test_eof; 
	_test_eof275: cs = 275; goto _test_eof; 
	_test_eof276: cs = 276; goto _test_eof; 
	_test_eof277: cs = 277; goto _test_eof; 
	_test_eof278: cs = 278; goto _test_eof; 
	_test_eof279: cs = 279; goto _test_eof; 
	_test_eof280: cs = 280; goto _test_eof; 
	_test_eof281: cs = 281; goto _test_eof; 
	_test_eof282: cs = 282; goto _test_eof; 
	_test_eof283: cs = 283; goto _test_eof; 
	_test_eof284: cs = 284; goto _test_eof; 
	_test_eof285: cs = 285; goto _test_eof; 
	_test_eof286: cs = 286; goto _test_eof; 
	_test_eof287: cs = 287; goto _test_eof; 
	_test_eof288: cs = 288; goto _test_eof; 
	_test_eof289: cs = 289; goto _test_eof; 
	_test_eof290: cs = 290; goto _test_eof; 
	_test_eof291: cs = 291; goto _test_eof; 
	_test_eof292: cs = 292; goto _test_eof; 
	_test_eof293: cs = 293; goto _test_eof; 
	_test_eof294: cs = 294; goto _test_eof; 
	_test_eof295: cs = 295; goto _test_eof; 
	_test_eof296: cs = 296; goto _test_eof; 
	_test_eof297: cs = 297; goto _test_eof; 
	_test_eof298: cs = 298; goto _test_eof; 
	_test_eof299: cs = 299; goto _test_eof; 
	_test_eof300: cs = 300; goto _test_eof; 
	_test_eof301: cs = 301; goto _test_eof; 
	_test_eof302: cs = 302; goto _test_eof; 
	_test_eof303: cs = 303; goto _test_eof; 
	_test_eof304: cs = 304; goto _test_eof; 
	_test_eof305: cs = 305; goto _test_eof; 
	_test_eof306: cs = 306; goto _test_eof; 
	_test_eof307: cs = 307; goto _test_eof; 
	_test_eof308: cs = 308; goto _test_eof; 
	_test_eof309: cs = 309; goto _test_eof; 
	_test_eof310: cs = 310; goto _test_eof; 
	_test_eof311: cs = 311; goto _test_eof; 
	_test_eof312: cs = 312; goto _test_eof; 
	_test_eof313: cs = 313; goto _test_eof; 
	_test_eof314: cs = 314; goto _test_eof; 
	_test_eof315: cs = 315; goto _test_eof; 
	_test_eof316: cs = 316; goto _test_eof; 
	_test_eof317: cs = 317; goto _test_eof; 
	_test_eof318: cs = 318; goto _test_eof; 
	_test_eof319: cs = 319; goto _test_eof; 
	_test_eof320: cs = 320; goto _test_eof; 
	_test_eof321: cs = 321; goto _test_eof; 
	_test_eof322: cs = 322; goto _test_eof; 
	_test_eof323: cs = 323; goto _test_eof; 
	_test_eof324: cs = 324; goto _test_eof; 
	_test_eof325: cs = 325; goto _test_eof; 
	_test_eof326: cs = 326; goto _test_eof; 
	_test_eof374: cs = 374; goto _test_eof; 
	_test_eof327: cs = 327; goto _test_eof; 
	_test_eof328: cs = 328; goto _test_eof; 
	_test_eof329: cs = 329; goto _test_eof; 
	_test_eof330: cs = 330; goto _test_eof; 
	_test_eof331: cs = 331; goto _test_eof; 
	_test_eof332: cs = 332; goto _test_eof; 
	_test_eof333: cs = 333; goto _test_eof; 
	_test_eof334: cs = 334; goto _test_eof; 
	_test_eof335: cs = 335; goto _test_eof; 
	_test_eof336: cs = 336; goto _test_eof; 
	_test_eof337: cs = 337; goto _test_eof; 
	_test_eof338: cs = 338; goto _test_eof; 
	_test_eof339: cs = 339; goto _test_eof; 
	_test_eof340: cs = 340; goto _test_eof; 
	_test_eof341: cs = 341; goto _test_eof; 
	_test_eof342: cs = 342; goto _test_eof; 
	_test_eof343: cs = 343; goto _test_eof; 
	_test_eof344: cs = 344; goto _test_eof; 
	_test_eof345: cs = 345; goto _test_eof; 
	_test_eof346: cs = 346; goto _test_eof; 
	_test_eof347: cs = 347; goto _test_eof; 
	_test_eof348: cs = 348; goto _test_eof; 
	_test_eof349: cs = 349; goto _test_eof; 
	_test_eof350: cs = 350; goto _test_eof; 
	_test_eof351: cs = 351; goto _test_eof; 
	_test_eof352: cs = 352; goto _test_eof; 
	_test_eof353: cs = 353; goto _test_eof; 
	_test_eof354: cs = 354; goto _test_eof; 
	_test_eof355: cs = 355; goto _test_eof; 
	_test_eof356: cs = 356; goto _test_eof; 
	_test_eof357: cs = 357; goto _test_eof; 
	_test_eof358: cs = 358; goto _test_eof; 
	_test_eof359: cs = 359; goto _test_eof; 
	_test_eof360: cs = 360; goto _test_eof; 
	_test_eof361: cs = 361; goto _test_eof; 
	_test_eof362: cs = 362; goto _test_eof; 
	_test_eof363: cs = 363; goto _test_eof; 
	_test_eof364: cs = 364; goto _test_eof; 
	_test_eof365: cs = 365; goto _test_eof; 
	_test_eof366: cs = 366; goto _test_eof; 
	_test_eof367: cs = 367; goto _test_eof; 
	_test_eof368: cs = 368; goto _test_eof; 
	_test_eof369: cs = 369; goto _test_eof; 
	_test_eof370: cs = 370; goto _test_eof; 
	_test_eof371: cs = 371; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 452 "parser.rl"

	if ( exit && cs >= 
#line 6328 "parser.cc"
372
#line 453 "parser.rl"
 )
		return Stop;

	/* Did parsing succeed? */
	if ( cs == 
#line 6336 "parser.cc"
0
#line 457 "parser.rl"
 )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * response_parser
 */

#define RET_OK0 30
#define RET_OK1 31

Allocated consRet0()
{
	long length = 1;

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, RET_OK0 );

	return packet.relinquish();
}

Allocated consRet1( const String &arg )
{
	long length = 1 + 
			binLength( arg );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, RET_OK1 );
	dest = writeBin( dest, arg );

	return packet.relinquish();
}


#line 514 "parser.rl"



#line 6383 "parser.cc"
static const int response_parser_start = 1;
static const int response_parser_first_final = 6;
static const int response_parser_error = 0;

static const int response_parser_en_main = 1;


#line 517 "parser.rl"

ResponseParser::ResponseParser()
:
	OK(false)
{
	
#line 6398 "parser.cc"
	{
	cs = response_parser_start;
	}

#line 523 "parser.rl"
}

Parser::Control ResponseParser::data( const char *data, int dlen )
{

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	
#line 6413 "parser.cc"
	{
	short _widec;
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	switch( (*p) ) {
		case 30u: goto tr0;
		case 31u: goto st2;
	}
	goto st0;
st0:
cs = 0;
	goto _out;
tr0:
#line 505 "parser.rl"
	{ 
			OK = true; 
			{p++; cs = 6; goto _out;}
		}
	goto st6;
tr6:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 509 "parser.rl"
	{ body.set( buf ); }
#line 510 "parser.rl"
	{
			OK = true;
			{p++; cs = 6; goto _out;}
		}
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 6451 "parser.cc"
	goto st0;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 0u )
		goto tr3;
	goto tr4;
tr3:
#line 175 "common.rl"
	{ val = 0; }
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 6468 "parser.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr5;
tr5:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st4;
tr7:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st4;
tr8:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st4;
st4:
	if ( ++p == pe )
		goto _test_eof4;
case 4:
#line 6500 "parser.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr7;
	} else if ( _widec >= 256 )
		goto tr6;
	goto st0;
tr4:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 6520 "parser.cc"
	goto tr8;
	}
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 532 "parser.rl"

	/* Did parsing succeed? */
	if ( cs == 
#line 6537 "parser.cc"
0
#line 534 "parser.rl"
 )
		throw ParseError( __FILE__, __LINE__ );

	if ( cs >= 
#line 6544 "parser.cc"
6
#line 537 "parser.rl"
 )
		return Stop;

	return Continue;
}

#define PREFRIEND_MESSAGE_NOTIFY_ACCEPT    1
#define PREFRIEND_MESSAGE_REGISTERED       2

Allocated consNotifyAccept( const String &peerNotifyReqid )
{
	long length = 1 +
			stringLength( peerNotifyReqid );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, PREFRIEND_MESSAGE_NOTIFY_ACCEPT );
	dest = writeString( dest, peerNotifyReqid );

	return packet.relinquish();
}

Allocated consRegistered( const String &peerNotifyReqid, const String &friendClaimSigKey )
{
	long length = 1 +
			stringLength( peerNotifyReqid ) +
			binLength( friendClaimSigKey );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, PREFRIEND_MESSAGE_REGISTERED );
	dest = writeString( dest, peerNotifyReqid );
	dest = writeBin( dest, friendClaimSigKey );

	return packet.relinquish();
}


/*
 * prefriend_message_parser
 */


#line 612 "parser.rl"



#line 6596 "parser.cc"
static const int prefriend_message_parser_start = 1;
static const int prefriend_message_parser_first_final = 10;
static const int prefriend_message_parser_error = 0;

static const int prefriend_message_parser_en_main = 1;


#line 615 "parser.rl"

Parser::Control PrefriendParser::data( const char *data, int dlen )
{
	type = Unknown;
	
#line 6610 "parser.cc"
	{
	cs = prefriend_message_parser_start;
	}

#line 620 "parser.rl"

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	
#line 6621 "parser.cc"
	{
	short _widec;
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	switch( (*p) ) {
		case 1u: goto st2;
		case 2u: goto st4;
	}
	goto st0;
st0:
cs = 0;
	goto _out;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	switch( (*p) ) {
		case 45u: goto tr3;
		case 95u: goto tr3;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr3;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr3;
	} else
		goto tr3;
	goto st0;
tr3:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st3;
tr5:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 6668 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr4;
		case 45u: goto tr5;
		case 95u: goto tr5;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr5;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr5;
	} else
		goto tr5;
	goto st0;
tr4:
#line 590 "parser.rl"
	{
			peerNotifyReqid.set(buf);
		}
#line 600 "parser.rl"
	{
			message("prefriend_message: notify_accept %s\n",
					peerNotifyReqid() );
			type = NotifyAccept;
		}
	goto st10;
tr12:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 595 "parser.rl"
	{
			friendClaimSigKey.set( buf );
		}
#line 606 "parser.rl"
	{
			message("prefriend_message: registered %s\n",
					peerNotifyReqid() );
			type = Registered;
		}
	goto st10;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
#line 6713 "parser.cc"
	goto st0;
st4:
	if ( ++p == pe )
		goto _test_eof4;
case 4:
	switch( (*p) ) {
		case 45u: goto tr6;
		case 95u: goto tr6;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr6;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr6;
	} else
		goto tr6;
	goto st0;
tr6:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st5;
tr8:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 6746 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr7;
		case 45u: goto tr8;
		case 95u: goto tr8;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr8;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr8;
	} else
		goto tr8;
	goto st0;
tr7:
#line 590 "parser.rl"
	{
			peerNotifyReqid.set(buf);
		}
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 6771 "parser.cc"
	if ( (*p) == 0u )
		goto tr9;
	goto tr10;
tr9:
#line 175 "common.rl"
	{ val = 0; }
	goto st7;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
#line 6783 "parser.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr11;
tr11:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st8;
tr13:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st8;
tr14:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st8;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
#line 6815 "parser.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr13;
	} else if ( _widec >= 256 )
		goto tr12;
	goto st0;
tr10:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st9;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
#line 6835 "parser.cc"
	goto tr14;
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 625 "parser.rl"

	if ( cs < 
#line 6855 "parser.cc"
10
#line 626 "parser.rl"
 )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * User-User messages
 */

#define MP_BROADCAST_KEY                      1
#define MP_ENCRYPT_REMOTE_BROADCAST_AUTHOR    2
#define MP_ENCRYPT_REMOTE_BROADCAST_SUBJECT   3
#define MP_REPUB_REMOTE_BROADCAST_PUBLISHER   4
#define MP_REPUB_REMOTE_BROADCAST_AUTHOR      5
#define MP_REPUB_REMOTE_BROADCAST_SUBJECT     6
#define MP_RETURN_REMOTE_BROADCAST_AUTHOR     7
#define MP_RETURN_REMOTE_BROADCAST_SUBJECT    8
#define MP_BROADCAST_SUCCESS_AUTHOR           9
#define MP_BROADCAST_SUCCESS_SUBJECT          10
#define MP_USER_MESSAGE                       11

Allocated consBroadcastKey( const String &distName, long long generation, const String &bkKeys )
{
	long length = 1 + 
			stringLength( distName ) +
			sixtyFourBitLength() + 
			binLength( bkKeys );
	
	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, MP_BROADCAST_KEY );
	dest = writeString( dest, distName );
	dest = write64Bit( dest, generation );
	dest = writeBin( dest, bkKeys );

	return packet.relinquish();
}

Allocated consEncryptRemoteBroadcastAuthor( 	
		const String &authorReturnReqid, const String &floginToken, const String &distName, 
		long long generation, const String &recipients, const String &plainMsg )
{
	long length = 1 + 
			stringLength( authorReturnReqid ) +
			stringLength( floginToken ) +
			stringLength( distName ) +
			sixtyFourBitLength() +
			binLength( recipients ) +
			binLength( plainMsg );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, MP_ENCRYPT_REMOTE_BROADCAST_AUTHOR );
	dest = writeString( dest, authorReturnReqid );
	dest = writeString( dest, floginToken );
	dest = writeString( dest, distName );
	dest = write64Bit( dest, generation );
	dest = writeBin( dest, recipients );
	dest = writeBin( dest, plainMsg );

	return packet.relinquish();
}

Allocated consEncryptRemoteBroadcastSubject(
		const String &reqid, const String &authorHash, const String &distName, 
		long long generation, const String &recipients, const String &plainMsg )
{
	long length = 1 + 
			stringLength( reqid ) +
			stringLength( authorHash ) +
			stringLength( distName ) +
			sixtyFourBitLength() +
			binLength( recipients ) + 
			binLength( plainMsg );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, MP_ENCRYPT_REMOTE_BROADCAST_SUBJECT );
	dest = writeString( dest, reqid );
	dest = writeString( dest, authorHash );
	dest = writeString( dest, distName );
	dest = write64Bit( dest, generation );
	dest = writeBin( dest, recipients );
	dest = writeBin( dest, plainMsg );

	return packet.relinquish();
}

Allocated consRepubRemoteBroadcastPublisher(
		const String &messageId, const String &distName,
		long long generation, const String &recipients )
{
	long length = 1 + 
			stringLength( messageId ) +
			stringLength( distName ) +
			sixtyFourBitLength() +
			binLength( recipients );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, MP_REPUB_REMOTE_BROADCAST_PUBLISHER );
	dest = writeString( dest, messageId );
	dest = writeString( dest, distName );
	dest = write64Bit( dest, generation );
	dest = writeBin( dest, recipients );

	return packet.relinquish();
}

Allocated consRepubRemoteBroadcastAuthor(
		const String &publisher, const String &messageId,
		const String &distName, long long generation,
		const String &recipients )
{
	long length = 1 + 
			stringLength( publisher ) +
			stringLength( messageId ) +
			stringLength( distName ) +
			sixtyFourBitLength() +
			binLength( recipients );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, MP_REPUB_REMOTE_BROADCAST_AUTHOR );
	dest = writeString( dest, publisher );
	dest = writeString( dest, messageId );
	dest = writeString( dest, distName );
	dest = write64Bit( dest, generation );
	dest = writeBin( dest, recipients );

	return packet.relinquish();
}

Allocated consRepubRemoteBroadcastSubject(
		const String &publisher, const String &messageId,
		const String &distName, long long generation, 
		const String &recipients )
{
	long length = 1 + 
			stringLength( publisher ) +
			stringLength( messageId ) +
			stringLength( distName ) +
			sixtyFourBitLength() +
			binLength( recipients );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, MP_REPUB_REMOTE_BROADCAST_SUBJECT );
	dest = writeString( dest, publisher );
	dest = writeString( dest, messageId );
	dest = writeString( dest, distName );
	dest = write64Bit( dest, generation );
	dest = writeBin( dest, recipients );

	return packet.relinquish();
}

Allocated consReturnRemoteBroadcastAuthor(
		const String &reqid, const String &encPacket )
{
	long length = 1 + 
			stringLength( reqid ) +
			binLength( encPacket );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, MP_RETURN_REMOTE_BROADCAST_AUTHOR );
	dest = writeString( dest, reqid );
	dest = writeBin( dest, encPacket );

	return packet.relinquish();
}

Allocated consReturnRemoteBroadcastSubject(
		const String &returnReqid, const String &encPacket )
{
	long length = 1 + 
			stringLength( returnReqid ) +
			binLength( encPacket );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, MP_RETURN_REMOTE_BROADCAST_SUBJECT );
	dest = writeString( dest, returnReqid );
	dest = writeBin( dest, encPacket );

	return packet.relinquish();
}

Allocated consBroadcastSuccessAuthor( const String &messageId )
{
	long length = 1 + 
			stringLength( messageId );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, MP_BROADCAST_SUCCESS_AUTHOR );
	dest = writeString( dest, messageId );

	return packet.relinquish();
}

Allocated consBroadcastSuccessSubject( const String &messageId )
{
	long length = 1 + 
			stringLength( messageId );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, MP_BROADCAST_SUCCESS_SUBJECT );
	dest = writeString( dest, messageId );

	return packet.relinquish();
}

Allocated consUserMessage( const String &msg )
{
	long length = 1 + 
			binLength( msg );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, MP_USER_MESSAGE );
	dest = writeBin( dest, msg );

	return packet.relinquish();
}

/*
 * message_parser
 */


#line 949 "parser.rl"



#line 7107 "parser.cc"
static const int message_parser_start = 149;
static const int message_parser_first_final = 149;
static const int message_parser_error = 0;

static const int message_parser_en_main = 149;


#line 952 "parser.rl"

Parser::Control MessageParser::data( const char *data, int dlen )
{
	
#line 7120 "parser.cc"
	{
	cs = message_parser_start;
	}

#line 956 "parser.rl"

	const unsigned char *p = (u_char*) data;
	const unsigned char *pe = (u_char*)data + dlen;
	type = Unknown;

	
#line 7132 "parser.cc"
	{
	short _widec;
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
tr15:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 191 "common.rl"
	{ body.set( buf ); }
#line 889 "parser.rl"
	{
				message( "message: broadcast_key %s %lld\n",
						distName(), generation );
				type = BroadcastKey;
			}
	goto st149;
tr43:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 191 "common.rl"
	{ body.set( buf ); }
#line 895 "parser.rl"
	{
				message( "message: encrypt_remote_broadcast_author %s %s %s %lld %ld\n", 
						reqid(), token(), distName(), generation, length );
				type = EncryptRemoteBroadcastAuthor;
			}
	goto st149;
tr72:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 191 "common.rl"
	{ body.set( buf ); }
#line 901 "parser.rl"
	{
				message( "message: encrypt_remote_broadcast_subject %s %s %s %lld %ld\n", 
						reqid(), hash(), distName(), generation, length );
				type = EncryptRemoteBroadcastSubject;
			}
	goto st149;
tr93:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 191 "common.rl"
	{ body.set( buf ); }
#line 907 "parser.rl"
	{
				message( "message: repub_remote_broadcast_publisher\n" );
				type = RepubRemoteBroadcastPublisher;
			}
	goto st149;
tr124:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 191 "common.rl"
	{ body.set( buf ); }
#line 912 "parser.rl"
	{
				message( "message: repub_remote_broadcast_author\n" );
				type = RepubRemoteBroadcastAuthor;
			}
	goto st149;
tr155:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 191 "common.rl"
	{ body.set( buf ); }
#line 917 "parser.rl"
	{
				message( "message: repub_remote_broadcast_subject\n" );
				type = RepubRemoteBroadcastSubject;
			}
	goto st149;
tr164:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 191 "common.rl"
	{ body.set( buf ); }
#line 922 "parser.rl"
	{
				message( "message: return_remote_broadcast_author %s %ld\n",
						reqid(), length );
				type = ReturnRemoteBroadcastAuthor;
			}
	goto st149;
tr173:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 191 "common.rl"
	{ body.set( buf ); }
#line 928 "parser.rl"
	{
				message( "message: return_remote_broadcast_subject %s %ld\n",
						reqid(), length );
				type = ReturnRemoteBroadcastSubject;
			}
	goto st149;
tr177:
#line 213 "common.rl"
	{ 
			messageId.set( buf );
		}
#line 934 "parser.rl"
	{
				message( "message: broadcast_success_author %s\n", messageId() );
				type = BroadcastSuccessAuthor;
			}
	goto st149;
tr180:
#line 213 "common.rl"
	{ 
			messageId.set( buf );
		}
#line 939 "parser.rl"
	{
				message( "message: broadcast_success_subject %s\n", messageId() );
				type = BroadcastSuccessSubject;
			}
	goto st149;
tr185:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 191 "common.rl"
	{ body.set( buf ); }
#line 944 "parser.rl"
	{
				message( "message: user_message\n" );
				type = UserMessage;
			}
	goto st149;
st149:
	if ( ++p == pe )
		goto _test_eof149;
case 149:
#line 7269 "parser.cc"
	switch( (*p) ) {
		case 1u: goto st1;
		case 2u: goto st15;
		case 3u: goto st37;
		case 4u: goto st59;
		case 5u: goto st75;
		case 6u: goto st102;
		case 7u: goto st129;
		case 8u: goto st135;
		case 9u: goto st141;
		case 10u: goto st143;
		case 11u: goto st145;
	}
	goto st0;
st0:
cs = 0;
	goto _out;
st1:
	if ( ++p == pe )
		goto _test_eof1;
case 1:
	switch( (*p) ) {
		case 45u: goto tr0;
		case 95u: goto tr0;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr0;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr0;
	} else
		goto tr0;
	goto st0;
tr0:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st2;
tr3:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st2;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
#line 7318 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr2;
		case 45u: goto tr3;
		case 95u: goto tr3;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr3;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr3;
	} else
		goto tr3;
	goto st0;
tr2:
#line 201 "common.rl"
	{ distName.set( buf ); }
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 7341 "parser.cc"
	goto tr4;
tr4:
#line 195 "common.rl"
	{ generation = 0; }
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st4;
st4:
	if ( ++p == pe )
		goto _test_eof4;
case 4:
#line 7356 "parser.cc"
	goto tr5;
tr5:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 7369 "parser.cc"
	goto tr6;
tr6:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 7382 "parser.cc"
	goto tr7;
tr7:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st7;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
#line 7395 "parser.cc"
	goto tr8;
tr8:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st8;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
#line 7408 "parser.cc"
	goto tr9;
tr9:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st9;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
#line 7421 "parser.cc"
	goto tr10;
tr10:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st10;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
#line 7434 "parser.cc"
	goto tr11;
tr11:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st11;
st11:
	if ( ++p == pe )
		goto _test_eof11;
case 11:
#line 7447 "parser.cc"
	if ( (*p) == 0u )
		goto tr12;
	goto tr13;
tr12:
#line 175 "common.rl"
	{ val = 0; }
	goto st12;
st12:
	if ( ++p == pe )
		goto _test_eof12;
case 12:
#line 7459 "parser.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr14;
tr14:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st13;
tr16:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st13;
tr17:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st13;
st13:
	if ( ++p == pe )
		goto _test_eof13;
case 13:
#line 7491 "parser.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr16;
	} else if ( _widec >= 256 )
		goto tr15;
	goto st0;
tr13:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st14;
st14:
	if ( ++p == pe )
		goto _test_eof14;
case 14:
#line 7511 "parser.cc"
	goto tr17;
st15:
	if ( ++p == pe )
		goto _test_eof15;
case 15:
	switch( (*p) ) {
		case 45u: goto tr18;
		case 95u: goto tr18;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr18;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr18;
	} else
		goto tr18;
	goto st0;
tr18:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st16;
tr20:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st16;
st16:
	if ( ++p == pe )
		goto _test_eof16;
case 16:
#line 7544 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr19;
		case 45u: goto tr20;
		case 95u: goto tr20;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr20;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr20;
	} else
		goto tr20;
	goto st0;
tr19:
#line 202 "common.rl"
	{ reqid.set( buf ); }
	goto st17;
st17:
	if ( ++p == pe )
		goto _test_eof17;
case 17:
#line 7567 "parser.cc"
	switch( (*p) ) {
		case 45u: goto tr21;
		case 95u: goto tr21;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr21;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr21;
	} else
		goto tr21;
	goto st0;
tr21:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st18;
tr23:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st18;
st18:
	if ( ++p == pe )
		goto _test_eof18;
case 18:
#line 7595 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr22;
		case 45u: goto tr23;
		case 95u: goto tr23;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr23;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr23;
	} else
		goto tr23;
	goto st0;
tr22:
#line 204 "common.rl"
	{ token.set( buf ); }
	goto st19;
st19:
	if ( ++p == pe )
		goto _test_eof19;
case 19:
#line 7618 "parser.cc"
	switch( (*p) ) {
		case 45u: goto tr24;
		case 95u: goto tr24;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr24;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr24;
	} else
		goto tr24;
	goto st0;
tr24:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st20;
tr26:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st20;
st20:
	if ( ++p == pe )
		goto _test_eof20;
case 20:
#line 7646 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr25;
		case 45u: goto tr26;
		case 95u: goto tr26;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr26;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr26;
	} else
		goto tr26;
	goto st0;
tr25:
#line 201 "common.rl"
	{ distName.set( buf ); }
	goto st21;
st21:
	if ( ++p == pe )
		goto _test_eof21;
case 21:
#line 7669 "parser.cc"
	goto tr27;
tr27:
#line 195 "common.rl"
	{ generation = 0; }
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st22;
st22:
	if ( ++p == pe )
		goto _test_eof22;
case 22:
#line 7684 "parser.cc"
	goto tr28;
tr28:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st23;
st23:
	if ( ++p == pe )
		goto _test_eof23;
case 23:
#line 7697 "parser.cc"
	goto tr29;
tr29:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st24;
st24:
	if ( ++p == pe )
		goto _test_eof24;
case 24:
#line 7710 "parser.cc"
	goto tr30;
tr30:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st25;
st25:
	if ( ++p == pe )
		goto _test_eof25;
case 25:
#line 7723 "parser.cc"
	goto tr31;
tr31:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st26;
st26:
	if ( ++p == pe )
		goto _test_eof26;
case 26:
#line 7736 "parser.cc"
	goto tr32;
tr32:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st27;
st27:
	if ( ++p == pe )
		goto _test_eof27;
case 27:
#line 7749 "parser.cc"
	goto tr33;
tr33:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st28;
st28:
	if ( ++p == pe )
		goto _test_eof28;
case 28:
#line 7762 "parser.cc"
	goto tr34;
tr34:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st29;
st29:
	if ( ++p == pe )
		goto _test_eof29;
case 29:
#line 7775 "parser.cc"
	if ( (*p) == 0u )
		goto tr35;
	goto tr36;
tr35:
#line 175 "common.rl"
	{ val = 0; }
	goto st30;
st30:
	if ( ++p == pe )
		goto _test_eof30;
case 30:
#line 7787 "parser.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr37;
tr37:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st31;
tr39:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st31;
tr46:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st31;
st31:
	if ( ++p == pe )
		goto _test_eof31;
case 31:
#line 7819 "parser.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr39;
	} else if ( _widec >= 256 )
		goto tr38;
	goto st0;
tr38:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 188 "common.rl"
	{ recipients.set( buf ); }
	goto st32;
st32:
	if ( ++p == pe )
		goto _test_eof32;
case 32:
#line 7841 "parser.cc"
	if ( (*p) == 0u )
		goto tr40;
	goto tr41;
tr40:
#line 175 "common.rl"
	{ val = 0; }
	goto st33;
st33:
	if ( ++p == pe )
		goto _test_eof33;
case 33:
#line 7853 "parser.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr42;
tr42:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st34;
tr44:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st34;
tr45:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st34;
st34:
	if ( ++p == pe )
		goto _test_eof34;
case 34:
#line 7885 "parser.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr44;
	} else if ( _widec >= 256 )
		goto tr43;
	goto st0;
tr41:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st35;
st35:
	if ( ++p == pe )
		goto _test_eof35;
case 35:
#line 7905 "parser.cc"
	goto tr45;
tr36:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st36;
st36:
	if ( ++p == pe )
		goto _test_eof36;
case 36:
#line 7915 "parser.cc"
	goto tr46;
st37:
	if ( ++p == pe )
		goto _test_eof37;
case 37:
	switch( (*p) ) {
		case 45u: goto tr47;
		case 95u: goto tr47;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr47;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr47;
	} else
		goto tr47;
	goto st0;
tr47:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st38;
tr49:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st38;
st38:
	if ( ++p == pe )
		goto _test_eof38;
case 38:
#line 7948 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr48;
		case 45u: goto tr49;
		case 95u: goto tr49;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr49;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr49;
	} else
		goto tr49;
	goto st0;
tr48:
#line 202 "common.rl"
	{ reqid.set( buf ); }
	goto st39;
st39:
	if ( ++p == pe )
		goto _test_eof39;
case 39:
#line 7971 "parser.cc"
	switch( (*p) ) {
		case 45u: goto tr50;
		case 95u: goto tr50;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr50;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr50;
	} else
		goto tr50;
	goto st0;
tr50:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st40;
tr52:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st40;
st40:
	if ( ++p == pe )
		goto _test_eof40;
case 40:
#line 7999 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr51;
		case 45u: goto tr52;
		case 95u: goto tr52;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr52;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr52;
	} else
		goto tr52;
	goto st0;
tr51:
#line 205 "common.rl"
	{ hash.set( buf ); }
	goto st41;
st41:
	if ( ++p == pe )
		goto _test_eof41;
case 41:
#line 8022 "parser.cc"
	switch( (*p) ) {
		case 45u: goto tr53;
		case 95u: goto tr53;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr53;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr53;
	} else
		goto tr53;
	goto st0;
tr53:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st42;
tr55:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st42;
st42:
	if ( ++p == pe )
		goto _test_eof42;
case 42:
#line 8050 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr54;
		case 45u: goto tr55;
		case 95u: goto tr55;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr55;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr55;
	} else
		goto tr55;
	goto st0;
tr54:
#line 201 "common.rl"
	{ distName.set( buf ); }
	goto st43;
st43:
	if ( ++p == pe )
		goto _test_eof43;
case 43:
#line 8073 "parser.cc"
	goto tr56;
tr56:
#line 195 "common.rl"
	{ generation = 0; }
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st44;
st44:
	if ( ++p == pe )
		goto _test_eof44;
case 44:
#line 8088 "parser.cc"
	goto tr57;
tr57:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st45;
st45:
	if ( ++p == pe )
		goto _test_eof45;
case 45:
#line 8101 "parser.cc"
	goto tr58;
tr58:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st46;
st46:
	if ( ++p == pe )
		goto _test_eof46;
case 46:
#line 8114 "parser.cc"
	goto tr59;
tr59:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st47;
st47:
	if ( ++p == pe )
		goto _test_eof47;
case 47:
#line 8127 "parser.cc"
	goto tr60;
tr60:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st48;
st48:
	if ( ++p == pe )
		goto _test_eof48;
case 48:
#line 8140 "parser.cc"
	goto tr61;
tr61:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st49;
st49:
	if ( ++p == pe )
		goto _test_eof49;
case 49:
#line 8153 "parser.cc"
	goto tr62;
tr62:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st50;
st50:
	if ( ++p == pe )
		goto _test_eof50;
case 50:
#line 8166 "parser.cc"
	goto tr63;
tr63:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st51;
st51:
	if ( ++p == pe )
		goto _test_eof51;
case 51:
#line 8179 "parser.cc"
	if ( (*p) == 0u )
		goto tr64;
	goto tr65;
tr64:
#line 175 "common.rl"
	{ val = 0; }
	goto st52;
st52:
	if ( ++p == pe )
		goto _test_eof52;
case 52:
#line 8191 "parser.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr66;
tr66:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st53;
tr68:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st53;
tr75:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st53;
st53:
	if ( ++p == pe )
		goto _test_eof53;
case 53:
#line 8223 "parser.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr68;
	} else if ( _widec >= 256 )
		goto tr67;
	goto st0;
tr67:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 188 "common.rl"
	{ recipients.set( buf ); }
	goto st54;
st54:
	if ( ++p == pe )
		goto _test_eof54;
case 54:
#line 8245 "parser.cc"
	if ( (*p) == 0u )
		goto tr69;
	goto tr70;
tr69:
#line 175 "common.rl"
	{ val = 0; }
	goto st55;
st55:
	if ( ++p == pe )
		goto _test_eof55;
case 55:
#line 8257 "parser.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr71;
tr71:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st56;
tr73:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st56;
tr74:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st56;
st56:
	if ( ++p == pe )
		goto _test_eof56;
case 56:
#line 8289 "parser.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr73;
	} else if ( _widec >= 256 )
		goto tr72;
	goto st0;
tr70:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st57;
st57:
	if ( ++p == pe )
		goto _test_eof57;
case 57:
#line 8309 "parser.cc"
	goto tr74;
tr65:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st58;
st58:
	if ( ++p == pe )
		goto _test_eof58;
case 58:
#line 8319 "parser.cc"
	goto tr75;
st59:
	if ( ++p == pe )
		goto _test_eof59;
case 59:
	switch( (*p) ) {
		case 43u: goto tr76;
		case 95u: goto tr76;
	}
	if ( (*p) < 48u ) {
		if ( 45u <= (*p) && (*p) <= 46u )
			goto tr76;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 97u <= (*p) && (*p) <= 122u )
				goto tr76;
		} else if ( (*p) >= 65u )
			goto tr76;
	} else
		goto tr76;
	goto st0;
tr76:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
#line 209 "common.rl"
	{
			if ( buf.length > 64 )
				throw ParseError( __FILE__, __LINE__ );
		}
	goto st60;
tr78:
#line 23 "common.rl"
	{ buf.append((*p)); }
#line 209 "common.rl"
	{
			if ( buf.length > 64 )
				throw ParseError( __FILE__, __LINE__ );
		}
	goto st60;
st60:
	if ( ++p == pe )
		goto _test_eof60;
case 60:
#line 8365 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr77;
		case 43u: goto tr78;
		case 95u: goto tr78;
	}
	if ( (*p) < 48u ) {
		if ( 45u <= (*p) && (*p) <= 46u )
			goto tr78;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 97u <= (*p) && (*p) <= 122u )
				goto tr78;
		} else if ( (*p) >= 65u )
			goto tr78;
	} else
		goto tr78;
	goto st0;
tr77:
#line 213 "common.rl"
	{ 
			messageId.set( buf );
		}
	goto st61;
st61:
	if ( ++p == pe )
		goto _test_eof61;
case 61:
#line 8393 "parser.cc"
	switch( (*p) ) {
		case 45u: goto tr79;
		case 95u: goto tr79;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr79;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr79;
	} else
		goto tr79;
	goto st0;
tr79:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st62;
tr81:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st62;
st62:
	if ( ++p == pe )
		goto _test_eof62;
case 62:
#line 8421 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr80;
		case 45u: goto tr81;
		case 95u: goto tr81;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr81;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr81;
	} else
		goto tr81;
	goto st0;
tr80:
#line 201 "common.rl"
	{ distName.set( buf ); }
	goto st63;
st63:
	if ( ++p == pe )
		goto _test_eof63;
case 63:
#line 8444 "parser.cc"
	goto tr82;
tr82:
#line 195 "common.rl"
	{ generation = 0; }
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st64;
st64:
	if ( ++p == pe )
		goto _test_eof64;
case 64:
#line 8459 "parser.cc"
	goto tr83;
tr83:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st65;
st65:
	if ( ++p == pe )
		goto _test_eof65;
case 65:
#line 8472 "parser.cc"
	goto tr84;
tr84:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st66;
st66:
	if ( ++p == pe )
		goto _test_eof66;
case 66:
#line 8485 "parser.cc"
	goto tr85;
tr85:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st67;
st67:
	if ( ++p == pe )
		goto _test_eof67;
case 67:
#line 8498 "parser.cc"
	goto tr86;
tr86:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st68;
st68:
	if ( ++p == pe )
		goto _test_eof68;
case 68:
#line 8511 "parser.cc"
	goto tr87;
tr87:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st69;
st69:
	if ( ++p == pe )
		goto _test_eof69;
case 69:
#line 8524 "parser.cc"
	goto tr88;
tr88:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st70;
st70:
	if ( ++p == pe )
		goto _test_eof70;
case 70:
#line 8537 "parser.cc"
	goto tr89;
tr89:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st71;
st71:
	if ( ++p == pe )
		goto _test_eof71;
case 71:
#line 8550 "parser.cc"
	if ( (*p) == 0u )
		goto tr90;
	goto tr91;
tr90:
#line 175 "common.rl"
	{ val = 0; }
	goto st72;
st72:
	if ( ++p == pe )
		goto _test_eof72;
case 72:
#line 8562 "parser.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr92;
tr92:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st73;
tr94:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st73;
tr95:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st73;
st73:
	if ( ++p == pe )
		goto _test_eof73;
case 73:
#line 8594 "parser.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr94;
	} else if ( _widec >= 256 )
		goto tr93;
	goto st0;
tr91:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st74;
st74:
	if ( ++p == pe )
		goto _test_eof74;
case 74:
#line 8614 "parser.cc"
	goto tr95;
st75:
	if ( ++p == pe )
		goto _test_eof75;
case 75:
	if ( (*p) == 100u )
		goto tr96;
	goto st0;
tr96:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st76;
st76:
	if ( ++p == pe )
		goto _test_eof76;
case 76:
#line 8633 "parser.cc"
	if ( (*p) == 115u )
		goto tr97;
	goto st0;
tr97:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st77;
st77:
	if ( ++p == pe )
		goto _test_eof77;
case 77:
#line 8645 "parser.cc"
	if ( (*p) == 110u )
		goto tr98;
	goto st0;
tr98:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st78;
st78:
	if ( ++p == pe )
		goto _test_eof78;
case 78:
#line 8657 "parser.cc"
	if ( (*p) == 112u )
		goto tr99;
	goto st0;
tr99:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st79;
st79:
	if ( ++p == pe )
		goto _test_eof79;
case 79:
#line 8669 "parser.cc"
	if ( (*p) == 58u )
		goto tr100;
	goto st0;
tr100:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st80;
st80:
	if ( ++p == pe )
		goto _test_eof80;
case 80:
#line 8681 "parser.cc"
	if ( (*p) == 47u )
		goto tr101;
	goto st0;
tr101:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st81;
st81:
	if ( ++p == pe )
		goto _test_eof81;
case 81:
#line 8693 "parser.cc"
	if ( (*p) == 47u )
		goto tr102;
	goto st0;
tr102:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st82;
st82:
	if ( ++p == pe )
		goto _test_eof82;
case 82:
#line 8705 "parser.cc"
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr103;
	} else if ( (*p) >= 33u )
		goto tr103;
	goto st0;
tr103:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st83;
st83:
	if ( ++p == pe )
		goto _test_eof83;
case 83:
#line 8720 "parser.cc"
	if ( (*p) == 47u )
		goto tr104;
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr103;
	goto st0;
tr104:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st84;
st84:
	if ( ++p == pe )
		goto _test_eof84;
case 84:
#line 8734 "parser.cc"
	if ( (*p) == 0u )
		goto tr105;
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr106;
	} else if ( (*p) >= 33u )
		goto tr106;
	goto st0;
tr105:
#line 218 "common.rl"
	{ iduri.set(buf); }
	goto st85;
st85:
	if ( ++p == pe )
		goto _test_eof85;
case 85:
#line 8751 "parser.cc"
	switch( (*p) ) {
		case 43u: goto tr107;
		case 95u: goto tr107;
	}
	if ( (*p) < 48u ) {
		if ( 45u <= (*p) && (*p) <= 46u )
			goto tr107;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 97u <= (*p) && (*p) <= 122u )
				goto tr107;
		} else if ( (*p) >= 65u )
			goto tr107;
	} else
		goto tr107;
	goto st0;
tr107:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
#line 209 "common.rl"
	{
			if ( buf.length > 64 )
				throw ParseError( __FILE__, __LINE__ );
		}
	goto st86;
tr109:
#line 23 "common.rl"
	{ buf.append((*p)); }
#line 209 "common.rl"
	{
			if ( buf.length > 64 )
				throw ParseError( __FILE__, __LINE__ );
		}
	goto st86;
st86:
	if ( ++p == pe )
		goto _test_eof86;
case 86:
#line 8792 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr108;
		case 43u: goto tr109;
		case 95u: goto tr109;
	}
	if ( (*p) < 48u ) {
		if ( 45u <= (*p) && (*p) <= 46u )
			goto tr109;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 97u <= (*p) && (*p) <= 122u )
				goto tr109;
		} else if ( (*p) >= 65u )
			goto tr109;
	} else
		goto tr109;
	goto st0;
tr108:
#line 213 "common.rl"
	{ 
			messageId.set( buf );
		}
	goto st87;
st87:
	if ( ++p == pe )
		goto _test_eof87;
case 87:
#line 8820 "parser.cc"
	switch( (*p) ) {
		case 45u: goto tr110;
		case 95u: goto tr110;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr110;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr110;
	} else
		goto tr110;
	goto st0;
tr110:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st88;
tr112:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st88;
st88:
	if ( ++p == pe )
		goto _test_eof88;
case 88:
#line 8848 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr111;
		case 45u: goto tr112;
		case 95u: goto tr112;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr112;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr112;
	} else
		goto tr112;
	goto st0;
tr111:
#line 201 "common.rl"
	{ distName.set( buf ); }
	goto st89;
st89:
	if ( ++p == pe )
		goto _test_eof89;
case 89:
#line 8871 "parser.cc"
	goto tr113;
tr113:
#line 195 "common.rl"
	{ generation = 0; }
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st90;
st90:
	if ( ++p == pe )
		goto _test_eof90;
case 90:
#line 8886 "parser.cc"
	goto tr114;
tr114:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st91;
st91:
	if ( ++p == pe )
		goto _test_eof91;
case 91:
#line 8899 "parser.cc"
	goto tr115;
tr115:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st92;
st92:
	if ( ++p == pe )
		goto _test_eof92;
case 92:
#line 8912 "parser.cc"
	goto tr116;
tr116:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st93;
st93:
	if ( ++p == pe )
		goto _test_eof93;
case 93:
#line 8925 "parser.cc"
	goto tr117;
tr117:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st94;
st94:
	if ( ++p == pe )
		goto _test_eof94;
case 94:
#line 8938 "parser.cc"
	goto tr118;
tr118:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st95;
st95:
	if ( ++p == pe )
		goto _test_eof95;
case 95:
#line 8951 "parser.cc"
	goto tr119;
tr119:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st96;
st96:
	if ( ++p == pe )
		goto _test_eof96;
case 96:
#line 8964 "parser.cc"
	goto tr120;
tr120:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st97;
st97:
	if ( ++p == pe )
		goto _test_eof97;
case 97:
#line 8977 "parser.cc"
	if ( (*p) == 0u )
		goto tr121;
	goto tr122;
tr121:
#line 175 "common.rl"
	{ val = 0; }
	goto st98;
st98:
	if ( ++p == pe )
		goto _test_eof98;
case 98:
#line 8989 "parser.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr123;
tr123:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st99;
tr125:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st99;
tr126:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st99;
st99:
	if ( ++p == pe )
		goto _test_eof99;
case 99:
#line 9021 "parser.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr125;
	} else if ( _widec >= 256 )
		goto tr124;
	goto st0;
tr122:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st100;
st100:
	if ( ++p == pe )
		goto _test_eof100;
case 100:
#line 9041 "parser.cc"
	goto tr126;
tr106:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st101;
st101:
	if ( ++p == pe )
		goto _test_eof101;
case 101:
#line 9051 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr105;
		case 47u: goto tr104;
	}
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr106;
	goto st0;
st102:
	if ( ++p == pe )
		goto _test_eof102;
case 102:
	if ( (*p) == 100u )
		goto tr127;
	goto st0;
tr127:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st103;
st103:
	if ( ++p == pe )
		goto _test_eof103;
case 103:
#line 9076 "parser.cc"
	if ( (*p) == 115u )
		goto tr128;
	goto st0;
tr128:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st104;
st104:
	if ( ++p == pe )
		goto _test_eof104;
case 104:
#line 9088 "parser.cc"
	if ( (*p) == 110u )
		goto tr129;
	goto st0;
tr129:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st105;
st105:
	if ( ++p == pe )
		goto _test_eof105;
case 105:
#line 9100 "parser.cc"
	if ( (*p) == 112u )
		goto tr130;
	goto st0;
tr130:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st106;
st106:
	if ( ++p == pe )
		goto _test_eof106;
case 106:
#line 9112 "parser.cc"
	if ( (*p) == 58u )
		goto tr131;
	goto st0;
tr131:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st107;
st107:
	if ( ++p == pe )
		goto _test_eof107;
case 107:
#line 9124 "parser.cc"
	if ( (*p) == 47u )
		goto tr132;
	goto st0;
tr132:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st108;
st108:
	if ( ++p == pe )
		goto _test_eof108;
case 108:
#line 9136 "parser.cc"
	if ( (*p) == 47u )
		goto tr133;
	goto st0;
tr133:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st109;
st109:
	if ( ++p == pe )
		goto _test_eof109;
case 109:
#line 9148 "parser.cc"
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr134;
	} else if ( (*p) >= 33u )
		goto tr134;
	goto st0;
tr134:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st110;
st110:
	if ( ++p == pe )
		goto _test_eof110;
case 110:
#line 9163 "parser.cc"
	if ( (*p) == 47u )
		goto tr135;
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr134;
	goto st0;
tr135:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st111;
st111:
	if ( ++p == pe )
		goto _test_eof111;
case 111:
#line 9177 "parser.cc"
	if ( (*p) == 0u )
		goto tr136;
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr137;
	} else if ( (*p) >= 33u )
		goto tr137;
	goto st0;
tr136:
#line 218 "common.rl"
	{ iduri.set(buf); }
	goto st112;
st112:
	if ( ++p == pe )
		goto _test_eof112;
case 112:
#line 9194 "parser.cc"
	switch( (*p) ) {
		case 43u: goto tr138;
		case 95u: goto tr138;
	}
	if ( (*p) < 48u ) {
		if ( 45u <= (*p) && (*p) <= 46u )
			goto tr138;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 97u <= (*p) && (*p) <= 122u )
				goto tr138;
		} else if ( (*p) >= 65u )
			goto tr138;
	} else
		goto tr138;
	goto st0;
tr138:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
#line 209 "common.rl"
	{
			if ( buf.length > 64 )
				throw ParseError( __FILE__, __LINE__ );
		}
	goto st113;
tr140:
#line 23 "common.rl"
	{ buf.append((*p)); }
#line 209 "common.rl"
	{
			if ( buf.length > 64 )
				throw ParseError( __FILE__, __LINE__ );
		}
	goto st113;
st113:
	if ( ++p == pe )
		goto _test_eof113;
case 113:
#line 9235 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr139;
		case 43u: goto tr140;
		case 95u: goto tr140;
	}
	if ( (*p) < 48u ) {
		if ( 45u <= (*p) && (*p) <= 46u )
			goto tr140;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 97u <= (*p) && (*p) <= 122u )
				goto tr140;
		} else if ( (*p) >= 65u )
			goto tr140;
	} else
		goto tr140;
	goto st0;
tr139:
#line 213 "common.rl"
	{ 
			messageId.set( buf );
		}
	goto st114;
st114:
	if ( ++p == pe )
		goto _test_eof114;
case 114:
#line 9263 "parser.cc"
	switch( (*p) ) {
		case 45u: goto tr141;
		case 95u: goto tr141;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr141;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr141;
	} else
		goto tr141;
	goto st0;
tr141:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st115;
tr143:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st115;
st115:
	if ( ++p == pe )
		goto _test_eof115;
case 115:
#line 9291 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr142;
		case 45u: goto tr143;
		case 95u: goto tr143;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr143;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr143;
	} else
		goto tr143;
	goto st0;
tr142:
#line 201 "common.rl"
	{ distName.set( buf ); }
	goto st116;
st116:
	if ( ++p == pe )
		goto _test_eof116;
case 116:
#line 9314 "parser.cc"
	goto tr144;
tr144:
#line 195 "common.rl"
	{ generation = 0; }
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st117;
st117:
	if ( ++p == pe )
		goto _test_eof117;
case 117:
#line 9329 "parser.cc"
	goto tr145;
tr145:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st118;
st118:
	if ( ++p == pe )
		goto _test_eof118;
case 118:
#line 9342 "parser.cc"
	goto tr146;
tr146:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st119;
st119:
	if ( ++p == pe )
		goto _test_eof119;
case 119:
#line 9355 "parser.cc"
	goto tr147;
tr147:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st120;
st120:
	if ( ++p == pe )
		goto _test_eof120;
case 120:
#line 9368 "parser.cc"
	goto tr148;
tr148:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st121;
st121:
	if ( ++p == pe )
		goto _test_eof121;
case 121:
#line 9381 "parser.cc"
	goto tr149;
tr149:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st122;
st122:
	if ( ++p == pe )
		goto _test_eof122;
case 122:
#line 9394 "parser.cc"
	goto tr150;
tr150:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st123;
st123:
	if ( ++p == pe )
		goto _test_eof123;
case 123:
#line 9407 "parser.cc"
	goto tr151;
tr151:
#line 196 "common.rl"
	{ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		}
	goto st124;
st124:
	if ( ++p == pe )
		goto _test_eof124;
case 124:
#line 9420 "parser.cc"
	if ( (*p) == 0u )
		goto tr152;
	goto tr153;
tr152:
#line 175 "common.rl"
	{ val = 0; }
	goto st125;
st125:
	if ( ++p == pe )
		goto _test_eof125;
case 125:
#line 9432 "parser.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr154;
tr154:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st126;
tr156:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st126;
tr157:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st126;
st126:
	if ( ++p == pe )
		goto _test_eof126;
case 126:
#line 9464 "parser.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr156;
	} else if ( _widec >= 256 )
		goto tr155;
	goto st0;
tr153:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st127;
st127:
	if ( ++p == pe )
		goto _test_eof127;
case 127:
#line 9484 "parser.cc"
	goto tr157;
tr137:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st128;
st128:
	if ( ++p == pe )
		goto _test_eof128;
case 128:
#line 9494 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr136;
		case 47u: goto tr135;
	}
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr137;
	goto st0;
st129:
	if ( ++p == pe )
		goto _test_eof129;
case 129:
	switch( (*p) ) {
		case 45u: goto tr158;
		case 95u: goto tr158;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr158;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr158;
	} else
		goto tr158;
	goto st0;
tr158:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st130;
tr160:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st130;
st130:
	if ( ++p == pe )
		goto _test_eof130;
case 130:
#line 9533 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr159;
		case 45u: goto tr160;
		case 95u: goto tr160;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr160;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr160;
	} else
		goto tr160;
	goto st0;
tr159:
#line 202 "common.rl"
	{ reqid.set( buf ); }
	goto st131;
st131:
	if ( ++p == pe )
		goto _test_eof131;
case 131:
#line 9556 "parser.cc"
	if ( (*p) == 0u )
		goto tr161;
	goto tr162;
tr161:
#line 175 "common.rl"
	{ val = 0; }
	goto st132;
st132:
	if ( ++p == pe )
		goto _test_eof132;
case 132:
#line 9568 "parser.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr163;
tr163:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st133;
tr165:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st133;
tr166:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st133;
st133:
	if ( ++p == pe )
		goto _test_eof133;
case 133:
#line 9600 "parser.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr165;
	} else if ( _widec >= 256 )
		goto tr164;
	goto st0;
tr162:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st134;
st134:
	if ( ++p == pe )
		goto _test_eof134;
case 134:
#line 9620 "parser.cc"
	goto tr166;
st135:
	if ( ++p == pe )
		goto _test_eof135;
case 135:
	switch( (*p) ) {
		case 45u: goto tr167;
		case 95u: goto tr167;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr167;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr167;
	} else
		goto tr167;
	goto st0;
tr167:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st136;
tr169:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st136;
st136:
	if ( ++p == pe )
		goto _test_eof136;
case 136:
#line 9653 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr168;
		case 45u: goto tr169;
		case 95u: goto tr169;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr169;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr169;
	} else
		goto tr169;
	goto st0;
tr168:
#line 202 "common.rl"
	{ reqid.set( buf ); }
	goto st137;
st137:
	if ( ++p == pe )
		goto _test_eof137;
case 137:
#line 9676 "parser.cc"
	if ( (*p) == 0u )
		goto tr170;
	goto tr171;
tr170:
#line 175 "common.rl"
	{ val = 0; }
	goto st138;
st138:
	if ( ++p == pe )
		goto _test_eof138;
case 138:
#line 9688 "parser.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr172;
tr172:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st139;
tr174:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st139;
tr175:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st139;
st139:
	if ( ++p == pe )
		goto _test_eof139;
case 139:
#line 9720 "parser.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr174;
	} else if ( _widec >= 256 )
		goto tr173;
	goto st0;
tr171:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st140;
st140:
	if ( ++p == pe )
		goto _test_eof140;
case 140:
#line 9740 "parser.cc"
	goto tr175;
st141:
	if ( ++p == pe )
		goto _test_eof141;
case 141:
	switch( (*p) ) {
		case 43u: goto tr176;
		case 95u: goto tr176;
	}
	if ( (*p) < 48u ) {
		if ( 45u <= (*p) && (*p) <= 46u )
			goto tr176;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 97u <= (*p) && (*p) <= 122u )
				goto tr176;
		} else if ( (*p) >= 65u )
			goto tr176;
	} else
		goto tr176;
	goto st0;
tr176:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
#line 209 "common.rl"
	{
			if ( buf.length > 64 )
				throw ParseError( __FILE__, __LINE__ );
		}
	goto st142;
tr178:
#line 23 "common.rl"
	{ buf.append((*p)); }
#line 209 "common.rl"
	{
			if ( buf.length > 64 )
				throw ParseError( __FILE__, __LINE__ );
		}
	goto st142;
st142:
	if ( ++p == pe )
		goto _test_eof142;
case 142:
#line 9786 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr177;
		case 43u: goto tr178;
		case 95u: goto tr178;
	}
	if ( (*p) < 48u ) {
		if ( 45u <= (*p) && (*p) <= 46u )
			goto tr178;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 97u <= (*p) && (*p) <= 122u )
				goto tr178;
		} else if ( (*p) >= 65u )
			goto tr178;
	} else
		goto tr178;
	goto st0;
st143:
	if ( ++p == pe )
		goto _test_eof143;
case 143:
	switch( (*p) ) {
		case 43u: goto tr179;
		case 95u: goto tr179;
	}
	if ( (*p) < 48u ) {
		if ( 45u <= (*p) && (*p) <= 46u )
			goto tr179;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 97u <= (*p) && (*p) <= 122u )
				goto tr179;
		} else if ( (*p) >= 65u )
			goto tr179;
	} else
		goto tr179;
	goto st0;
tr179:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
#line 209 "common.rl"
	{
			if ( buf.length > 64 )
				throw ParseError( __FILE__, __LINE__ );
		}
	goto st144;
tr181:
#line 23 "common.rl"
	{ buf.append((*p)); }
#line 209 "common.rl"
	{
			if ( buf.length > 64 )
				throw ParseError( __FILE__, __LINE__ );
		}
	goto st144;
st144:
	if ( ++p == pe )
		goto _test_eof144;
case 144:
#line 9848 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr180;
		case 43u: goto tr181;
		case 95u: goto tr181;
	}
	if ( (*p) < 48u ) {
		if ( 45u <= (*p) && (*p) <= 46u )
			goto tr181;
	} else if ( (*p) > 57u ) {
		if ( (*p) > 90u ) {
			if ( 97u <= (*p) && (*p) <= 122u )
				goto tr181;
		} else if ( (*p) >= 65u )
			goto tr181;
	} else
		goto tr181;
	goto st0;
st145:
	if ( ++p == pe )
		goto _test_eof145;
case 145:
	if ( (*p) == 0u )
		goto tr182;
	goto tr183;
tr182:
#line 175 "common.rl"
	{ val = 0; }
	goto st146;
st146:
	if ( ++p == pe )
		goto _test_eof146;
case 146:
#line 9881 "parser.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr184;
tr184:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st147;
tr186:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st147;
tr187:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st147;
st147:
	if ( ++p == pe )
		goto _test_eof147;
case 147:
#line 9913 "parser.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr186;
	} else if ( _widec >= 256 )
		goto tr185;
	goto st0;
tr183:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st148;
st148:
	if ( ++p == pe )
		goto _test_eof148;
case 148:
#line 9933 "parser.cc"
	goto tr187;
	}
	_test_eof149: cs = 149; goto _test_eof; 
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
	_test_eof24: cs = 24; goto _test_eof; 
	_test_eof25: cs = 25; goto _test_eof; 
	_test_eof26: cs = 26; goto _test_eof; 
	_test_eof27: cs = 27; goto _test_eof; 
	_test_eof28: cs = 28; goto _test_eof; 
	_test_eof29: cs = 29; goto _test_eof; 
	_test_eof30: cs = 30; goto _test_eof; 
	_test_eof31: cs = 31; goto _test_eof; 
	_test_eof32: cs = 32; goto _test_eof; 
	_test_eof33: cs = 33; goto _test_eof; 
	_test_eof34: cs = 34; goto _test_eof; 
	_test_eof35: cs = 35; goto _test_eof; 
	_test_eof36: cs = 36; goto _test_eof; 
	_test_eof37: cs = 37; goto _test_eof; 
	_test_eof38: cs = 38; goto _test_eof; 
	_test_eof39: cs = 39; goto _test_eof; 
	_test_eof40: cs = 40; goto _test_eof; 
	_test_eof41: cs = 41; goto _test_eof; 
	_test_eof42: cs = 42; goto _test_eof; 
	_test_eof43: cs = 43; goto _test_eof; 
	_test_eof44: cs = 44; goto _test_eof; 
	_test_eof45: cs = 45; goto _test_eof; 
	_test_eof46: cs = 46; goto _test_eof; 
	_test_eof47: cs = 47; goto _test_eof; 
	_test_eof48: cs = 48; goto _test_eof; 
	_test_eof49: cs = 49; goto _test_eof; 
	_test_eof50: cs = 50; goto _test_eof; 
	_test_eof51: cs = 51; goto _test_eof; 
	_test_eof52: cs = 52; goto _test_eof; 
	_test_eof53: cs = 53; goto _test_eof; 
	_test_eof54: cs = 54; goto _test_eof; 
	_test_eof55: cs = 55; goto _test_eof; 
	_test_eof56: cs = 56; goto _test_eof; 
	_test_eof57: cs = 57; goto _test_eof; 
	_test_eof58: cs = 58; goto _test_eof; 
	_test_eof59: cs = 59; goto _test_eof; 
	_test_eof60: cs = 60; goto _test_eof; 
	_test_eof61: cs = 61; goto _test_eof; 
	_test_eof62: cs = 62; goto _test_eof; 
	_test_eof63: cs = 63; goto _test_eof; 
	_test_eof64: cs = 64; goto _test_eof; 
	_test_eof65: cs = 65; goto _test_eof; 
	_test_eof66: cs = 66; goto _test_eof; 
	_test_eof67: cs = 67; goto _test_eof; 
	_test_eof68: cs = 68; goto _test_eof; 
	_test_eof69: cs = 69; goto _test_eof; 
	_test_eof70: cs = 70; goto _test_eof; 
	_test_eof71: cs = 71; goto _test_eof; 
	_test_eof72: cs = 72; goto _test_eof; 
	_test_eof73: cs = 73; goto _test_eof; 
	_test_eof74: cs = 74; goto _test_eof; 
	_test_eof75: cs = 75; goto _test_eof; 
	_test_eof76: cs = 76; goto _test_eof; 
	_test_eof77: cs = 77; goto _test_eof; 
	_test_eof78: cs = 78; goto _test_eof; 
	_test_eof79: cs = 79; goto _test_eof; 
	_test_eof80: cs = 80; goto _test_eof; 
	_test_eof81: cs = 81; goto _test_eof; 
	_test_eof82: cs = 82; goto _test_eof; 
	_test_eof83: cs = 83; goto _test_eof; 
	_test_eof84: cs = 84; goto _test_eof; 
	_test_eof85: cs = 85; goto _test_eof; 
	_test_eof86: cs = 86; goto _test_eof; 
	_test_eof87: cs = 87; goto _test_eof; 
	_test_eof88: cs = 88; goto _test_eof; 
	_test_eof89: cs = 89; goto _test_eof; 
	_test_eof90: cs = 90; goto _test_eof; 
	_test_eof91: cs = 91; goto _test_eof; 
	_test_eof92: cs = 92; goto _test_eof; 
	_test_eof93: cs = 93; goto _test_eof; 
	_test_eof94: cs = 94; goto _test_eof; 
	_test_eof95: cs = 95; goto _test_eof; 
	_test_eof96: cs = 96; goto _test_eof; 
	_test_eof97: cs = 97; goto _test_eof; 
	_test_eof98: cs = 98; goto _test_eof; 
	_test_eof99: cs = 99; goto _test_eof; 
	_test_eof100: cs = 100; goto _test_eof; 
	_test_eof101: cs = 101; goto _test_eof; 
	_test_eof102: cs = 102; goto _test_eof; 
	_test_eof103: cs = 103; goto _test_eof; 
	_test_eof104: cs = 104; goto _test_eof; 
	_test_eof105: cs = 105; goto _test_eof; 
	_test_eof106: cs = 106; goto _test_eof; 
	_test_eof107: cs = 107; goto _test_eof; 
	_test_eof108: cs = 108; goto _test_eof; 
	_test_eof109: cs = 109; goto _test_eof; 
	_test_eof110: cs = 110; goto _test_eof; 
	_test_eof111: cs = 111; goto _test_eof; 
	_test_eof112: cs = 112; goto _test_eof; 
	_test_eof113: cs = 113; goto _test_eof; 
	_test_eof114: cs = 114; goto _test_eof; 
	_test_eof115: cs = 115; goto _test_eof; 
	_test_eof116: cs = 116; goto _test_eof; 
	_test_eof117: cs = 117; goto _test_eof; 
	_test_eof118: cs = 118; goto _test_eof; 
	_test_eof119: cs = 119; goto _test_eof; 
	_test_eof120: cs = 120; goto _test_eof; 
	_test_eof121: cs = 121; goto _test_eof; 
	_test_eof122: cs = 122; goto _test_eof; 
	_test_eof123: cs = 123; goto _test_eof; 
	_test_eof124: cs = 124; goto _test_eof; 
	_test_eof125: cs = 125; goto _test_eof; 
	_test_eof126: cs = 126; goto _test_eof; 
	_test_eof127: cs = 127; goto _test_eof; 
	_test_eof128: cs = 128; goto _test_eof; 
	_test_eof129: cs = 129; goto _test_eof; 
	_test_eof130: cs = 130; goto _test_eof; 
	_test_eof131: cs = 131; goto _test_eof; 
	_test_eof132: cs = 132; goto _test_eof; 
	_test_eof133: cs = 133; goto _test_eof; 
	_test_eof134: cs = 134; goto _test_eof; 
	_test_eof135: cs = 135; goto _test_eof; 
	_test_eof136: cs = 136; goto _test_eof; 
	_test_eof137: cs = 137; goto _test_eof; 
	_test_eof138: cs = 138; goto _test_eof; 
	_test_eof139: cs = 139; goto _test_eof; 
	_test_eof140: cs = 140; goto _test_eof; 
	_test_eof141: cs = 141; goto _test_eof; 
	_test_eof142: cs = 142; goto _test_eof; 
	_test_eof143: cs = 143; goto _test_eof; 
	_test_eof144: cs = 144; goto _test_eof; 
	_test_eof145: cs = 145; goto _test_eof; 
	_test_eof146: cs = 146; goto _test_eof; 
	_test_eof147: cs = 147; goto _test_eof; 
	_test_eof148: cs = 148; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 962 "parser.rl"

	if ( cs < 
#line 10093 "parser.cc"
149
#line 963 "parser.rl"
 )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

#define FOF_MP_RB_BROADCAST_KEY 1

Allocated consRbBroadcastKey( const String &rbSigKeyHash )
{
	long length = 1 + 
			stringLength( rbSigKeyHash );
	
	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, FOF_MP_RB_BROADCAST_KEY );
	dest = writeString( dest, rbSigKeyHash );

	return packet.relinquish();
}

/*
 * fof_message_parser
 */


#line 1003 "parser.rl"



#line 10127 "parser.cc"
static const int fof_message_parser_start = 3;
static const int fof_message_parser_first_final = 3;
static const int fof_message_parser_error = 0;

static const int fof_message_parser_en_main = 3;


#line 1006 "parser.rl"

Parser::Control FofMessageParser::data( const char *data, int dlen )
{
	
#line 10140 "parser.cc"
	{
	cs = fof_message_parser_start;
	}

#line 1010 "parser.rl"

	const unsigned char *p = (u_char*) data;
	const unsigned char *pe = (u_char*)data + dlen;
	type = Unknown;

	
#line 10152 "parser.cc"
	{
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
tr2:
#line 205 "common.rl"
	{ hash.set( buf ); }
#line 998 "parser.rl"
	{
				message( "message: rb_broadcast_key %s\n", hash() );
				type = RbBroadcastKey;
			}
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 10171 "parser.cc"
	if ( (*p) == 1u )
		goto st1;
	goto st0;
st0:
cs = 0;
	goto _out;
st1:
	if ( ++p == pe )
		goto _test_eof1;
case 1:
	switch( (*p) ) {
		case 45u: goto tr0;
		case 95u: goto tr0;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr0;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr0;
	} else
		goto tr0;
	goto st0;
tr0:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st2;
tr3:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st2;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
#line 10209 "parser.cc"
	switch( (*p) ) {
		case 0u: goto tr2;
		case 45u: goto tr3;
		case 95u: goto tr3;
	}
	if ( (*p) < 65u ) {
		if ( 48u <= (*p) && (*p) <= 57u )
			goto tr3;
	} else if ( (*p) > 90u ) {
		if ( 97u <= (*p) && (*p) <= 122u )
			goto tr3;
	} else
		goto tr3;
	goto st0;
	}
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof1: cs = 1; goto _test_eof; 
	_test_eof2: cs = 2; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 1016 "parser.rl"

	if ( cs < 
#line 10236 "parser.cc"
3
#line 1017 "parser.rl"
 )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

Allocated Server::fetchPublicKeyNet( const String &host, const String &user )
{
	message( "fetching public key for %s from %s\n", user(), host() );
	TlsConnect tlsConnect( c, tlsContext );

	/* Connect and send the public key request. */
	tlsConnect.connect( host );
	String publicKey = consPublicKey( user );
	tlsConnect.write( publicKey );

	/* Parse the result. */
	ResponseParser parser;
	tlsConnect.readParse( parser );

	if ( parser.body.length == 0 )
		throw ParseError( __FILE__, __LINE__ );

	return parser.body.relinquish();
}

Allocated Server::fetchRequestedRelidNet( const String &host,
		const String &reqid )
{
	TlsConnect tlsConnect( c, tlsContext );

	tlsConnect.connect( host );

	/* Send the request. */
	String fetchRequestedRelid = consFetchRequestedRelid( reqid );
	tlsConnect.write( fetchRequestedRelid );

	/* Parse the result. */
	ResponseParser parser;
	tlsConnect.readParse( parser );

	if ( parser.body.length == 0 )
		throw ParseError( __FILE__, __LINE__ );

	/* Output. */
	return parser.body.relinquish();
}

Allocated Server::fetchResponseRelidNet( const String &host,
		const String &reqid )
{
	TlsConnect tlsConnect( c, tlsContext );

	tlsConnect.connect( host );

	/* Send the request. */
	String fetchResponseRelid = consFetchResponseRelid( reqid );
	tlsConnect.write( fetchResponseRelid );

	/* Parse the result. */
	ResponseParser parser;
	tlsConnect.readParse( parser );

	if ( parser.body.length == 0 )
		throw ParseError( __FILE__, __LINE__ );

	/* Output. */
	return parser.body.relinquish();
}

Allocated Server::fetchFtokenNet( const String &host,
		const String &reqid )
{
	TlsConnect tlsConnect( c, tlsContext );

	tlsConnect.connect( host );

	/* Send the request. */
	String fetchFtoken = consFetchFtoken( reqid );
	tlsConnect.write( fetchFtoken );

	/* Parse the result. */
	ResponseParser parser;
	tlsConnect.readParse( parser );

	if ( parser.body.length == 0 )
		throw ParseError( __FILE__, __LINE__ );

	/* Output. */
	return parser.body.relinquish();
}

Allocated QueueRunner::sendMessageNet( const String &host,
		const String &relid, const String &msg )
{
	TlsConnect tlsConnect( c, tlsContext );
	ResponseParser parser;

	tlsConnect.connect( host );

	/* Send the request. */
	String message = consMessage( relid, msg );
	tlsConnect.write( message );

	tlsConnect.readParse( parser );

	return parser.body.length > 0 ?
			parser.body.relinquish() : Allocated();
}

Allocated QueueRunner::sendFofMessageNet( const String &host,
		const String &relid, const String &msg )
{
	message( "sending FOF message NET\n" );

	TlsConnect tlsConnect( c, tlsContext );
	ResponseParser parser;

	tlsConnect.connect( host );

	/* Send the request. */
	String fofMessage = consFofMessage( relid, msg );
	tlsConnect.write( fofMessage );

	tlsConnect.readParse( parser );

	return parser.body.length > 0 ?
			parser.body.relinquish() : Allocated();
}

void QueueRunner::sendBroadcastNet( const String &host,
		RecipientList &recipientList, const String &network,
		long long keyGen, const String &msg )
{
	TlsConnect tlsConnect( c, tlsContext );
	tlsConnect.connect( host );
	
	for ( RecipientList::iterator r = recipientList.begin(); r != recipientList.end(); r++ ) {
		/* FIXME: catch errors here. */
		String relid = Pointer( r->c_str() );
		String broadcastReceipient = consBroadcastRecipient( relid );
		tlsConnect.write( broadcastReceipient );

		ResponseParser parser;
		tlsConnect.readParse( parser );
		if ( parser.body.length > 0 )
			throw ParseError( __FILE__, __LINE__ );
	}

	/* Send the request. */
	String broadcast = consBroadcast( network, keyGen, msg );
	tlsConnect.write( broadcast );

	ResponseParser parser;
	tlsConnect.readParse( parser );

	if ( parser.body.length > 0 )
		throw ParseError( __FILE__, __LINE__ );
}

