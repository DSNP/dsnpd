
#line 1 "rcfile.rl"
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
#include "error.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define CFG_READ_LEN 1024

ConfigParser::ConfigParser( const char *confFile, ConfigSlice requestedSlice, Config *config )
:
	config(config),
	curSect(0),
	nextConfigSectionId(0),
	requestedSlice(requestedSlice)
{
	/* Now there is only one config. */
	curSect = new ConfigSection( 0 );

	debug( DBG_CFG, "CFG: main section\n" );

	config->main = curSect;

	FILE *rcfile = fopen( confFile, "r" );
	if ( rcfile == 0 ) 
		fatal( "could not open conf file %s\n", confFile );
	
	init();

	/* Read and parse. */
	char *buf = new char[CFG_READ_LEN];
	while ( true ) {
		long len = fread( buf, 1, CFG_READ_LEN, rcfile );

		if ( len > 0 )
			parseData( buf, len );
		
		if ( len < CFG_READ_LEN )
			break;
	}

	/* Cause EOF. */
	parseData( 0, 0 );

	fclose( rcfile );
	delete[] buf;
}

/* NOTE: The indicies into this array must match the switch in the setValue
 * function. */
ConfigVar ConfigParser::varNames[] = {
	{ "CFG_PORT",             SliceDaemon },
	{ "CFG_DB_HOST",          SliceDaemon },
	{ "CFG_DB_USER",          SliceDaemon },
	{ "CFG_DB_DATABASE",      SliceDaemon },
	{ "CFG_DB_PASS",          SliceDaemon },
	{ "CFG_KEYS_HOST",        SliceKeyAgent },
	{ "CFG_KEYS_USER",        SliceKeyAgent },
	{ "CFG_KEYS_DATABASE",    SliceKeyAgent },
	{ "CFG_KEYS_PASS",        SliceKeyAgent },
	{ "CFG_NOTIF_HOST",       SliceNotifAgent },
	{ "CFG_NOTIF_KEYS_USER",  SliceNotifAgent },
	{ "CFG_NOTIF_DATABASE",   SliceNotifAgent },
	{ "CFG_NOTIF_PASS",       SliceNotifAgent },
	{ "CFG_HOST",             SliceDaemon },
	{ "CFG_TLS_CRT",          SliceDaemon },
	{ "CFG_TLS_KEY",          SliceDaemon },
	{ "CFG_NOTIFICATION",     SliceNotifAgent },
	{ "CFG_COMM_KEY",         SliceDaemon },
	{ "CFG_COMM_KEY",         SliceNotifAgent }
};


void ConfigParser::setValue( int i, const String &value )
{
	switch ( i ) {
		case 0:  curSect->CFG_PORT = value; break;
		case 1:  curSect->CFG_DB_HOST = value; break;
		case 2:  curSect->CFG_DB_USER = value; break;
		case 3:  curSect->CFG_DB_DATABASE = value; break;
		case 4:  curSect->CFG_DB_PASS = value; break;
		case 5:  curSect->CFG_KEYS_HOST = value; break;
		case 6:  curSect->CFG_KEYS_USER = value; break;
		case 7:  curSect->CFG_KEYS_DATABASE = value; break;
		case 8:  curSect->CFG_KEYS_PASS = value; break;
		case 9:  curSect->CFG_NOTIF_HOST = value; break;
		case 10: curSect->CFG_NOTIF_KEYS_USER = value; break;
		case 11: curSect->CFG_NOTIF_DATABASE = value; break;
		case 12: curSect->CFG_NOTIF_PASS = value; break;
		case 13: curSect->CFG_HOST = value; break;
		case 14: curSect->CFG_TLS_CRT = value; break;
		case 15: curSect->CFG_TLS_KEY = value; break;
		case 16: curSect->CFG_NOTIFICATION = value; break;
		/* Appears twice, because we need it in two slices. */
		case 17: curSect->CFG_COMM_KEY = value; break;
		case 18: curSect->CFG_COMM_KEY = value; break;
	}
}

void ConfigParser::processValue()
{
	long numCV = sizeof(varNames) / sizeof(ConfigVar);
	for ( long i = 0; i < numCV; i++ ) {
		/* The var name must be fore all slices, or the slice must match the
		 * slice requested during parsing. */
		if ( requestedSlice == varNames[i].slice ) {
			/* Check for name match. */
			if ( strcmp( varNames[i].name, name() ) == 0 ) {
				setValue( i, value );
				debug( DBG_CFG, "CFG: %s = %s\n", varNames[i].name, value() );
			}
		}
	}
}

void ConfigParser::startHost()
{
	/* Create the config. */
	curSect = new ConfigSection( config->hostList.length() );

	/* n can point to either either 'host' or 'site'. */
	debug( DBG_CFG, "CFG: starting a host section\n" );
	config->hostList.append( curSect );
}

void ConfigParser::startSite()
{
	/* Create the config. */
	curSect = new ConfigSection( config->siteList.length() );
	curSect->name = buf;

	/* n can point to either either 'host' or 'site'. */
	debug( DBG_CFG, "CFG: starting a site section\n" );
	config->siteList.append( curSect );
}


#line 196 "rcfile.rl"



#line 164 "rcfile.cc"
static const int rcfile_start = 40;
static const int rcfile_first_final = 40;
static const int rcfile_error = 0;

static const int rcfile_en_main = 40;


#line 199 "rcfile.rl"

void ConfigParser::init()
{
	
#line 177 "rcfile.cc"
	{
	cs = rcfile_start;
	}

#line 203 "rcfile.rl"
}

/* Call with data = 0 && length = 0 to indicate end of file. */
void ConfigParser::parseData( const char *data, long length )
{
	const char *p = data, *pe = data + length;
	//const char *eof = data == 0 ? pe : 0;

	
#line 192 "rcfile.cc"
	{
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
tr12:
#line 176 "rcfile.rl"
	{
		startHost();
	}
	goto st40;
tr21:
#line 182 "rcfile.rl"
	{
		startSite();
	}
	goto st40;
tr30:
#line 166 "rcfile.rl"
	{
		value.set(buf);
		if ( curSect == 0 )
			throw ConfigParseError();
		processValue();
	}
	goto st40;
tr39:
#line 166 "rcfile.rl"
	{
		value.set(buf);
		if ( curSect == 0 )
			throw ConfigParseError();
		processValue();
	}
#line 176 "rcfile.rl"
	{
		startHost();
	}
	goto st40;
tr48:
#line 166 "rcfile.rl"
	{
		value.set(buf);
		if ( curSect == 0 )
			throw ConfigParseError();
		processValue();
	}
#line 182 "rcfile.rl"
	{
		startSite();
	}
	goto st40;
st40:
	if ( ++p == pe )
		goto _test_eof40;
case 40:
#line 249 "rcfile.cc"
	switch( (*p) ) {
		case 9: goto st1;
		case 10: goto st40;
		case 32: goto st1;
		case 35: goto st2;
		case 61: goto st3;
		case 95: goto tr54;
	}
	if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr54;
	} else if ( (*p) >= 65 )
		goto tr54;
	goto st0;
st0:
cs = 0;
	goto _out;
st1:
	if ( ++p == pe )
		goto _test_eof1;
case 1:
	switch( (*p) ) {
		case 9: goto st1;
		case 10: goto st40;
		case 32: goto st1;
	}
	goto st0;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 10 )
		goto st40;
	goto st2;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
	switch( (*p) ) {
		case 9: goto st4;
		case 32: goto st4;
		case 61: goto st3;
		case 104: goto st5;
		case 115: goto st10;
	}
	goto st0;
st4:
	if ( ++p == pe )
		goto _test_eof4;
case 4:
	switch( (*p) ) {
		case 9: goto st4;
		case 32: goto st4;
		case 104: goto st5;
		case 115: goto st10;
	}
	goto st0;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
	if ( (*p) == 111 )
		goto st6;
	goto st0;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
	if ( (*p) == 115 )
		goto st7;
	goto st0;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
	if ( (*p) == 116 )
		goto st8;
	goto st0;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
	switch( (*p) ) {
		case 9: goto st8;
		case 32: goto st8;
		case 61: goto st9;
	}
	goto st0;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
	switch( (*p) ) {
		case 10: goto tr12;
		case 61: goto st9;
	}
	goto st0;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
	if ( (*p) == 105 )
		goto st11;
	goto st0;
st11:
	if ( ++p == pe )
		goto _test_eof11;
case 11:
	if ( (*p) == 116 )
		goto st12;
	goto st0;
st12:
	if ( ++p == pe )
		goto _test_eof12;
case 12:
	if ( (*p) == 101 )
		goto st13;
	goto st0;
st13:
	if ( ++p == pe )
		goto _test_eof13;
case 13:
	switch( (*p) ) {
		case 9: goto st14;
		case 32: goto st14;
	}
	goto st0;
st14:
	if ( ++p == pe )
		goto _test_eof14;
case 14:
	switch( (*p) ) {
		case 9: goto st14;
		case 32: goto st14;
		case 95: goto tr17;
	}
	if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr17;
	} else if ( (*p) >= 65 )
		goto tr17;
	goto st0;
tr17:
#line 162 "rcfile.rl"
	{ buf.clear(); }
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st15;
tr19:
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st15;
st15:
	if ( ++p == pe )
		goto _test_eof15;
case 15:
#line 406 "rcfile.cc"
	switch( (*p) ) {
		case 9: goto st16;
		case 32: goto st16;
		case 61: goto st17;
		case 95: goto tr19;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr19;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr19;
	} else
		goto tr19;
	goto st0;
st16:
	if ( ++p == pe )
		goto _test_eof16;
case 16:
	switch( (*p) ) {
		case 9: goto st16;
		case 32: goto st16;
		case 61: goto st17;
	}
	goto st0;
st17:
	if ( ++p == pe )
		goto _test_eof17;
case 17:
	switch( (*p) ) {
		case 10: goto tr21;
		case 61: goto st17;
	}
	goto st0;
tr54:
#line 162 "rcfile.rl"
	{ buf.clear(); }
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st18;
tr23:
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st18;
st18:
	if ( ++p == pe )
		goto _test_eof18;
case 18:
#line 455 "rcfile.cc"
	switch( (*p) ) {
		case 9: goto tr22;
		case 32: goto tr22;
		case 61: goto tr24;
		case 95: goto tr23;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr23;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr23;
	} else
		goto tr23;
	goto st0;
tr22:
#line 165 "rcfile.rl"
	{ name.set(buf); }
	goto st19;
st19:
	if ( ++p == pe )
		goto _test_eof19;
case 19:
#line 479 "rcfile.cc"
	switch( (*p) ) {
		case 9: goto st19;
		case 32: goto st19;
		case 61: goto st20;
	}
	goto st0;
tr24:
#line 165 "rcfile.rl"
	{ name.set(buf); }
	goto st20;
st20:
	if ( ++p == pe )
		goto _test_eof20;
case 20:
#line 494 "rcfile.cc"
	switch( (*p) ) {
		case 9: goto st20;
		case 10: goto tr28;
		case 32: goto st20;
	}
	goto tr27;
tr27:
#line 162 "rcfile.rl"
	{ buf.clear(); }
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st21;
tr29:
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st21;
st21:
	if ( ++p == pe )
		goto _test_eof21;
case 21:
#line 515 "rcfile.cc"
	if ( (*p) == 10 )
		goto tr30;
	goto tr29;
tr28:
#line 162 "rcfile.rl"
	{ buf.clear(); }
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
#line 166 "rcfile.rl"
	{
		value.set(buf);
		if ( curSect == 0 )
			throw ConfigParseError();
		processValue();
	}
	goto st41;
st41:
	if ( ++p == pe )
		goto _test_eof41;
case 41:
#line 536 "rcfile.cc"
	switch( (*p) ) {
		case 10: goto tr30;
		case 61: goto tr32;
		case 95: goto tr55;
	}
	if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr55;
	} else if ( (*p) >= 65 )
		goto tr55;
	goto tr29;
tr32:
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st22;
st22:
	if ( ++p == pe )
		goto _test_eof22;
case 22:
#line 556 "rcfile.cc"
	switch( (*p) ) {
		case 9: goto tr31;
		case 10: goto tr30;
		case 32: goto tr31;
		case 61: goto tr32;
		case 104: goto tr33;
		case 115: goto tr34;
	}
	goto tr29;
tr31:
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st23;
st23:
	if ( ++p == pe )
		goto _test_eof23;
case 23:
#line 574 "rcfile.cc"
	switch( (*p) ) {
		case 9: goto tr31;
		case 10: goto tr30;
		case 32: goto tr31;
		case 104: goto tr33;
		case 115: goto tr34;
	}
	goto tr29;
tr33:
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st24;
st24:
	if ( ++p == pe )
		goto _test_eof24;
case 24:
#line 591 "rcfile.cc"
	switch( (*p) ) {
		case 10: goto tr30;
		case 111: goto tr35;
	}
	goto tr29;
tr35:
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st25;
st25:
	if ( ++p == pe )
		goto _test_eof25;
case 25:
#line 605 "rcfile.cc"
	switch( (*p) ) {
		case 10: goto tr30;
		case 115: goto tr36;
	}
	goto tr29;
tr36:
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st26;
st26:
	if ( ++p == pe )
		goto _test_eof26;
case 26:
#line 619 "rcfile.cc"
	switch( (*p) ) {
		case 10: goto tr30;
		case 116: goto tr37;
	}
	goto tr29;
tr37:
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st27;
st27:
	if ( ++p == pe )
		goto _test_eof27;
case 27:
#line 633 "rcfile.cc"
	switch( (*p) ) {
		case 9: goto tr37;
		case 10: goto tr30;
		case 32: goto tr37;
		case 61: goto tr38;
	}
	goto tr29;
tr38:
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st28;
st28:
	if ( ++p == pe )
		goto _test_eof28;
case 28:
#line 649 "rcfile.cc"
	switch( (*p) ) {
		case 10: goto tr39;
		case 61: goto tr38;
	}
	goto tr29;
tr34:
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st29;
st29:
	if ( ++p == pe )
		goto _test_eof29;
case 29:
#line 663 "rcfile.cc"
	switch( (*p) ) {
		case 10: goto tr30;
		case 105: goto tr40;
	}
	goto tr29;
tr40:
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st30;
st30:
	if ( ++p == pe )
		goto _test_eof30;
case 30:
#line 677 "rcfile.cc"
	switch( (*p) ) {
		case 10: goto tr30;
		case 116: goto tr41;
	}
	goto tr29;
tr41:
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st31;
st31:
	if ( ++p == pe )
		goto _test_eof31;
case 31:
#line 691 "rcfile.cc"
	switch( (*p) ) {
		case 10: goto tr30;
		case 101: goto tr42;
	}
	goto tr29;
tr42:
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st32;
st32:
	if ( ++p == pe )
		goto _test_eof32;
case 32:
#line 705 "rcfile.cc"
	switch( (*p) ) {
		case 9: goto tr43;
		case 10: goto tr30;
		case 32: goto tr43;
	}
	goto tr29;
tr43:
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st33;
st33:
	if ( ++p == pe )
		goto _test_eof33;
case 33:
#line 720 "rcfile.cc"
	switch( (*p) ) {
		case 9: goto tr43;
		case 10: goto tr30;
		case 32: goto tr43;
		case 95: goto tr44;
	}
	if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr44;
	} else if ( (*p) >= 65 )
		goto tr44;
	goto tr29;
tr46:
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st34;
tr44:
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
#line 162 "rcfile.rl"
	{ buf.clear(); }
	goto st34;
st34:
	if ( ++p == pe )
		goto _test_eof34;
case 34:
#line 747 "rcfile.cc"
	switch( (*p) ) {
		case 9: goto tr45;
		case 10: goto tr30;
		case 32: goto tr45;
		case 61: goto tr47;
		case 95: goto tr46;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr46;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr46;
	} else
		goto tr46;
	goto tr29;
tr45:
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st35;
st35:
	if ( ++p == pe )
		goto _test_eof35;
case 35:
#line 772 "rcfile.cc"
	switch( (*p) ) {
		case 9: goto tr45;
		case 10: goto tr30;
		case 32: goto tr45;
		case 61: goto tr47;
	}
	goto tr29;
tr47:
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st36;
st36:
	if ( ++p == pe )
		goto _test_eof36;
case 36:
#line 788 "rcfile.cc"
	switch( (*p) ) {
		case 10: goto tr48;
		case 61: goto tr47;
	}
	goto tr29;
tr50:
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st37;
tr55:
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
#line 162 "rcfile.rl"
	{ buf.clear(); }
	goto st37;
st37:
	if ( ++p == pe )
		goto _test_eof37;
case 37:
#line 808 "rcfile.cc"
	switch( (*p) ) {
		case 9: goto tr49;
		case 10: goto tr30;
		case 32: goto tr49;
		case 61: goto tr51;
		case 95: goto tr50;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr50;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr50;
	} else
		goto tr50;
	goto tr29;
tr52:
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st38;
tr49:
#line 165 "rcfile.rl"
	{ name.set(buf); }
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st38;
st38:
	if ( ++p == pe )
		goto _test_eof38;
case 38:
#line 839 "rcfile.cc"
	switch( (*p) ) {
		case 9: goto tr52;
		case 10: goto tr30;
		case 32: goto tr52;
		case 61: goto tr53;
	}
	goto tr29;
tr53:
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st39;
tr51:
#line 165 "rcfile.rl"
	{ name.set(buf); }
#line 163 "rcfile.rl"
	{ buf.append((*p)); }
	goto st39;
st39:
	if ( ++p == pe )
		goto _test_eof39;
case 39:
#line 861 "rcfile.cc"
	switch( (*p) ) {
		case 9: goto tr53;
		case 10: goto tr28;
		case 32: goto tr53;
	}
	goto tr27;
	}
	_test_eof40: cs = 40; goto _test_eof; 
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
	_test_eof41: cs = 41; goto _test_eof; 
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

	_test_eof: {}
	_out: {}
	}

#line 212 "rcfile.rl"

	if ( cs == rcfile_error )
		throw ConfigParseError();
}
