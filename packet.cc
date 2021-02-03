
#line 1 "packet.rl"
/*
 * Copyright (c) 2011, Adrian Thurston <thurston@complang.org>
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
#include "packet.h"
#include "keyagent.h"
#include "error.h"

/* 
 * Common Stuff.
 */


#line 48 "packet.rl"


#define EP_PUBLIC_KEY            1
#define EP_PUBLIC_KEY_SET        2
#define EP_RELID_SET             3
#define EP_RELID_SET_PAIR        4
#define EP_RELID_RESPONSE        5
#define EP_PRIVATE_KEY           6
#define EP_PW_ENCRYPTED          7
#define EP_SIGNED                8
#define EP_SIGNED_ID             9
#define EP_DETACHED_SIG          10
#define EP_DETACHED_SIG_KEY      11
#define EP_SIGNED_ENCRYPTED      12
#define EP_BK_KEYS               13
#define EP_BK_ENCRYPTED          14
#define EP_BK_SIGNED_ENCRYPTED   15
#define EP_BROADCAST             16
#define EP_RECIPIENT_LIST        17

long binLength( const String &bin )
{
	/* FIXME: check for overflow (2 byte length). */
	return 2 + bin.length;
}

long stringLength( const String &s )
{
	return s.length + 1;
}

long sixtyFourBitLength()
	{ return 8; }

u_char *writeBin( u_char *dest, const String &bin )
{
	dest[0] = ( (u_long)bin.length >> 8 ) & 0xff;
	dest[1] = (u_long)bin.length & 0xff;
	memcpy( dest + 2, bin.binary(), bin.length );
	dest += 2 + bin.length;
	return dest;
}

u_char *writeString( u_char *dest, const String &s )
{
	memcpy( dest, s(), s.length );
	dest += s.length;
	*dest++ = 0;
	return dest;
}

u_char *write64Bit( u_char *dest, u_int64_t i )
{
	for ( int shift = 56; shift >= 0; shift -= 8 )
		*dest++ = ( i >> shift ) & 0xff;
	return dest;
}

u_char *writeType( u_char *dest, u_char type )
{
	dest[0] = type;
	dest += 1;
	return dest;
}

/*
 * Public Key
 */

Allocated consPublicKey( const PrivateKey &key )
{
	long length = 1 + binLength(key.n) + binLength(key.e);
	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_PUBLIC_KEY );
	dest = writeBin( dest, key.n );
	dest = writeBin( dest, key.e );

	return encPacket.relinquish();
}


#line 143 "packet.rl"



#line 118 "packet.cc"
static const int packet_public_keys_start = 1;
static const int packet_public_keys_first_final = 10;
static const int packet_public_keys_error = 0;

static const int packet_public_keys_en_main = 1;


#line 146 "packet.rl"

Parser::Control PacketPublicKey::data( const char *data, int dlen )
{
	
#line 131 "packet.cc"
	{
	cs = packet_public_keys_start;
	}

#line 150 "packet.rl"

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	
#line 142 "packet.cc"
	{
	short _widec;
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) == 1u )
		goto st2;
	goto st0;
st0:
cs = 0;
	goto _out;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 0u )
		goto tr2;
	goto tr3;
tr2:
#line 175 "common.rl"
	{ val = 0; }
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 171 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr4;
tr4:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st4;
tr6:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st4;
tr13:
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
#line 203 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr6;
	} else if ( _widec >= 256 )
		goto tr5;
	goto st0;
tr5:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 136 "packet.rl"
	{ n.set( buf ); }
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 225 "packet.cc"
	if ( (*p) == 0u )
		goto tr7;
	goto tr8;
tr7:
#line 175 "common.rl"
	{ val = 0; }
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 237 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr9;
tr9:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st7;
tr11:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st7;
tr12:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st7;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
#line 269 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr11;
	} else if ( _widec >= 256 )
		goto tr10;
	goto st0;
tr10:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 137 "packet.rl"
	{ e.set( buf ); }
#line 139 "packet.rl"
	{
		debug( DBG_EP, "encryption packet: public_key: %ld %ld\n", 
				n.length, e.length );
	}
	goto st10;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
#line 296 "packet.cc"
	goto st0;
tr8:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st8;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
#line 306 "packet.cc"
	goto tr12;
tr3:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st9;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
#line 316 "packet.cc"
	goto tr13;
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 155 "packet.rl"

	if ( cs < 
#line 336 "packet.cc"
10
#line 156 "packet.rl"
 )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * Public Key Set
 */

Allocated consPublicKeySet( const String &priv0, const String &priv1,
		const String &priv2, const String &priv3 )
{
	long length = 1 + 
			binLength(priv0) + binLength(priv1) + 
			binLength(priv2) + binLength(priv3);

	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_PUBLIC_KEY_SET );
	dest = writeBin( dest, priv0 );
	dest = writeBin( dest, priv1 );
	dest = writeBin( dest, priv2 );
	dest = writeBin( dest, priv3 );

	return encPacket.relinquish();
}


#line 200 "packet.rl"



#line 373 "packet.cc"
static const int packet_public_key_set_start = 1;
static const int packet_public_key_set_first_final = 18;
static const int packet_public_key_set_error = 0;

static const int packet_public_key_set_en_main = 1;


#line 203 "packet.rl"

Parser::Control PacketPublicKeySet::data( const char *data, int dlen )
{
	
#line 386 "packet.cc"
	{
	cs = packet_public_key_set_start;
	}

#line 207 "packet.rl"

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	
#line 397 "packet.cc"
	{
	short _widec;
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) == 2u )
		goto st2;
	goto st0;
st0:
cs = 0;
	goto _out;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 0u )
		goto tr2;
	goto tr3;
tr2:
#line 175 "common.rl"
	{ val = 0; }
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 426 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr4;
tr4:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st4;
tr6:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st4;
tr25:
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
#line 458 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr6;
	} else if ( _widec >= 256 )
		goto tr5;
	goto st0;
tr5:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 191 "packet.rl"
	{ priv0.set( buf ); }
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 480 "packet.cc"
	if ( (*p) == 0u )
		goto tr7;
	goto tr8;
tr7:
#line 175 "common.rl"
	{ val = 0; }
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 492 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr9;
tr9:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st7;
tr11:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st7;
tr24:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st7;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
#line 524 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr11;
	} else if ( _widec >= 256 )
		goto tr10;
	goto st0;
tr10:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 192 "packet.rl"
	{ priv1.set( buf ); }
	goto st8;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
#line 546 "packet.cc"
	if ( (*p) == 0u )
		goto tr12;
	goto tr13;
tr12:
#line 175 "common.rl"
	{ val = 0; }
	goto st9;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
#line 558 "packet.cc"
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
	goto st10;
tr16:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st10;
tr23:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st10;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
#line 590 "packet.cc"
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
tr15:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 193 "packet.rl"
	{ priv2.set( buf ); }
	goto st11;
st11:
	if ( ++p == pe )
		goto _test_eof11;
case 11:
#line 612 "packet.cc"
	if ( (*p) == 0u )
		goto tr17;
	goto tr18;
tr17:
#line 175 "common.rl"
	{ val = 0; }
	goto st12;
st12:
	if ( ++p == pe )
		goto _test_eof12;
case 12:
#line 624 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr19;
tr19:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st13;
tr21:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st13;
tr22:
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
#line 656 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr21;
	} else if ( _widec >= 256 )
		goto tr20;
	goto st0;
tr20:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 194 "packet.rl"
	{ priv3.set( buf ); }
#line 196 "packet.rl"
	{
		debug( DBG_EP, "encryption packet: public_key_set: %ld %ld %ld %ld\n", 
				priv0.length, priv1.length, priv2.length, priv3.length );
	}
	goto st18;
st18:
	if ( ++p == pe )
		goto _test_eof18;
case 18:
#line 683 "packet.cc"
	goto st0;
tr18:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st14;
st14:
	if ( ++p == pe )
		goto _test_eof14;
case 14:
#line 693 "packet.cc"
	goto tr22;
tr13:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st15;
st15:
	if ( ++p == pe )
		goto _test_eof15;
case 15:
#line 703 "packet.cc"
	goto tr23;
tr8:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st16;
st16:
	if ( ++p == pe )
		goto _test_eof16;
case 16:
#line 713 "packet.cc"
	goto tr24;
tr3:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st17;
st17:
	if ( ++p == pe )
		goto _test_eof17;
case 17:
#line 723 "packet.cc"
	goto tr25;
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
	_test_eof18: cs = 18; goto _test_eof; 
	_test_eof14: cs = 14; goto _test_eof; 
	_test_eof15: cs = 15; goto _test_eof; 
	_test_eof16: cs = 16; goto _test_eof; 
	_test_eof17: cs = 17; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 212 "packet.rl"

	if ( cs < 
#line 751 "packet.cc"
18
#line 213 "packet.rl"
 )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * Relid Set
 */

Allocated consRelidSet( const RelidSet &relidSet )
{
	long length = 1 + 
			binLength(relidSet.priv0) + binLength(relidSet.priv1) + 
			binLength(relidSet.priv2) + binLength(relidSet.priv3) +
			binLength(relidSet.priv4);

	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_RELID_SET );
	dest = writeBin( dest, relidSet.priv0 );
	dest = writeBin( dest, relidSet.priv1 );
	dest = writeBin( dest, relidSet.priv2 );
	dest = writeBin( dest, relidSet.priv3 );
	dest = writeBin( dest, relidSet.priv4 );

	return encPacket.relinquish();
}


#line 259 "packet.rl"



#line 789 "packet.cc"
static const int packet_relid_set_start = 1;
static const int packet_relid_set_first_final = 22;
static const int packet_relid_set_error = 0;

static const int packet_relid_set_en_main = 1;


#line 262 "packet.rl"

Parser::Control PacketRelidSet::data( const char *data, int dlen )
{
	
#line 802 "packet.cc"
	{
	cs = packet_relid_set_start;
	}

#line 266 "packet.rl"

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	
#line 813 "packet.cc"
	{
	short _widec;
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) == 3u )
		goto st2;
	goto st0;
st0:
cs = 0;
	goto _out;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 0u )
		goto tr2;
	goto tr3;
tr2:
#line 175 "common.rl"
	{ val = 0; }
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 842 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr4;
tr4:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st4;
tr6:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st4;
tr31:
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
#line 874 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr6;
	} else if ( _widec >= 256 )
		goto tr5;
	goto st0;
tr5:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 249 "packet.rl"
	{ priv0.set( buf ); }
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 896 "packet.cc"
	if ( (*p) == 0u )
		goto tr7;
	goto tr8;
tr7:
#line 175 "common.rl"
	{ val = 0; }
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 908 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr9;
tr9:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st7;
tr11:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st7;
tr30:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st7;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
#line 940 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr11;
	} else if ( _widec >= 256 )
		goto tr10;
	goto st0;
tr10:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 250 "packet.rl"
	{ priv1.set( buf ); }
	goto st8;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
#line 962 "packet.cc"
	if ( (*p) == 0u )
		goto tr12;
	goto tr13;
tr12:
#line 175 "common.rl"
	{ val = 0; }
	goto st9;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
#line 974 "packet.cc"
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
	goto st10;
tr16:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st10;
tr29:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st10;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
#line 1006 "packet.cc"
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
tr15:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 251 "packet.rl"
	{ priv2.set( buf ); }
	goto st11;
st11:
	if ( ++p == pe )
		goto _test_eof11;
case 11:
#line 1028 "packet.cc"
	if ( (*p) == 0u )
		goto tr17;
	goto tr18;
tr17:
#line 175 "common.rl"
	{ val = 0; }
	goto st12;
st12:
	if ( ++p == pe )
		goto _test_eof12;
case 12:
#line 1040 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr19;
tr19:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st13;
tr21:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st13;
tr28:
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
#line 1072 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr21;
	} else if ( _widec >= 256 )
		goto tr20;
	goto st0;
tr20:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 252 "packet.rl"
	{ priv3.set( buf ); }
	goto st14;
st14:
	if ( ++p == pe )
		goto _test_eof14;
case 14:
#line 1094 "packet.cc"
	if ( (*p) == 0u )
		goto tr22;
	goto tr23;
tr22:
#line 175 "common.rl"
	{ val = 0; }
	goto st15;
st15:
	if ( ++p == pe )
		goto _test_eof15;
case 15:
#line 1106 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr24;
tr24:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st16;
tr26:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st16;
tr27:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st16;
st16:
	if ( ++p == pe )
		goto _test_eof16;
case 16:
#line 1138 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr26;
	} else if ( _widec >= 256 )
		goto tr25;
	goto st0;
tr25:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 253 "packet.rl"
	{ priv4.set( buf ); }
#line 255 "packet.rl"
	{
		debug( DBG_EP, "encryption packet: relid_set: %ld %ld %ld %ld %ld\n", 
				priv0.length, priv1.length, priv2.length, priv3.length, priv4.length );
	}
	goto st22;
st22:
	if ( ++p == pe )
		goto _test_eof22;
case 22:
#line 1165 "packet.cc"
	goto st0;
tr23:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st17;
st17:
	if ( ++p == pe )
		goto _test_eof17;
case 17:
#line 1175 "packet.cc"
	goto tr27;
tr18:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st18;
st18:
	if ( ++p == pe )
		goto _test_eof18;
case 18:
#line 1185 "packet.cc"
	goto tr28;
tr13:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st19;
st19:
	if ( ++p == pe )
		goto _test_eof19;
case 19:
#line 1195 "packet.cc"
	goto tr29;
tr8:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st20;
st20:
	if ( ++p == pe )
		goto _test_eof20;
case 20:
#line 1205 "packet.cc"
	goto tr30;
tr3:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st21;
st21:
	if ( ++p == pe )
		goto _test_eof21;
case 21:
#line 1215 "packet.cc"
	goto tr31;
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
	_test_eof22: cs = 22; goto _test_eof; 
	_test_eof17: cs = 17; goto _test_eof; 
	_test_eof18: cs = 18; goto _test_eof; 
	_test_eof19: cs = 19; goto _test_eof; 
	_test_eof20: cs = 20; goto _test_eof; 
	_test_eof21: cs = 21; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 271 "packet.rl"

	if ( cs < 
#line 1247 "packet.cc"
22
#line 272 "packet.rl"
 )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * Relid Set Pair
 */

Allocated consRelidSetPair( const String &requested, const String &returned )
{
	long length = 1 + binLength(requested) + binLength(returned);

	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_RELID_SET_PAIR );
	dest = writeBin( dest, requested );
	dest = writeBin( dest, returned );

	return encPacket.relinquish();
}


#line 309 "packet.rl"



#line 1279 "packet.cc"
static const int packet_relid_set_pair_start = 1;
static const int packet_relid_set_pair_first_final = 10;
static const int packet_relid_set_pair_error = 0;

static const int packet_relid_set_pair_en_main = 1;


#line 312 "packet.rl"

Parser::Control PacketRelidSetPair::data( const char *data, int dlen )
{
	
#line 1292 "packet.cc"
	{
	cs = packet_relid_set_pair_start;
	}

#line 316 "packet.rl"

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	
#line 1303 "packet.cc"
	{
	short _widec;
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) == 4u )
		goto st2;
	goto st0;
st0:
cs = 0;
	goto _out;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 0u )
		goto tr2;
	goto tr3;
tr2:
#line 175 "common.rl"
	{ val = 0; }
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 1332 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr4;
tr4:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st4;
tr6:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st4;
tr13:
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
#line 1364 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr6;
	} else if ( _widec >= 256 )
		goto tr5;
	goto st0;
tr5:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 302 "packet.rl"
	{ requested.set( buf ); }
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 1386 "packet.cc"
	if ( (*p) == 0u )
		goto tr7;
	goto tr8;
tr7:
#line 175 "common.rl"
	{ val = 0; }
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 1398 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr9;
tr9:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st7;
tr11:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st7;
tr12:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st7;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
#line 1430 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr11;
	} else if ( _widec >= 256 )
		goto tr10;
	goto st0;
tr10:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 303 "packet.rl"
	{ returned.set( buf ); }
#line 305 "packet.rl"
	{
		debug( DBG_EP, "encryption packet: relid_set_pair: %ld %ld\n", 
				requested.length, returned.length );
	}
	goto st10;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
#line 1457 "packet.cc"
	goto st0;
tr8:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st8;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
#line 1467 "packet.cc"
	goto tr12;
tr3:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st9;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
#line 1477 "packet.cc"
	goto tr13;
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 321 "packet.rl"

	if ( cs < 
#line 1497 "packet.cc"
10
#line 322 "packet.rl"
 )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * Relid Response
 */

Allocated consRelidResponse( const String &peerNotifyReqid, const String &relidSetPair )
{
	long length = 1 + binLength(peerNotifyReqid) + binLength(relidSetPair);
	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_RELID_RESPONSE );
	dest = writeBin( dest, peerNotifyReqid );
	dest = writeBin( dest, relidSetPair );

	return encPacket.relinquish();
}


#line 358 "packet.rl"



#line 1528 "packet.cc"
static const int packet_relid_response_start = 1;
static const int packet_relid_response_first_final = 10;
static const int packet_relid_response_error = 0;

static const int packet_relid_response_en_main = 1;


#line 361 "packet.rl"

Parser::Control PacketRelidResponse::data( const char *data, int dlen )
{
	
#line 1541 "packet.cc"
	{
	cs = packet_relid_response_start;
	}

#line 365 "packet.rl"

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	
#line 1552 "packet.cc"
	{
	short _widec;
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) == 5u )
		goto st2;
	goto st0;
st0:
cs = 0;
	goto _out;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 0u )
		goto tr2;
	goto tr3;
tr2:
#line 175 "common.rl"
	{ val = 0; }
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 1581 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr4;
tr4:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st4;
tr6:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st4;
tr13:
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
#line 1613 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr6;
	} else if ( _widec >= 256 )
		goto tr5;
	goto st0;
tr5:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 351 "packet.rl"
	{ peerNotifyReqid.set( buf ); }
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 1635 "packet.cc"
	if ( (*p) == 0u )
		goto tr7;
	goto tr8;
tr7:
#line 175 "common.rl"
	{ val = 0; }
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 1647 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr9;
tr9:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st7;
tr11:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st7;
tr12:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st7;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
#line 1679 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr11;
	} else if ( _widec >= 256 )
		goto tr10;
	goto st0;
tr10:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 352 "packet.rl"
	{ relidSetPair.set( buf ); }
#line 354 "packet.rl"
	{
		debug( DBG_EP, "encryption packet: relid_response: %ld %ld\n", 
				peerNotifyReqid.length, relidSetPair.length );
	}
	goto st10;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
#line 1706 "packet.cc"
	goto st0;
tr8:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st8;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
#line 1716 "packet.cc"
	goto tr12;
tr3:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st9;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
#line 1726 "packet.cc"
	goto tr13;
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 370 "packet.rl"

	if ( cs < 
#line 1746 "packet.cc"
10
#line 371 "packet.rl"
 )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}


/*
 * Private Key
 */

Allocated consPrivateKey( const PrivateKey &key )
{
	long length = 1 + 
			binLength( key.n ) + binLength( key.e ) + 
			binLength( key.d ) + binLength( key.p ) +
			binLength( key.q ) + binLength( key.dmp1 ) +
			binLength( key.dmq1 ) + binLength( key.iqmp );

	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_PRIVATE_KEY );
	dest = writeBin( dest, key.n );
	dest = writeBin( dest, key.e );
	dest = writeBin( dest, key.d );
	dest = writeBin( dest, key.p );
	dest = writeBin( dest, key.q );
	dest = writeBin( dest, key.dmp1 );
	dest = writeBin( dest, key.dmq1 );
	dest = writeBin( dest, key.iqmp );

	return encPacket.relinquish();
}


#line 426 "packet.rl"



#line 1789 "packet.cc"
static const int packet_private_keys_start = 1;
static const int packet_private_keys_first_final = 34;
static const int packet_private_keys_error = 0;

static const int packet_private_keys_en_main = 1;


#line 429 "packet.rl"

Parser::Control PacketPrivateKey::data( const char *data, int dlen )
{
	
#line 1802 "packet.cc"
	{
	cs = packet_private_keys_start;
	}

#line 433 "packet.rl"

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	
#line 1813 "packet.cc"
	{
	short _widec;
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) == 6u )
		goto st2;
	goto st0;
st0:
cs = 0;
	goto _out;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 0u )
		goto tr2;
	goto tr3;
tr2:
#line 175 "common.rl"
	{ val = 0; }
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 1842 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr4;
tr4:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st4;
tr6:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st4;
tr49:
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
#line 1874 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr6;
	} else if ( _widec >= 256 )
		goto tr5;
	goto st0;
tr5:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 412 "packet.rl"
	{ key.n.set( buf ); }
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 1896 "packet.cc"
	if ( (*p) == 0u )
		goto tr7;
	goto tr8;
tr7:
#line 175 "common.rl"
	{ val = 0; }
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 1908 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr9;
tr9:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st7;
tr11:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st7;
tr48:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st7;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
#line 1940 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr11;
	} else if ( _widec >= 256 )
		goto tr10;
	goto st0;
tr10:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 413 "packet.rl"
	{ key.e.set( buf ); }
	goto st8;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
#line 1962 "packet.cc"
	if ( (*p) == 0u )
		goto tr12;
	goto tr13;
tr12:
#line 175 "common.rl"
	{ val = 0; }
	goto st9;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
#line 1974 "packet.cc"
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
	goto st10;
tr16:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st10;
tr47:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st10;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
#line 2006 "packet.cc"
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
tr15:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 414 "packet.rl"
	{ key.d.set( buf ); }
	goto st11;
st11:
	if ( ++p == pe )
		goto _test_eof11;
case 11:
#line 2028 "packet.cc"
	if ( (*p) == 0u )
		goto tr17;
	goto tr18;
tr17:
#line 175 "common.rl"
	{ val = 0; }
	goto st12;
st12:
	if ( ++p == pe )
		goto _test_eof12;
case 12:
#line 2040 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr19;
tr19:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st13;
tr21:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st13;
tr46:
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
#line 2072 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr21;
	} else if ( _widec >= 256 )
		goto tr20;
	goto st0;
tr20:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 415 "packet.rl"
	{ key.p.set( buf ); }
	goto st14;
st14:
	if ( ++p == pe )
		goto _test_eof14;
case 14:
#line 2094 "packet.cc"
	if ( (*p) == 0u )
		goto tr22;
	goto tr23;
tr22:
#line 175 "common.rl"
	{ val = 0; }
	goto st15;
st15:
	if ( ++p == pe )
		goto _test_eof15;
case 15:
#line 2106 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr24;
tr24:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st16;
tr26:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st16;
tr45:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st16;
st16:
	if ( ++p == pe )
		goto _test_eof16;
case 16:
#line 2138 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr26;
	} else if ( _widec >= 256 )
		goto tr25;
	goto st0;
tr25:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 416 "packet.rl"
	{ key.q.set( buf ); }
	goto st17;
st17:
	if ( ++p == pe )
		goto _test_eof17;
case 17:
#line 2160 "packet.cc"
	if ( (*p) == 0u )
		goto tr27;
	goto tr28;
tr27:
#line 175 "common.rl"
	{ val = 0; }
	goto st18;
st18:
	if ( ++p == pe )
		goto _test_eof18;
case 18:
#line 2172 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr29;
tr29:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st19;
tr31:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st19;
tr44:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st19;
st19:
	if ( ++p == pe )
		goto _test_eof19;
case 19:
#line 2204 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr31;
	} else if ( _widec >= 256 )
		goto tr30;
	goto st0;
tr30:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 417 "packet.rl"
	{ key.dmp1.set( buf ); }
	goto st20;
st20:
	if ( ++p == pe )
		goto _test_eof20;
case 20:
#line 2226 "packet.cc"
	if ( (*p) == 0u )
		goto tr32;
	goto tr33;
tr32:
#line 175 "common.rl"
	{ val = 0; }
	goto st21;
st21:
	if ( ++p == pe )
		goto _test_eof21;
case 21:
#line 2238 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr34;
tr34:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st22;
tr36:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st22;
tr43:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st22;
st22:
	if ( ++p == pe )
		goto _test_eof22;
case 22:
#line 2270 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr36;
	} else if ( _widec >= 256 )
		goto tr35;
	goto st0;
tr35:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 418 "packet.rl"
	{ key.dmq1.set( buf ); }
	goto st23;
st23:
	if ( ++p == pe )
		goto _test_eof23;
case 23:
#line 2292 "packet.cc"
	if ( (*p) == 0u )
		goto tr37;
	goto tr38;
tr37:
#line 175 "common.rl"
	{ val = 0; }
	goto st24;
st24:
	if ( ++p == pe )
		goto _test_eof24;
case 24:
#line 2304 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr39;
tr39:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st25;
tr41:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st25;
tr42:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st25;
st25:
	if ( ++p == pe )
		goto _test_eof25;
case 25:
#line 2336 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr41;
	} else if ( _widec >= 256 )
		goto tr40;
	goto st0;
tr40:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 419 "packet.rl"
	{ key.iqmp.set( buf ); }
#line 421 "packet.rl"
	{
		debug( DBG_EP, "encryption packet: private_key: %ld %ld %ld %ld %ld %ld %ld %ld\n", 
				key.n.length, key.e.length, key.d.length, key.p.length ,
				key.q.length, key.dmp1.length, key.dmq1.length, key.iqmp.length );
	}
	goto st34;
st34:
	if ( ++p == pe )
		goto _test_eof34;
case 34:
#line 2364 "packet.cc"
	goto st0;
tr38:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st26;
st26:
	if ( ++p == pe )
		goto _test_eof26;
case 26:
#line 2374 "packet.cc"
	goto tr42;
tr33:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st27;
st27:
	if ( ++p == pe )
		goto _test_eof27;
case 27:
#line 2384 "packet.cc"
	goto tr43;
tr28:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st28;
st28:
	if ( ++p == pe )
		goto _test_eof28;
case 28:
#line 2394 "packet.cc"
	goto tr44;
tr23:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st29;
st29:
	if ( ++p == pe )
		goto _test_eof29;
case 29:
#line 2404 "packet.cc"
	goto tr45;
tr18:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st30;
st30:
	if ( ++p == pe )
		goto _test_eof30;
case 30:
#line 2414 "packet.cc"
	goto tr46;
tr13:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st31;
st31:
	if ( ++p == pe )
		goto _test_eof31;
case 31:
#line 2424 "packet.cc"
	goto tr47;
tr8:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st32;
st32:
	if ( ++p == pe )
		goto _test_eof32;
case 32:
#line 2434 "packet.cc"
	goto tr48;
tr3:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st33;
st33:
	if ( ++p == pe )
		goto _test_eof33;
case 33:
#line 2444 "packet.cc"
	goto tr49;
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
	_test_eof18: cs = 18; goto _test_eof; 
	_test_eof19: cs = 19; goto _test_eof; 
	_test_eof20: cs = 20; goto _test_eof; 
	_test_eof21: cs = 21; goto _test_eof; 
	_test_eof22: cs = 22; goto _test_eof; 
	_test_eof23: cs = 23; goto _test_eof; 
	_test_eof24: cs = 24; goto _test_eof; 
	_test_eof25: cs = 25; goto _test_eof; 
	_test_eof34: cs = 34; goto _test_eof; 
	_test_eof26: cs = 26; goto _test_eof; 
	_test_eof27: cs = 27; goto _test_eof; 
	_test_eof28: cs = 28; goto _test_eof; 
	_test_eof29: cs = 29; goto _test_eof; 
	_test_eof30: cs = 30; goto _test_eof; 
	_test_eof31: cs = 31; goto _test_eof; 
	_test_eof32: cs = 32; goto _test_eof; 
	_test_eof33: cs = 33; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 438 "packet.rl"

	if ( cs < 
#line 2488 "packet.cc"
34
#line 439 "packet.rl"
 )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * PW Encrypted
 */

Allocated consPwEncrypted( const String &enc )
{
	long length = 1 + binLength(enc);
	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_PW_ENCRYPTED );
	dest = writeBin( dest, enc );

	return encPacket.relinquish();
}


#line 472 "packet.rl"



#line 2518 "packet.cc"
static const int packet_pw_encrypted_start = 1;
static const int packet_pw_encrypted_first_final = 6;
static const int packet_pw_encrypted_error = 0;

static const int packet_pw_encrypted_en_main = 1;


#line 475 "packet.rl"

Parser::Control PacketPwEncrypted::data( const char *data, int dlen )
{
	
#line 2531 "packet.cc"
	{
	cs = packet_pw_encrypted_start;
	}

#line 479 "packet.rl"

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	
#line 2542 "packet.cc"
	{
	short _widec;
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) == 7u )
		goto st2;
	goto st0;
st0:
cs = 0;
	goto _out;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 0u )
		goto tr2;
	goto tr3;
tr2:
#line 175 "common.rl"
	{ val = 0; }
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 2571 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr4;
tr4:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st4;
tr6:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st4;
tr7:
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
#line 2603 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr6;
	} else if ( _widec >= 256 )
		goto tr5;
	goto st0;
tr5:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 467 "packet.rl"
	{ enc.set( buf ); }
#line 469 "packet.rl"
	{
		debug( DBG_EP, "encryption packet: pw_encrypted: %ld\n", enc.length );
	}
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 2629 "packet.cc"
	goto st0;
tr3:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 2639 "packet.cc"
	goto tr7;
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 484 "packet.rl"

	if ( cs < 
#line 2655 "packet.cc"
6
#line 485 "packet.rl"
 )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * Signed
 */

Allocated consSigned( const String &sig, const String &msg )
{
	long length = 1 + binLength(sig) + binLength(msg);
	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_SIGNED );
	dest = writeBin( dest, sig );
	dest = writeBin( dest, msg );

	return encPacket.relinquish();
}


#line 521 "packet.rl"



#line 2686 "packet.cc"
static const int packet_signed_start = 1;
static const int packet_signed_first_final = 10;
static const int packet_signed_error = 0;

static const int packet_signed_en_main = 1;


#line 524 "packet.rl"

Parser::Control PacketSigned::data( const char *data, int dlen )
{
	
#line 2699 "packet.cc"
	{
	cs = packet_signed_start;
	}

#line 528 "packet.rl"

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	
#line 2710 "packet.cc"
	{
	short _widec;
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) == 8u )
		goto st2;
	goto st0;
st0:
cs = 0;
	goto _out;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 0u )
		goto tr2;
	goto tr3;
tr2:
#line 175 "common.rl"
	{ val = 0; }
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 2739 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr4;
tr4:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st4;
tr6:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st4;
tr13:
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
#line 2771 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr6;
	} else if ( _widec >= 256 )
		goto tr5;
	goto st0;
tr5:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 514 "packet.rl"
	{ sig.set( buf ); }
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 2793 "packet.cc"
	if ( (*p) == 0u )
		goto tr7;
	goto tr8;
tr7:
#line 175 "common.rl"
	{ val = 0; }
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 2805 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr9;
tr9:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st7;
tr11:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st7;
tr12:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st7;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
#line 2837 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr11;
	} else if ( _widec >= 256 )
		goto tr10;
	goto st0;
tr10:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 515 "packet.rl"
	{ msg.set( buf ); }
#line 517 "packet.rl"
	{
		debug( DBG_EP, "encryption packet: signed: %ld %ld\n", 
				sig.length, msg.length );
	}
	goto st10;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
#line 2864 "packet.cc"
	goto st0;
tr8:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st8;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
#line 2874 "packet.cc"
	goto tr12;
tr3:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st9;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
#line 2884 "packet.cc"
	goto tr13;
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 533 "packet.rl"

	if ( cs < 
#line 2904 "packet.cc"
10
#line 534 "packet.rl"
 )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * SignedId
 */

Allocated consSignedId( const String &iduri, const String &sig, const String &msg )
{
	long length = 1 +
			stringLength(iduri) +
			binLength(sig) +
			binLength(msg);

	String encPacket(length);
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_SIGNED_ID );
	dest = writeString( dest, iduri );
	dest = writeBin( dest, sig );
	dest = writeBin( dest, msg );

	return encPacket.relinquish();
}


#line 576 "packet.rl"



#line 2940 "packet.cc"
static const int packet_signed_id_start = 1;
static const int packet_signed_id_first_final = 21;
static const int packet_signed_id_error = 0;

static const int packet_signed_id_en_main = 1;


#line 579 "packet.rl"

Parser::Control PacketSignedId::data( const char *data, int dlen )
{
	
#line 2953 "packet.cc"
	{
	cs = packet_signed_id_start;
	}

#line 583 "packet.rl"

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	
#line 2964 "packet.cc"
	{
	short _widec;
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) == 9u )
		goto st2;
	goto st0;
st0:
cs = 0;
	goto _out;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 100u )
		goto tr2;
	goto st0;
tr2:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 2995 "packet.cc"
	if ( (*p) == 115u )
		goto tr3;
	goto st0;
tr3:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st4;
st4:
	if ( ++p == pe )
		goto _test_eof4;
case 4:
#line 3007 "packet.cc"
	if ( (*p) == 110u )
		goto tr4;
	goto st0;
tr4:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 3019 "packet.cc"
	if ( (*p) == 112u )
		goto tr5;
	goto st0;
tr5:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 3031 "packet.cc"
	if ( (*p) == 58u )
		goto tr6;
	goto st0;
tr6:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st7;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
#line 3043 "packet.cc"
	if ( (*p) == 47u )
		goto tr7;
	goto st0;
tr7:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st8;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
#line 3055 "packet.cc"
	if ( (*p) == 47u )
		goto tr8;
	goto st0;
tr8:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st9;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
#line 3067 "packet.cc"
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr9;
	} else if ( (*p) >= 33u )
		goto tr9;
	goto st0;
tr9:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st10;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
#line 3082 "packet.cc"
	if ( (*p) == 47u )
		goto tr10;
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr9;
	goto st0;
tr10:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st11;
st11:
	if ( ++p == pe )
		goto _test_eof11;
case 11:
#line 3096 "packet.cc"
	if ( (*p) == 0u )
		goto tr11;
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr12;
	} else if ( (*p) >= 33u )
		goto tr12;
	goto st0;
tr11:
#line 218 "common.rl"
	{ iduri.set(buf); }
	goto st12;
st12:
	if ( ++p == pe )
		goto _test_eof12;
case 12:
#line 3113 "packet.cc"
	if ( (*p) == 0u )
		goto tr13;
	goto tr14;
tr13:
#line 175 "common.rl"
	{ val = 0; }
	goto st13;
st13:
	if ( ++p == pe )
		goto _test_eof13;
case 13:
#line 3125 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr15;
tr15:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st14;
tr17:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st14;
tr24:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st14;
st14:
	if ( ++p == pe )
		goto _test_eof14;
case 14:
#line 3157 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr17;
	} else if ( _widec >= 256 )
		goto tr16;
	goto st0;
tr16:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 569 "packet.rl"
	{ sig.set( buf ); }
	goto st15;
st15:
	if ( ++p == pe )
		goto _test_eof15;
case 15:
#line 3179 "packet.cc"
	if ( (*p) == 0u )
		goto tr18;
	goto tr19;
tr18:
#line 175 "common.rl"
	{ val = 0; }
	goto st16;
st16:
	if ( ++p == pe )
		goto _test_eof16;
case 16:
#line 3191 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr20;
tr20:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st17;
tr22:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st17;
tr23:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st17;
st17:
	if ( ++p == pe )
		goto _test_eof17;
case 17:
#line 3223 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr22;
	} else if ( _widec >= 256 )
		goto tr21;
	goto st0;
tr21:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 570 "packet.rl"
	{ msg.set( buf ); }
#line 572 "packet.rl"
	{
		debug( DBG_EP, "encryption packet: signed: %ld %ld\n", 
				sig.length, msg.length );
	}
	goto st21;
st21:
	if ( ++p == pe )
		goto _test_eof21;
case 21:
#line 3250 "packet.cc"
	goto st0;
tr19:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st18;
st18:
	if ( ++p == pe )
		goto _test_eof18;
case 18:
#line 3260 "packet.cc"
	goto tr23;
tr14:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st19;
st19:
	if ( ++p == pe )
		goto _test_eof19;
case 19:
#line 3270 "packet.cc"
	goto tr24;
tr12:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st20;
st20:
	if ( ++p == pe )
		goto _test_eof20;
case 20:
#line 3280 "packet.cc"
	switch( (*p) ) {
		case 0u: goto tr11;
		case 47u: goto tr10;
	}
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr12;
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
	_test_eof12: cs = 12; goto _test_eof; 
	_test_eof13: cs = 13; goto _test_eof; 
	_test_eof14: cs = 14; goto _test_eof; 
	_test_eof15: cs = 15; goto _test_eof; 
	_test_eof16: cs = 16; goto _test_eof; 
	_test_eof17: cs = 17; goto _test_eof; 
	_test_eof21: cs = 21; goto _test_eof; 
	_test_eof18: cs = 18; goto _test_eof; 
	_test_eof19: cs = 19; goto _test_eof; 
	_test_eof20: cs = 20; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 588 "packet.rl"

	if ( cs < 
#line 3317 "packet.cc"
21
#line 589 "packet.rl"
 )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}


/*
 * Detached Signed
 */

Allocated consDetachedSig( const String &sig )
{
	long length = 1 + binLength( sig );
	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_DETACHED_SIG );
	dest = writeBin( dest, sig );

	return encPacket.relinquish();
}


#line 625 "packet.rl"



#line 3348 "packet.cc"
static const int packet_detached_sig_start = 1;
static const int packet_detached_sig_first_final = 6;
static const int packet_detached_sig_error = 0;

static const int packet_detached_sig_en_main = 1;


#line 628 "packet.rl"

Parser::Control PacketDetachedSig::data( const char *data, int dlen )
{
	
#line 3361 "packet.cc"
	{
	cs = packet_detached_sig_start;
	}

#line 632 "packet.rl"

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	
#line 3372 "packet.cc"
	{
	short _widec;
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) == 10u )
		goto st2;
	goto st0;
st0:
cs = 0;
	goto _out;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 0u )
		goto tr2;
	goto tr3;
tr2:
#line 175 "common.rl"
	{ val = 0; }
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 3401 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr4;
tr4:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st4;
tr6:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st4;
tr7:
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
#line 3433 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr6;
	} else if ( _widec >= 256 )
		goto tr5;
	goto st0;
tr5:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 618 "packet.rl"
	{ sig.set( buf ); }
#line 620 "packet.rl"
	{
		debug( DBG_EP, 
				"encryption packet: detached sig: %ld\n", 
				sig.length );
	}
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 3461 "packet.cc"
	goto st0;
tr3:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 3471 "packet.cc"
	goto tr7;
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 637 "packet.rl"

	if ( cs < 
#line 3487 "packet.cc"
6
#line 638 "packet.rl"
 )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * Detached Signed with Key.
 */

Allocated consDetachedSigKey( const String &pubKey, const String &sig )
{
	long length = 1 + binLength( pubKey ) + binLength( sig );
	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_DETACHED_SIG_KEY );
	dest = writeBin( dest, pubKey );
	dest = writeBin( dest, sig );

	return encPacket.relinquish();
}


#line 675 "packet.rl"



#line 3518 "packet.cc"
static const int packet_pub_key_detached_sig_start = 1;
static const int packet_pub_key_detached_sig_first_final = 10;
static const int packet_pub_key_detached_sig_error = 0;

static const int packet_pub_key_detached_sig_en_main = 1;


#line 678 "packet.rl"

Parser::Control PacketDetachedSigKey::data( const char *data, int dlen )
{
	
#line 3531 "packet.cc"
	{
	cs = packet_pub_key_detached_sig_start;
	}

#line 682 "packet.rl"

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	
#line 3542 "packet.cc"
	{
	short _widec;
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) == 11u )
		goto st2;
	goto st0;
st0:
cs = 0;
	goto _out;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 0u )
		goto tr2;
	goto tr3;
tr2:
#line 175 "common.rl"
	{ val = 0; }
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 3571 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr4;
tr4:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st4;
tr6:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st4;
tr13:
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
#line 3603 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr6;
	} else if ( _widec >= 256 )
		goto tr5;
	goto st0;
tr5:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 667 "packet.rl"
	{ pubKey.set( buf ); }
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 3625 "packet.cc"
	if ( (*p) == 0u )
		goto tr7;
	goto tr8;
tr7:
#line 175 "common.rl"
	{ val = 0; }
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 3637 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr9;
tr9:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st7;
tr11:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st7;
tr12:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st7;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
#line 3669 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr11;
	} else if ( _widec >= 256 )
		goto tr10;
	goto st0;
tr10:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 668 "packet.rl"
	{ sig.set( buf ); }
#line 670 "packet.rl"
	{
		debug( DBG_EP, 
				"encryption packet: detached sig: %ld\n", 
				sig.length );
	}
	goto st10;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
#line 3697 "packet.cc"
	goto st0;
tr8:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st8;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
#line 3707 "packet.cc"
	goto tr12;
tr3:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st9;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
#line 3717 "packet.cc"
	goto tr13;
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 687 "packet.rl"

	if ( cs < 
#line 3737 "packet.cc"
10
#line 688 "packet.rl"
 )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * Signed Encrypted
 */

Allocated consSignedEncrypted( const String &protKey, const String &enc )
{
	long length = 1 + binLength(protKey) + binLength(enc);
	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_SIGNED_ENCRYPTED );
	dest = writeBin( dest, protKey );
	dest = writeBin( dest, enc );

	return encPacket.relinquish();
}


#line 724 "packet.rl"



#line 3768 "packet.cc"
static const int packet_signed_encrypted_start = 1;
static const int packet_signed_encrypted_first_final = 10;
static const int packet_signed_encrypted_error = 0;

static const int packet_signed_encrypted_en_main = 1;


#line 727 "packet.rl"

Parser::Control PacketSignedEncrypted::data( const char *data, int dlen )
{
	
#line 3781 "packet.cc"
	{
	cs = packet_signed_encrypted_start;
	}

#line 731 "packet.rl"

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	
#line 3792 "packet.cc"
	{
	short _widec;
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) == 12u )
		goto st2;
	goto st0;
st0:
cs = 0;
	goto _out;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 0u )
		goto tr2;
	goto tr3;
tr2:
#line 175 "common.rl"
	{ val = 0; }
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 3821 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr4;
tr4:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st4;
tr6:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st4;
tr13:
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
#line 3853 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr6;
	} else if ( _widec >= 256 )
		goto tr5;
	goto st0;
tr5:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 717 "packet.rl"
	{ protKey.set( buf ); }
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 3875 "packet.cc"
	if ( (*p) == 0u )
		goto tr7;
	goto tr8;
tr7:
#line 175 "common.rl"
	{ val = 0; }
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 3887 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr9;
tr9:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st7;
tr11:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st7;
tr12:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st7;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
#line 3919 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr11;
	} else if ( _widec >= 256 )
		goto tr10;
	goto st0;
tr10:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 718 "packet.rl"
	{ enc.set( buf ); }
#line 720 "packet.rl"
	{
		debug( DBG_EP, "encryption packet: signed_encrypted: %ld %ld\n", 
				protKey.length, enc.length );
	}
	goto st10;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
#line 3946 "packet.cc"
	goto st0;
tr8:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st8;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
#line 3956 "packet.cc"
	goto tr12;
tr3:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st9;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
#line 3966 "packet.cc"
	goto tr13;
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 736 "packet.rl"

	if ( cs < 
#line 3986 "packet.cc"
10
#line 737 "packet.rl"
 )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * Broadcast Keys
 */

Allocated consBkKeys( const String &bk, const String &pubKey )
{
	long length = 1 + binLength(bk) + binLength(pubKey);
	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_BK_KEYS );
	dest = writeBin( dest, bk );
	dest = writeBin( dest, pubKey );

	return encPacket.relinquish();
}


#line 771 "packet.rl"



#line 4017 "packet.cc"
static const int packet_bk_keys_start = 1;
static const int packet_bk_keys_first_final = 10;
static const int packet_bk_keys_error = 0;

static const int packet_bk_keys_en_main = 1;


#line 774 "packet.rl"

Parser::Control PacketBkKeys::data( const char *data, int dlen )
{
	
#line 4030 "packet.cc"
	{
	cs = packet_bk_keys_start;
	}

#line 778 "packet.rl"

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	
#line 4041 "packet.cc"
	{
	short _widec;
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) == 13u )
		goto st2;
	goto st0;
st0:
cs = 0;
	goto _out;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 0u )
		goto tr2;
	goto tr3;
tr2:
#line 175 "common.rl"
	{ val = 0; }
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 4070 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr4;
tr4:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st4;
tr6:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st4;
tr13:
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
#line 4102 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr6;
	} else if ( _widec >= 256 )
		goto tr5;
	goto st0;
tr5:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 766 "packet.rl"
	{ bk.set( buf ); }
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 4124 "packet.cc"
	if ( (*p) == 0u )
		goto tr7;
	goto tr8;
tr7:
#line 175 "common.rl"
	{ val = 0; }
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 4136 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr9;
tr9:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st7;
tr11:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st7;
tr12:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st7;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
#line 4168 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr11;
	} else if ( _widec >= 256 )
		goto tr10;
	goto st0;
tr10:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 767 "packet.rl"
	{ pubKey.set( buf ); }
#line 768 "packet.rl"
	{
		debug( DBG_EP, "encryption packet: bk_keys\n" );
	}
	goto st10;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
#line 4194 "packet.cc"
	goto st0;
tr8:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st8;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
#line 4204 "packet.cc"
	goto tr12;
tr3:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st9;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
#line 4214 "packet.cc"
	goto tr13;
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 783 "packet.rl"

	if ( cs < 
#line 4234 "packet.cc"
10
#line 784 "packet.rl"
 )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * BK Encrypted
 */

Allocated consBkEncrypted( const String &enc )
{
	long length = 1 + binLength(enc);
	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_BK_ENCRYPTED );
	dest = writeBin( dest, enc );

	return encPacket.relinquish();
}


#line 817 "packet.rl"



#line 4264 "packet.cc"
static const int packet_bk_encrypted_start = 1;
static const int packet_bk_encrypted_first_final = 6;
static const int packet_bk_encrypted_error = 0;

static const int packet_bk_encrypted_en_main = 1;


#line 820 "packet.rl"

Parser::Control PacketBkEncrypted::data( const char *data, int dlen )
{
	
#line 4277 "packet.cc"
	{
	cs = packet_bk_encrypted_start;
	}

#line 824 "packet.rl"

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	
#line 4288 "packet.cc"
	{
	short _widec;
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) == 14u )
		goto st2;
	goto st0;
st0:
cs = 0;
	goto _out;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 0u )
		goto tr2;
	goto tr3;
tr2:
#line 175 "common.rl"
	{ val = 0; }
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 4317 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr4;
tr4:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st4;
tr6:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st4;
tr7:
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
#line 4349 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr6;
	} else if ( _widec >= 256 )
		goto tr5;
	goto st0;
tr5:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 812 "packet.rl"
	{ enc.set( buf ); }
#line 814 "packet.rl"
	{
		debug( DBG_EP, "encryption packet: bk_encrypted: %ld\n", enc.length );
	}
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 4375 "packet.cc"
	goto st0;
tr3:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 4385 "packet.cc"
	goto tr7;
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 829 "packet.rl"

	if ( cs < 
#line 4401 "packet.cc"
6
#line 830 "packet.rl"
 )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * BK Signed Encrypted
 */

Allocated consBkSignedEncrypted( const String &enc )
{
	long length = 1 + binLength(enc);
	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_BK_SIGNED_ENCRYPTED );
	dest = writeBin( dest, enc );

	return encPacket.relinquish();
}


#line 863 "packet.rl"



#line 4431 "packet.cc"
static const int packet_bk_signed_encrypted_start = 1;
static const int packet_bk_signed_encrypted_first_final = 6;
static const int packet_bk_signed_encrypted_error = 0;

static const int packet_bk_signed_encrypted_en_main = 1;


#line 866 "packet.rl"

Parser::Control PacketBkSignedEncrypted::data( const char *data, int dlen )
{
	
#line 4444 "packet.cc"
	{
	cs = packet_bk_signed_encrypted_start;
	}

#line 870 "packet.rl"

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	
#line 4455 "packet.cc"
	{
	short _widec;
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) == 15u )
		goto st2;
	goto st0;
st0:
cs = 0;
	goto _out;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 0u )
		goto tr2;
	goto tr3;
tr2:
#line 175 "common.rl"
	{ val = 0; }
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 4484 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr4;
tr4:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st4;
tr6:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st4;
tr7:
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
#line 4516 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr6;
	} else if ( _widec >= 256 )
		goto tr5;
	goto st0;
tr5:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 858 "packet.rl"
	{ enc.set( buf ); }
#line 860 "packet.rl"
	{
		debug( DBG_EP, "encryption packet: bk_signed_encrypted: %ld\n", enc.length );
	}
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 4542 "packet.cc"
	goto st0;
tr3:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 4552 "packet.cc"
	goto tr7;
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 875 "packet.rl"

	if ( cs < 
#line 4568 "packet.cc"
6
#line 876 "packet.rl"
 )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}


/*
 * Broadcast
 */

#define EP_BKT_PUBLISHER  1
#define EP_BKT_AUTHOR     2
#define EP_BKT_SUBJECT    3
#define EP_BKT_BODY       4

Allocated consBroadcast( const Broadcast &broadcast )
{
	/*
	 * Compute the length.
	 */
	long length = 1;
	if ( broadcast.publisher.length != 0 ) {
		length += 1;
		length += binLength( broadcast.publisher);
		length += binLength( broadcast.publisherSig );
	}

	if ( broadcast.author.length != 0 ) {
		length += 1;
		length += binLength( broadcast.author);
		length += binLength( broadcast.authorSig );
	}

	for ( BroadcastSubject *bs = broadcast.subjectList.head; 
			bs != 0; bs = bs->next )
	{
		length += 1;
		length += binLength( bs->subject );
		length += binLength( bs->subjectSig );
	}

	length += 1;
	length += binLength( broadcast.plainMsg );

	/*
	 * Write the packet.
	 */
	
	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_BROADCAST );

	if ( broadcast.publisher.length != 0 ) {
		dest = writeType( dest, EP_BKT_PUBLISHER );
		dest = writeBin( dest, broadcast.publisher );
		dest = writeBin( dest, broadcast.publisherSig );
	}

	if ( broadcast.author.length != 0 ) {
		dest = writeType( dest, EP_BKT_AUTHOR );
		dest = writeBin( dest, broadcast.author );
		dest = writeBin( dest, broadcast.authorSig );
	}

	for ( BroadcastSubject *bs = broadcast.subjectList.head; 
			bs != 0; bs = bs->next )
	{
		dest = writeType( dest, EP_BKT_SUBJECT );
		dest = writeBin( dest, bs->subject );
		dest = writeBin( dest, bs->subjectSig );
	}

	dest = writeType( dest, EP_BKT_BODY );
	dest = writeBin( dest, broadcast.plainMsg );

	return encPacket.relinquish();
}


#line 1000 "packet.rl"



#line 4656 "packet.cc"
static const int packet_broadcast_start = 1;
static const int packet_broadcast_first_final = 33;
static const int packet_broadcast_error = 0;

static const int packet_broadcast_en_main = 1;


#line 1003 "packet.rl"

Parser::Control PacketBroadcast::data( const char *data, int dlen )
{
	
#line 4669 "packet.cc"
	{
	cs = packet_broadcast_start;
	}

#line 1007 "packet.rl"

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	
#line 4680 "packet.cc"
	{
	short _widec;
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) == 16u )
		goto st2;
	goto st0;
st0:
cs = 0;
	goto _out;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	switch( (*p) ) {
		case 1u: goto st3;
		case 2u: goto st10;
		case 3u: goto tr4;
		case 4u: goto st25;
	}
	goto st0;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
	if ( (*p) == 0u )
		goto tr6;
	goto tr7;
tr6:
#line 175 "common.rl"
	{ val = 0; }
	goto st4;
st4:
	if ( ++p == pe )
		goto _test_eof4;
case 4:
#line 4720 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr8;
tr8:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st5;
tr10:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st5;
tr47:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 4752 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr10;
	} else if ( _widec >= 256 )
		goto tr9;
	goto st0;
tr9:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 969 "packet.rl"
	{ b.publisher.set( buf ); }
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 4774 "packet.cc"
	if ( (*p) == 0u )
		goto tr11;
	goto tr12;
tr11:
#line 175 "common.rl"
	{ val = 0; }
	goto st7;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
#line 4786 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr13;
tr13:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st8;
tr15:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st8;
tr46:
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
#line 4818 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr15;
	} else if ( _widec >= 256 )
		goto tr14;
	goto st0;
tr14:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 970 "packet.rl"
	{ b.publisherSig.set( buf ); }
	goto st9;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
#line 4840 "packet.cc"
	switch( (*p) ) {
		case 2u: goto st10;
		case 3u: goto tr4;
		case 4u: goto st25;
	}
	goto st0;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
	if ( (*p) == 0u )
		goto tr16;
	goto tr17;
tr16:
#line 175 "common.rl"
	{ val = 0; }
	goto st11;
st11:
	if ( ++p == pe )
		goto _test_eof11;
case 11:
#line 4862 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr18;
tr18:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st12;
tr20:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st12;
tr45:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st12;
st12:
	if ( ++p == pe )
		goto _test_eof12;
case 12:
#line 4894 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr20;
	} else if ( _widec >= 256 )
		goto tr19;
	goto st0;
tr19:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 975 "packet.rl"
	{ b.author.set( buf ); }
	goto st13;
st13:
	if ( ++p == pe )
		goto _test_eof13;
case 13:
#line 4916 "packet.cc"
	if ( (*p) == 0u )
		goto tr21;
	goto tr22;
tr21:
#line 175 "common.rl"
	{ val = 0; }
	goto st14;
st14:
	if ( ++p == pe )
		goto _test_eof14;
case 14:
#line 4928 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr23;
tr23:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st15;
tr25:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st15;
tr44:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st15;
st15:
	if ( ++p == pe )
		goto _test_eof15;
case 15:
#line 4960 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr25;
	} else if ( _widec >= 256 )
		goto tr24;
	goto st0;
tr24:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 976 "packet.rl"
	{ b.authorSig.set( buf ); }
	goto st16;
tr34:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 985 "packet.rl"
	{ 
				bs.subjectSig.set( buf );
				BroadcastSubject *nbs = new BroadcastSubject;
				nbs->subject = bs.subject.relinquish();
				nbs->subjectSig = bs.subjectSig.relinquish();
				b.subjectList.append( nbs );
			}
	goto st16;
st16:
	if ( ++p == pe )
		goto _test_eof16;
case 16:
#line 4994 "packet.cc"
	switch( (*p) ) {
		case 3u: goto tr4;
		case 4u: goto st25;
	}
	goto st0;
tr4:
#line 980 "packet.rl"
	{
				bs.subject.clear();
				bs.subjectSig.clear();
			}
	goto st17;
st17:
	if ( ++p == pe )
		goto _test_eof17;
case 17:
#line 5011 "packet.cc"
	if ( (*p) == 0u )
		goto tr26;
	goto tr27;
tr26:
#line 175 "common.rl"
	{ val = 0; }
	goto st18;
st18:
	if ( ++p == pe )
		goto _test_eof18;
case 18:
#line 5023 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr28;
tr28:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st19;
tr30:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st19;
tr37:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st19;
st19:
	if ( ++p == pe )
		goto _test_eof19;
case 19:
#line 5055 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr30;
	} else if ( _widec >= 256 )
		goto tr29;
	goto st0;
tr29:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 984 "packet.rl"
	{ bs.subject.set( buf );  }
	goto st20;
st20:
	if ( ++p == pe )
		goto _test_eof20;
case 20:
#line 5077 "packet.cc"
	if ( (*p) == 0u )
		goto tr31;
	goto tr32;
tr31:
#line 175 "common.rl"
	{ val = 0; }
	goto st21;
st21:
	if ( ++p == pe )
		goto _test_eof21;
case 21:
#line 5089 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr33;
tr33:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st22;
tr35:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st22;
tr36:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st22;
st22:
	if ( ++p == pe )
		goto _test_eof22;
case 22:
#line 5121 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr35;
	} else if ( _widec >= 256 )
		goto tr34;
	goto st0;
tr32:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st23;
st23:
	if ( ++p == pe )
		goto _test_eof23;
case 23:
#line 5141 "packet.cc"
	goto tr36;
tr27:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st24;
st24:
	if ( ++p == pe )
		goto _test_eof24;
case 24:
#line 5151 "packet.cc"
	goto tr37;
st25:
	if ( ++p == pe )
		goto _test_eof25;
case 25:
	if ( (*p) == 0u )
		goto tr38;
	goto tr39;
tr38:
#line 175 "common.rl"
	{ val = 0; }
	goto st26;
st26:
	if ( ++p == pe )
		goto _test_eof26;
case 26:
#line 5168 "packet.cc"
	if ( (*p) == 0u )
		goto st0;
	goto tr40;
tr40:
#line 176 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st27;
tr42:
#line 185 "common.rl"
	{ *dest++ = *p; }
	goto st27;
tr43:
#line 172 "common.rl"
	{ val |= *p; }
#line 180 "common.rl"
	{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
	goto st27;
st27:
	if ( ++p == pe )
		goto _test_eof27;
case 27:
#line 5200 "packet.cc"
	_widec = (*p);
	_widec = (short)(256u + ((*p) - 0u));
	if ( 
#line 153 "common.rl"
 --counter  ) _widec += 256;
	if ( _widec > 511 ) {
		if ( 512 <= _widec && _widec <= 767 )
			goto tr42;
	} else if ( _widec >= 256 )
		goto tr41;
	goto st0;
tr41:
#line 185 "common.rl"
	{ *dest++ = *p; }
#line 995 "packet.rl"
	{ b.plainMsg.set( buf ); }
#line 997 "packet.rl"
	{
		debug( DBG_EP, "encryption packet: broadcast\n" );
	}
	goto st33;
st33:
	if ( ++p == pe )
		goto _test_eof33;
case 33:
#line 5226 "packet.cc"
	goto st0;
tr39:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st28;
st28:
	if ( ++p == pe )
		goto _test_eof28;
case 28:
#line 5236 "packet.cc"
	goto tr43;
tr22:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st29;
st29:
	if ( ++p == pe )
		goto _test_eof29;
case 29:
#line 5246 "packet.cc"
	goto tr44;
tr17:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st30;
st30:
	if ( ++p == pe )
		goto _test_eof30;
case 30:
#line 5256 "packet.cc"
	goto tr45;
tr12:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st31;
st31:
	if ( ++p == pe )
		goto _test_eof31;
case 31:
#line 5266 "packet.cc"
	goto tr46;
tr7:
#line 171 "common.rl"
	{ val = (u_long)*p << 8; }
	goto st32;
st32:
	if ( ++p == pe )
		goto _test_eof32;
case 32:
#line 5276 "packet.cc"
	goto tr47;
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
	_test_eof33: cs = 33; goto _test_eof; 
	_test_eof28: cs = 28; goto _test_eof; 
	_test_eof29: cs = 29; goto _test_eof; 
	_test_eof30: cs = 30; goto _test_eof; 
	_test_eof31: cs = 31; goto _test_eof; 
	_test_eof32: cs = 32; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 1012 "packet.rl"

	if ( cs < 
#line 5319 "packet.cc"
33
#line 1013 "packet.rl"
 )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * Recipient List
 */

Allocated consRecipientList( const RecipientList2 &recipientList )
{
	long length = 1;

	for ( Recipient *r = recipientList.head; r != 0; r = r->next ) {
		length += r->relid.length + 1;
		length += r->iduri.length + 1;
	}
	
	length += 1;

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, EP_RECIPIENT_LIST );


	for ( Recipient *r = recipientList.head; r != 0; r = r->next ) {
		dest = writeString( dest, r->relid );
		dest = writeString( dest, r->iduri );
	}
	
	dest = writeType( dest, 0 );
	
	return packet.relinquish();
}


#line 1073 "packet.rl"



#line 5364 "packet.cc"
static const int packet_recipient_list_start = 1;
static const int packet_recipient_list_first_final = 15;
static const int packet_recipient_list_error = 0;

static const int packet_recipient_list_en_main = 1;


#line 1076 "packet.rl"

Parser::Control PacketRecipientList::data( const char *data, int dlen )
{
	
#line 5377 "packet.cc"
	{
	cs = packet_recipient_list_start;
	}

#line 1080 "packet.rl"

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	
#line 5388 "packet.cc"
	{
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) == 17u )
		goto st2;
	goto st0;
st0:
cs = 0;
	goto _out;
tr15:
#line 218 "common.rl"
	{ iduri.set(buf); }
#line 1054 "packet.rl"
	{
		Recipient *r = new Recipient;
		r->relid.set( relid );
		r->iduri.set( buf );
		rl.append( r );
	}
	goto st2;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
#line 5416 "packet.cc"
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
#line 1070 "packet.rl"
	{
		debug( DBG_EP, "encryption packet: recipeint_list\n" );
	}
	goto st15;
st15:
	if ( ++p == pe )
		goto _test_eof15;
case 15:
#line 5441 "packet.cc"
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
#line 5457 "packet.cc"
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
#line 203 "common.rl"
	{ relid.set( buf ); }
	goto st4;
st4:
	if ( ++p == pe )
		goto _test_eof4;
case 4:
#line 5480 "packet.cc"
	if ( (*p) == 100u )
		goto tr6;
	goto st0;
tr6:
#line 22 "common.rl"
	{ buf.clear(); }
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 5494 "packet.cc"
	if ( (*p) == 115u )
		goto tr7;
	goto st0;
tr7:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 5506 "packet.cc"
	if ( (*p) == 110u )
		goto tr8;
	goto st0;
tr8:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st7;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
#line 5518 "packet.cc"
	if ( (*p) == 112u )
		goto tr9;
	goto st0;
tr9:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st8;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
#line 5530 "packet.cc"
	if ( (*p) == 58u )
		goto tr10;
	goto st0;
tr10:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st9;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
#line 5542 "packet.cc"
	if ( (*p) == 47u )
		goto tr11;
	goto st0;
tr11:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st10;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
#line 5554 "packet.cc"
	if ( (*p) == 47u )
		goto tr12;
	goto st0;
tr12:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st11;
st11:
	if ( ++p == pe )
		goto _test_eof11;
case 11:
#line 5566 "packet.cc"
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr13;
	} else if ( (*p) >= 33u )
		goto tr13;
	goto st0;
tr13:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st12;
st12:
	if ( ++p == pe )
		goto _test_eof12;
case 12:
#line 5581 "packet.cc"
	if ( (*p) == 47u )
		goto tr14;
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr13;
	goto st0;
tr14:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st13;
st13:
	if ( ++p == pe )
		goto _test_eof13;
case 13:
#line 5595 "packet.cc"
	if ( (*p) == 0u )
		goto tr15;
	if ( (*p) > 46u ) {
		if ( 48u <= (*p) && (*p) <= 126u )
			goto tr16;
	} else if ( (*p) >= 33u )
		goto tr16;
	goto st0;
tr16:
#line 23 "common.rl"
	{ buf.append((*p)); }
	goto st14;
st14:
	if ( ++p == pe )
		goto _test_eof14;
case 14:
#line 5612 "packet.cc"
	switch( (*p) ) {
		case 0u: goto tr15;
		case 47u: goto tr14;
	}
	if ( 33u <= (*p) && (*p) <= 126u )
		goto tr16;
	goto st0;
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof15: cs = 15; goto _test_eof; 
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

	_test_eof: {}
	_out: {}
	}

#line 1085 "packet.rl"

	if ( cs < 
#line 5643 "packet.cc"
15
#line 1086 "packet.rl"
 )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

