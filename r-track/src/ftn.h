/*****************************************************************************
 * R-Track - Simple Netmail tracker
 *
 * $Id: ftn.h,v 0.10 2005/04/27 00:10:00 riddle Exp $
 *
 * Mailer processor header
 *
 *****************************************************************************
 * Copyright (C) 2005
 *
 * Riddle Software, Inc.                    Fidonet: 2:5025/18.1@fidonet
 * Vitaly Lunyov                             Internet: riddle@riddle.ru
 *
 * This file is a part of R-Track.
 *
 * R-Track is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * R-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with R-Track; see the file COPYING. If not, write to the Free
 * Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *****************************************************************************/

#if !defined(__FTN_1)
#define __FTN_1

#ifdef unix
#define slash '/'
#else
#define slash '\\'
#endif

#ifdef __MSDOS__
#include <dos.h>
#include <io.h>
#endif
#include <sys/stat.h>
#include <time.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ftnver    "280798"
#define byte      unsigned char
#define sint      short
#define word      unsigned short
#define ulong     unsigned long
#define SPC       "\t "
#define NoChr     "!~"
#define MAX       1024
#define S         char s[MAX]
#define ftnrev    1
#define crc32init 0xffffffff

typedef struct {
   sint z,net,node,pnt;
} ADR;

typedef struct {
   sint z,net,node,pnt;
   char domain[16];
} ADDR;

typedef struct {
   word orignode,destnode,year,month,day,hour,minute,second,baud,pkttype,orignet,destnet;
   byte productcode_lo,revision_maj;
   char password[8];
   word origzone,destzone,auxnet,cwvalidationcopy;
   byte productcode_hi,revision_min;
   word capabilword,orig_zone,dest_zone,origpoint,destpoint;
   word specific_data_lo,specific_data_hi;
} PktHeader;

typedef struct {
   word pkttype,orignode,destnode,orignet,destnet;
   word specific_data_lo,specific_data_hi;
} PktHdr;

typedef struct {
   char from[36],to_[36],subj[72],datetim[20];
   word timesread,destnode,orignode,cost,orignet,destnet,destzone,origzone,
        destpoint,origpoint,replyto,attr,nextreply;
} MsgHeader;

ulong crc32(byte b,ulong crc);
ulong strcrc32(char *s);
ulong addrcrc32(ADR adr);
void  codeaddr(ADR adr,byte zeropnt,char *s);
// returns: -1   in case of address start with '*'
//          -NNN in case of address start with 'NNN*'
//           NNN in case of address start with 'NNN'
//           0   in case of default
ADR   decodeaddr(char *addr);
byte  cmp_dig(sint digit,long mask);
byte  in_addr(ADR adr,ADR mask);
byte  inaddr(ADR adr,char *masklist);
void  binkfile(ADR adr,byte mainzone,char *s);
void  fdfile(ADR adr,char *s);
byte  busy(ADR adr,byte mainzone,byte create);
void  big(char *s);
void  low(char *s);
// 0 - echomail
// 1 - netmail
byte  kludges(ADR fadr,ADR toadr,ulong msgid,ulong msgidr,char *area,char *pid,char *k);
void  ftndate(time_t t,char *s);
void  makepkthdr(ADR fpkt,ADR topkt,PktHeader *hdr);
void  ftnrndinit(void);
void  ftnrnddone(void);
ulong ftnrnd(void);
// ulong ftnrnd(int timeofs);
// 0 - fail
// 1 - ok
// 2 - end of page
byte  fgetstr(char *s,int max,FILE *f);
// option: bit 0 - allow netmail origin
//         bit 1 - "continue/continued" messages
byte postfile(ADR fpkt,ADR topkt,ADR fadr,ADR toadr,ulong msgidr,
              int part,byte option,
              char *domain,char *name,char *pktname,char *tag,char *pid,
              char *from,char *to, char *subj,char *tear,char *orig);

#ifdef __MSDOS__
#include "ftn.c"
#endif

#endif
