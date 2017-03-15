/*****************************************************************************
 * R-Track - Simple Netmail tracker
 *
 * $Id: ftn.c,v 0.10 2005/04/27 00:10:00 riddle Exp $
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

#include "ftn.h"

const char *Mnth[]={"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
char *_msgid="$msg$id$.rnd";
ulong _ftnrnd=0;
const ulong Crc32Tab[256]=
    {0x00000000,0x77073096,0xee0e612c,0x990951ba,0x076dc419,0x706af48f,0xe963a535,0x9e6495a3,
     0x0edb8832,0x79dcb8a4,0xe0d5e91e,0x97d2d988,0x09b64c2b,0x7eb17cbd,0xe7b82d07,0x90bf1d91,
     0x1db71064,0x6ab020f2,0xf3b97148,0x84be41de,0x1adad47d,0x6ddde4eb,0xf4d4b551,0x83d385c7,
     0x136c9856,0x646ba8c0,0xfd62f97a,0x8a65c9ec,0x14015c4f,0x63066cd9,0xfa0f3d63,0x8d080df5,
     0x3b6e20c8,0x4c69105e,0xd56041e4,0xa2677172,0x3c03e4d1,0x4b04d447,0xd20d85fd,0xa50ab56b,
     0x35b5a8fa,0x42b2986c,0xdbbbc9d6,0xacbcf940,0x32d86ce3,0x45df5c75,0xdcd60dcf,0xabd13d59,
     0x26d930ac,0x51de003a,0xc8d75180,0xbfd06116,0x21b4f4b5,0x56b3c423,0xcfba9599,0xb8bda50f,
     0x2802b89e,0x5f058808,0xc60cd9b2,0xb10be924,0x2f6f7c87,0x58684c11,0xc1611dab,0xb6662d3d,
     0x76dc4190,0x01db7106,0x98d220bc,0xefd5102a,0x71b18589,0x06b6b51f,0x9fbfe4a5,0xe8b8d433,
     0x7807c9a2,0x0f00f934,0x9609a88e,0xe10e9818,0x7f6a0dbb,0x086d3d2d,0x91646c97,0xe6635c01,
     0x6b6b51f4,0x1c6c6162,0x856530d8,0xf262004e,0x6c0695ed,0x1b01a57b,0x8208f4c1,0xf50fc457,
     0x65b0d9c6,0x12b7e950,0x8bbeb8ea,0xfcb9887c,0x62dd1ddf,0x15da2d49,0x8cd37cf3,0xfbd44c65,
     0x4db26158,0x3ab551ce,0xa3bc0074,0xd4bb30e2,0x4adfa541,0x3dd895d7,0xa4d1c46d,0xd3d6f4fb,
     0x4369e96a,0x346ed9fc,0xad678846,0xda60b8d0,0x44042d73,0x33031de5,0xaa0a4c5f,0xdd0d7cc9,
     0x5005713c,0x270241aa,0xbe0b1010,0xc90c2086,0x5768b525,0x206f85b3,0xb966d409,0xce61e49f,
     0x5edef90e,0x29d9c998,0xb0d09822,0xc7d7a8b4,0x59b33d17,0x2eb40d81,0xb7bd5c3b,0xc0ba6cad,
     0xedb88320,0x9abfb3b6,0x03b6e20c,0x74b1d29a,0xead54739,0x9dd277af,0x04db2615,0x73dc1683,
     0xe3630b12,0x94643b84,0x0d6d6a3e,0x7a6a5aa8,0xe40ecf0b,0x9309ff9d,0x0a00ae27,0x7d079eb1,
     0xf00f9344,0x8708a3d2,0x1e01f268,0x6906c2fe,0xf762575d,0x806567cb,0x196c3671,0x6e6b06e7,
     0xfed41b76,0x89d32be0,0x10da7a5a,0x67dd4acc,0xf9b9df6f,0x8ebeeff9,0x17b7be43,0x60b08ed5,
     0xd6d6a3e8,0xa1d1937e,0x38d8c2c4,0x4fdff252,0xd1bb67f1,0xa6bc5767,0x3fb506dd,0x48b2364b,
     0xd80d2bda,0xaf0a1b4c,0x36034af6,0x41047a60,0xdf60efc3,0xa867df55,0x316e8eef,0x4669be79,
     0xcb61b38c,0xbc66831a,0x256fd2a0,0x5268e236,0xcc0c7795,0xbb0b4703,0x220216b9,0x5505262f,
     0xc5ba3bbe,0xb2bd0b28,0x2bb45a92,0x5cb36a04,0xc2d7ffa7,0xb5d0cf31,0x2cd99e8b,0x5bdeae1d,
     0x9b64c2b0,0xec63f226,0x756aa39c,0x026d930a,0x9c0906a9,0xeb0e363f,0x72076785,0x05005713,
     0x95bf4a82,0xe2b87a14,0x7bb12bae,0x0cb61b38,0x92d28e9b,0xe5d5be0d,0x7cdcefb7,0x0bdbdf21,
     0x86d3d2d4,0xf1d4e242,0x68ddb3f8,0x1fda836e,0x81be16cd,0xf6b9265b,0x6fb077e1,0x18b74777,
     0x88085ae6,0xff0f6a70,0x66063bca,0x11010b5c,0x8f659eff,0xf862ae69,0x616bffd3,0x166ccf45,
     0xa00ae278,0xd70dd2ee,0x4e048354,0x3903b3c2,0xa7672661,0xd06016f7,0x4969474d,0x3e6e77db,
     0xaed16a4a,0xd9d65adc,0x40df0b66,0x37d83bf0,0xa9bcae53,0xdebb9ec5,0x47b2cf7f,0x30b5ffe9,
     0xbdbdf21c,0xcabac28a,0x53b39330,0x24b4a3a6,0xbad03605,0xcdd70693,0x54de5729,0x23d967bf,
     0xb3667a2e,0xc4614ab8,0x5d681b02,0x2a6f2b94,0xb40bbe37,0xc30c8ea1,0x5a05df1b,0x2d02ef8d};

ulong crc32(byte b,ulong crc)
{
   return Crc32Tab[(byte) crc ^ b] ^ ((crc >> 8) & 0x00ffffff);
}
ulong strcrc32(char *s)
{
   ulong crc=crc32init;
   int i,j=strlen(s);
   for (i=0;i<j;i++) crc=crc32(s[i],crc);
   return crc;
}
ulong addrcrc32(ADR adr)
{
   S;
   codeaddr(adr,0,s);
   return strcrc32(s);
}
//---------------------------------------------------------------------------
void codeaddr(ADR adr,byte zeropnt,char *s)
{
   if (adr.pnt || zeropnt) sprintf(s,"%d:%d/%d.%d",adr.z,adr.net,adr.node,adr.pnt);
   else sprintf(s,"%d:%d/%d",adr.z,adr.net,adr.node);
}
ADR decodeaddr(char *addr)
{
   ADR adr;
   sint a[4]={0,0,0,0},n;
   byte i=0,im=3;
   if (!strchr(addr,':')) i++;
   if (!strchr(addr,'/')) i++;
   if (strchr(addr,'.')) im++;
   for (;i<im && *addr;i++)
   {
      n=atoi(addr); while (isdigit(*addr)) addr++;
      if (*addr=='*') { n=n?-n:-1; while (isdigit(*++addr)); }
      a[i]=n; addr++;
   }
   adr.z=a[0]; adr.net=a[1]; adr.node=a[2]; adr.pnt=a[3];
   return adr;
}
byte cmp_dig(sint digit,long mask)
{
   sint i,j=1;
   if (mask==-1) return 1;
   if (mask<0)
   {
      mask=-mask;
      if (mask<=digit)
      {
         while ((i=digit/mask)>1) { j*=10; mask*=10; };
         return i && digit-mask<j;
      }
      else return 0;
   }
   else return (digit==mask);
}
byte in_addr(ADR adr,ADR mask)
{
   return cmp_dig(adr.z,mask.z) && cmp_dig(adr.net,mask.net) &&
          cmp_dig(adr.node,mask.node) && cmp_dig(adr.pnt,mask.pnt);
}
byte inaddr(ADR adr,char *masklist)
{
   sint q=0,r,ni;
   while (*masklist)
   {
      while (strchr(SPC,*masklist)) masklist++;
      if (ni=(strchr(NoChr,*masklist)!=NULL)) masklist++;
      r=in_addr(adr,decodeaddr(masklist));
//      printf("'%s' (%d) -> %d\n",masklist,ni,r);
      while (!strchr(SPC,*masklist)) masklist++;
      if (ni) q&=!r; else q|=r;
   }
   return q;
}
// ---------------------------------------------------------------------------
void binkfile(ADR adr,byte mainzone,char *s)
{
   sprintf(s,".%03x%c%04x%04x.pnt%c%08x.",adr.z,slash,adr.net,adr.node,slash,adr.pnt);
   if (!adr.pnt) s[14]=0;
   if (mainzone) strcpy(s,s+4);
}
void fdfile(ADR adr,char *s)
{
   sprintf(s,"%08lx.",addrcrc32(adr));
}
byte busy(ADR adr,byte mainzone,byte create)
{
   int rc,rh;
   S;
   binkfile(adr,mainzone,s);
   strcat(s,"bsy");
   rc=access(s,0)==0;
   if (rc && (create==2)) unlink(s);
   if (!rc && (create==1))
   {
      rh=creat(s,S_IWRITE);
      close(rh);
   }
   return rc;
}
void big(char *s)
{
   int i;
   for (i=0;i<strlen(s);i++) s[i]=toupper(s[i]);
}
void low(char *s)
{
   int i;
   for (i=0;i<strlen(s);i++) s[i]=tolower(s[i]);
}
byte kludges(ADR fadr,ADR toadr,ulong msgid,ulong msgidr,char *area,char *pid,char *k)
{
   byte i;
   S;
   big(area);
   i=(*area==0) || (strcmp(area,"NETMAIL"))==0;
   if (i)
   {
      sprintf(k,"\1INTL %d:%d/%d %d:%d/%d\r",toadr.z,toadr.net,toadr.node,fadr.z,fadr.net,fadr.node);
      if (fadr.pnt)
      {
         sprintf(s,"\1FMPT %d\r",fadr.pnt);
         strcat(k,s);
      }
      if (toadr.pnt)
      {
         sprintf(s,"\1TOPT %d\r",toadr.pnt);
         strcat(k,s);
      }
   }
   else sprintf(k,"AREA:%s\r",area);
   strcat(k,"\1MSGID: ");
   codeaddr(fadr,0,s);
   strcat(k,s);
   sprintf(s," %08lx\r",msgid);
   strcat(k,s);
   if (msgidr)
   {
      strcat(k,"\1REPLY: ");
      codeaddr(toadr,0,s);
      strcat(k,s);
      sprintf(s," %08lx\r",msgidr);
      strcat(k,s);
   }
   if (*pid)
   {
      sprintf(s,"\1PID: %s\r",pid);
      strcat(k,s);
   }
   return i;
}
void ftndate(time_t t,char *s)
{
   struct tm *a;
   a=localtime(&t);
   sprintf(s,"%02d %s %02d  %02d:%02d:%02d",(*a).tm_mday,Mnth[(*a).tm_mon],(*a).tm_year % 100,(*a).tm_hour,(*a).tm_min,(*a).tm_sec);
}
void makepkthdr(ADR fpkt,ADR topkt,PktHeader *hdr)
{
   struct tm *a;
   time_t t;
   byte i;
   t=time(NULL);
   a=localtime(&t);
   (*hdr).pkttype=2;
   (*hdr).day=(*a).tm_mday;
   (*hdr).month=(*a).tm_mon;
   (*hdr).year=(*a).tm_year+1900;
   (*hdr).hour=(*a).tm_hour;
   (*hdr).minute=(*a).tm_min;
   (*hdr).second=(*a).tm_sec;
   (*hdr).baud=0;
   (*hdr).destnode=topkt.node;
   (*hdr).destnet=topkt.net;
   (*hdr).destzone=topkt.z;
   (*hdr).dest_zone=topkt.z;
   (*hdr).destpoint=topkt.pnt;
   (*hdr).orignode=fpkt.node;
   (*hdr).orignet=fpkt.net;
   (*hdr).origzone=fpkt.z;
   (*hdr).orig_zone=fpkt.z;
   (*hdr).origpoint=fpkt.pnt;
   (*hdr).auxnet=fpkt.net;
   (*hdr).specific_data_lo=0; (*hdr).specific_data_hi=0; // 0x6b63694e;
   for (i=0;i<8;i++) (*hdr).password[i]=0;
   (*hdr).productcode_lo=0xfe;
   (*hdr).productcode_hi=0;
   (*hdr).revision_maj=0;
   (*hdr).revision_min=ftnrev;
   (*hdr).capabilword=1;
   (*hdr).cwvalidationcopy=((*hdr).capabilword & 0xff00) >> 8 | ((*hdr).capabilword & 0xff) << 8;
}
void ftnrnddone(void)
{
   FILE *f;
#ifdef __BORLANDC__
   _creat(_msgid,FA_HIDDEN);
#endif
   f=fopen(_msgid,"w+b");
   if (f)
   {
      fwrite(&_ftnrnd,4,1,f);
      fclose(f);
   }
}
void ftnrndinit(void)
{
   FILE *f;
   int i=0;
   f=fopen(_msgid,"rb");
   if (f)
   {
      i=fread(&_ftnrnd,4,1,f);
      fclose(f);
   }
   if (!i)
   {
      _ftnrnd=time(NULL)+1708041075L;
      ftnrnddone();
   }
}
ulong ftnrnd(void)
{
   return _ftnrnd++;
}
byte fgetstr(char *s,int max,FILE *f)
{
   int i=0;
   char c;
   while ((c=fgetc(f))!=EOF && c!=10 && c!=13 && c!=12 && i<max-1) s[i++]=(c=='')?'H':c;
   s[i]=0;
   if (c==10) { if ((c=fgetc(f))!=13 && c!=EOF) ungetc(c,f); } else
   if (c==13) { if ((c=fgetc(f))!=10 && c!=EOF) ungetc(c,f); }
   return (c==EOF && i==0)?0:(c==12)?2:1;
}
byte postfile(ADR fpkt,ADR topkt,ADR fadr,ADR toadr,ulong msgidr,
              int part,byte option,
              char *domain,char *name,char *pktname,char *tag,char *pid,
              char *from,char *to, char *subj,char *tear,char *orig)
{
   FILE *f,*in;
   PktHeader hdr;
   PktHdr h;
   ulong size=part*1024L,wrs,wrps /* ,msgid */;
   int i=0,j,k;
   S,s0[MAX],s1[MAX],s2[MAX],pkt[MAX],c;
   in=fopen(name,"rb");
   if (!in) return 2; // File not found
   makepkthdr(fpkt,topkt,&hdr);
   h.pkttype=hdr.pkttype;
   h.orignode=hdr.orignode;
   h.destnode=hdr.destnode;
   h.orignet=hdr.orignet; hdr.orignet=fadr.net; // -1; // PKT type 2+
   h.destnet=hdr.destnet;
   h.specific_data_lo=0; h.specific_data_hi=0;
//   printf("HdrLen=%d, HLen=%d\n",sizeof hdr,sizeof h);
   if (strlen(pktname)<5 || pktname[strlen(pktname)-1]==slash) sprintf(pkt,"%s%08lX.PKT",pktname,ftnrnd());
   else strcpy(pkt,pktname);
   if (access(pkt,2)) f=fopen(pkt,"w+b");
   else f=fopen(pkt,"r+b");
   if (!f)
   {
      fclose(in);
      return 3; // Can't create packet
   }
   else
   {
      fseek(f,0L,SEEK_END); // Seek to EOF
      if (!ftell(f)) fwrite(&hdr,sizeof hdr,1,f); // New packet
      else fseek(f,-2L,SEEK_CUR); // Double zero bypass
   }
   while (!feof(in))
   {
      j=kludges(fadr,toadr,ftnrnd(),msgidr,tag,pid,s1);
      ftndate(time(NULL)+i,s2);
      fwrite(&h,sizeof h,1,f);
      fwrite(s2,strlen(s2)+1,1,f);
      fwrite(to,strlen(to)+1,1,f);
      fwrite(from,strlen(from)+1,1,f);
      fwrite(subj,strlen(subj)+1,1,f);
      fwrite(s1,strlen(s1),1,f);
      wrs=strlen(s1)+strlen(tear)+64;
      if (!j || option & 1) wrs+=strlen(orig)+32;
      if (i && option & 2)
      {
         sprintf(s," Continue (part %d) \r",i+1);
         wrs+=fwrite(s,strlen(s),1,f);
      }
      k=1;
      while (wrs<size && k==1)
      {
         if (k=fgetstr(s,MAX,in))
         {
            fwrite(s,strlen(s),1,f);
            fputc('\r',f);
            wrs+=strlen(s)+1;
         }
//       printf("%d. '%s'\n",k,s);
      }
      if (wrs>=size || k==2)
      {
         if (option & 2)
         {
            strcpy(s," Continued on next page \r");
            fwrite(s,strlen(s),1,f);
         }
         i++;
      }
      codeaddr(fadr,0,s0);
      if (j) sprintf(s,"\1Via %s%s, %s %s\r",s0,domain,s2,pid);
      else sprintf(s,"SEEN-BY: %d/%d\r",fadr.net,fadr.node);
      if (!j || option & 1)
      {
         sprintf(s2,"\r * Origin: %s (%s)",orig,s0);
      }
      else s2[0]=0;
      sprintf(s0,"\r--- %s%s\r%s",tear,s2,s);
      fwrite(s0,strlen(s0)+1,1,f);
   }
   fputc(0,f);
   fputc(0,f);
   fclose(f);
   fclose(in);
   return 0;
}
