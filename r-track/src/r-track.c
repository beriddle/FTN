/*****************************************************************************
 * R-Track - Simple Netmail tracker
 *
 * $Id: ftn.h,v 0.12 2007/02/20 00:12:00 riddle Exp $
 *
 * Mailer processor header
 *
 *****************************************************************************
 * Copyright (C) 2005,2007
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

#define M   256
#define PID "R-Track"
#define VER "0.12"

#if defined(__OS2__)
#define OS "2"
#elif defined(__NT__)
#define OS "W32"
#elif defined(unix)
#define OS "Unix"
#else
#define OS "DOS"
#endif

char pktdir[M],msgdir[M],prg[M];
int part,debug,dstover;
ADR fadr,toadr,fpkt,topkt;

void help(int err)
{
   printf("[?] Error: ");
   switch (err)
   {
      case 1: puts("Required parameter missing"); break;
      case 2: puts("File not found"); break;
      case 3: puts("Invalid switch"); break;
      case 4: puts("Invalid \"From\" address"); break;
      case 5: puts("Invalid \"To\" address"); break;
   }
   printf("\nUsage: %s [<Switches>]\n",prg);
   puts("Switches:");
   puts(" -M<Netmail directory>");
   puts(" -P<Packet directory>");
   puts(" -F<Packet origination>");
   puts(" -T<Packet destinaton>");
   puts(" -S<Packet size (kB)>");
   puts(" -X Override destination address");
   puts(" -D (switch for debug purposes)");
   exit(err);
}
char parse_str(int mi,int *i,int *n,char *p[],char *dest)
{
   char c=p[*i][*n],e=',';
   int j=0;
//   printf("init c='%c', e='%c', i=%d, n=%d, mi=%d\n",c,e,*i,*n,mi);
   if (!c && (*i)<mi)
   {
      (*i)++;
      *n=0;
      e=0;
   }
//   printf("stage c='%c', e='%c', i=%d, n=%d, mi=%d\n",c,e,*i,*n,mi);
   while ((c=p[*i][(*n)++]))
   {
      if (c==e) break;
      else dest[j++]=c;
//      printf("inside c='%c', e='%c', i=%d, n=%d, mi=%d\n",c,e,*i,*n,mi);
   }
   dest[j]=0;
//   printf("outside c='%c', e='%c', i=%d, n=%d, mi=%d\n",c,e,*i,*n,mi);
   if (!c && (*i)<mi)
   {
      (*i)++;
      c=p[*i][0];
      *n=(c==',')?1:0;
   }
   return c;
}
ADR parse_addr(char *c,int mi,int *i,int *n,char *p[])
{
   char tmp[M];
   *c=parse_str(mi,i,n,p,tmp);
   return decodeaddr(tmp);
}
int parse_cmdline(int ac,char *av[])
{
   char c,tmp[M];
   int k=0,n=0,p;
   part=256; debug=0; dstover=0;
   fpkt.z=0; fpkt.net=0; fpkt.node=0; fpkt.pnt=0;
   fadr.z=0; fadr.net=0; fadr.node=0; fadr.pnt=0;
   topkt.z=0; topkt.net=0; topkt.node=0; topkt.pnt=0;
   toadr.z=0; toadr.net=0; toadr.node=0; toadr.pnt=0;
   p=1; ac--;
   while (p<=ac)
   {
      c=av[p][n++];
      k=c?k:0;
//      printf("%d. (c=%c, k=%d, n=%d, p=%d) \"%s\"\n",p,c,k,n,p,av[p]);
      if (k)
      {
         if (debug) printf("Switch - \"%c\"\n",c);
         switch (tolower(c))
         {
            case 'm':
               c=parse_str(ac,&p,&n,av,msgdir);
            break;
            case 'p':
               c=parse_str(ac,&p,&n,av,pktdir);
            break;
            case 'f':
               fpkt=parse_addr(&c,ac,&p,&n,av);
            break;
            case 't':
               topkt=parse_addr(&c,ac,&p,&n,av);
            break;
            case 's':
               c=parse_str(ac,&p,&n,av,tmp);
               part=atoi(tmp);
               if (part<64 || part>1024) part=256;
            break;
            case 'x': dstover=1; p++; n=0; break;
            case 'd': debug=1; p++; n=0; break;
            default: help(3);
         }
      }
      if (!k)
         if (c=='-' || c=='/') { k=1; continue; }
      k=0;
   }
   return 0;
}

byte packmsg(ADR fpkt,ADR topkt,char *domain,
             char *msgdir,char *pktdir)
{
   FILE *mf,*pf;
   DIR *md;
   MsgHeader mh;
   PktHeader hdr;
   PktHdr ph;
   ADR fadr,toadr;
   struct stat st;
   struct dirent *dir;
   int sz=sizeof mh,rc=0,p=0,bsy=busy(topkt,topkt.z,1);
   long sb;
   char klg[M*2],pkt[M],xa[M],s[M],t[M],tn[M],msg[M],*body,*q,*x;

   binkfile(topkt,topkt.z,t);
   sprintf(pkt,"%s%scut",pktdir,t);
   if (debug) {
      printf("binkfile='%s' bsy=%d\n",pkt,bsy);
   }
   if (!bsy)
   {
      pf=fopen(pkt,"r+b");
      if (!pf) pf=fopen(pkt,"w+b");
      if (pf)
      {
         if ((md=opendir(msgdir)))
         {
            while ((dir=readdir(md)))
            {
               strcpy(t,dir->d_name);
               if (debug) printf("Checking %s\n",t);
               if (strstr(t,"msg")==NULL) continue;
	       sprintf(msg,"%s%c%s",msgdir,slash,t);

               if (debug) printf("Packing %s\n",msg);
               mf=fopen(msg,"rb");
               if (mf)
               {
                  fstat(fileno(mf),&st);
                  sb=st.st_size-sz;
                  body=malloc(sb);
                  fread(&mh,sz,1,mf);
                  fread(body,sb,1,mf);
                  fclose(mf);
                  unlink(msg);
                  // --- parse kludges
                  fadr.z=0; fadr.net=0; fadr.node=0; fadr.pnt=0;
                  toadr.z=0; toadr.net=0; toadr.node=0; toadr.pnt=0;
                  q=body;
                  klg[0]=0;
                  while (*q=='\1')
                  {
                     q++;
                     if (q==strstr(q,"INTL"))
                     {
                        q+=5;
                        x=strchr(q,' ');
                        strncpy(t,q,x-q);
                        t[x-q]=0;
                        q=x+1;
                        if (debug) printf("intl='%s' ",t);
                        toadr=decodeaddr(t);
                        x=strchr(q,'\r');
                        strncpy(t,q,x-q);
                        t[x-q]=0;
                        q=x+1;
                        if (debug) printf("'%s'\n",t);
                        fadr=decodeaddr(t);
                     }
                     else if (q==strstr(q,"TOPT"))
                     {
                        q+=5;
                        toadr.pnt=atoi(q);
                        q=strchr(q,'\r');
                        q++;
                     }
                     else if (q==strstr(q,"FMPT"))
                     {
                        q+=5;
                        fadr.pnt=atoi(q);
                        q=strchr(q,'\r');
                        q++;
                     }
                     else
                     {
                        q--;
                        x=strchr(q,'\r');
                        strncat(klg,q,x-q+1);
                        q=x+1;
                     }
                  }
                  sb-=q-body;
                  // --- parse end ---
                  fseek(pf,0L,SEEK_END); // Seek to EOF
                  if (!ftell(pf)) // New packet
                  {
                     makepkthdr(fpkt,topkt,&hdr);
                     hdr.orignet=-1; // PKT type 2+
                     fwrite(&hdr,sizeof hdr,1,pf);
                  }
                  else if (!p) fseek(pf,-2L,SEEK_END); // Double zero bypass
                  p++;
                  ph.pkttype=2;
                  ph.orignode=mh.orignode;
                  ph.orignet=mh.orignet;
                  ph.destnode=mh.destnode;
                  ph.destnet=mh.destnet;
                  ph.specific_data_lo=mh.attr;
                  ph.specific_data_hi=0;
                  if (dstover)
                  {
                     sprintf(xa,"\1X-Real-To: %d:%d/%d.%d\r",
                            toadr.z,toadr.net,toadr.node,toadr.pnt);
                     toadr=topkt;
                     ph.destnode=toadr.node;
                     ph.destnet=toadr.net;
                  } else xa[0]=0;
                  ph.specific_data_lo=ph.specific_data_hi=0;
                  fwrite(&ph,sizeof ph,1,pf);
                  strcpy(t,mh.datetim); fwrite(&t,strlen(t)+1,1,pf);
                  strcpy(t,mh.to_); fwrite(&t,strlen(t)+1,1,pf);
                  strcpy(t,mh.from); fwrite(&t,strlen(t)+1,1,pf);
                  strcpy(t,mh.subj); fwrite(&t,strlen(t)+1,1,pf);

                  sprintf(t,"\1INTL %d:%d/%d %d:%d/%d\r",
                            toadr.z,toadr.net,toadr.node,
                            fadr.z,fadr.net,fadr.node);
                  fwrite(&t,strlen(t),1,pf);
                  if (toadr.pnt)
                  {
                     sprintf(t,"\1TOPT %d\r",toadr.pnt);
                     fwrite(&t,strlen(t),1,pf);
                  }
                  if (fadr.pnt)
                  {
                     sprintf(t,"\1FMPT %d\r",fadr.pnt);
                     fwrite(&t,strlen(t),1,pf);
                  }
                  fwrite(&klg,strlen(klg),1,pf);
                  if (strlen(xa)) fwrite(&xa,strlen(xa),1,pf);
                  fwrite(q,sb,1,pf);
                  if (q[sb-1]!='\r') fputc('\r',pf);
                  codeaddr(fpkt,0,s);
                  ftndate(time(NULL),tn);
                  sprintf(t,"\1Via %s%s, %s %s %s\r",s,domain,tn,PID,VER);
                  fwrite(&t,strlen(t)+1,1,pf);
                  free(body);
               }
            }
            closedir(md);
         }
         if (p)
         {
            fputc(0,pf);
            fputc(0,pf);
         }
         fclose(pf);
      } else rc=1;
      bsy=busy(topkt,topkt.z,2);
      if (debug) printf("Packed %d messages, bsy=%d\n",p,bsy);
   }
   return rc;
}

int main(int ac,char *av[])
{
   strcpy(prg,strrchr(av[0],slash)+1);
   printf("%s/%s %s (C) Vitaly Lunyov (2:5025/18@fidonet)\n",PID,OS,VER);
   printf("Compiled on %s at %s\n",__DATE__,__TIME__);
   if (ac<3) help(1);
//   av[ac-1][strlen(av[ac-1])-1]=0;
/*
   if (debug)
   for (i=1;i<ac;i++)
   {
      printf("%d. \"%s\" (%02x)\n",i,av[i],av[i][strlen(av[i])-1]);
   }
*/
   parse_cmdline(ac,av);
   if (debug)
   {
      printf("\n*** Parsed parameters ***\n\n");
      if (*msgdir) printf("-m%s\n",msgdir);
      if (*pktdir) printf("-p%s\n",pktdir);
      printf("-f%d:%d/%d.%d\n",
             fpkt.z,fpkt.net,fpkt.node,fpkt.pnt);
      printf("-t%d:%d/%d.%d\n",
             topkt.z,topkt.net,topkt.node,topkt.pnt);
      printf("-s%d\n",part);
      if (dstover) printf("-x\n");
      printf("-d\n\n");
   }
   if (fpkt.z==0 || fpkt.net==0) help(4);
   if (topkt.z==0 || topkt.net==0) help(5);
   ftnrndinit();
   printf("[u] Packet from %d:%d/%d.%d to %d:%d/%d.%d\n",
          fpkt.z,fpkt.net,fpkt.node,fpkt.pnt,
          topkt.z,topkt.net,topkt.node,topkt.pnt);
   packmsg(fpkt,topkt,"@fidonet",msgdir,pktdir);
   puts("[u] Done\n");
   ftnrnddone();
   return 0;
}
