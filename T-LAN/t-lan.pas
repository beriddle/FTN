(*****************************************************************************
 * T-LAN - Universal Log Analyser
 *
 * $Id: t-lan.pas,v 0.34.11 2000/11/19 00:08:00 riddle Exp $
 *
 * Mailer processor header
 *
 *****************************************************************************
 * Copyright (C) 1996-2000
 *
 * Riddle Software, Inc.                    Fidonet: 2:5025/18.1@fidonet
 * Vitaly Lunyov                             Internet: riddle@riddle.ru
 *
 * This file is a part of T-LAN.
 *
 * T-LAN is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * T-LAN is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with T-LAN; see the file COPYING. If not, write to the Free
 * Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *****************************************************************************)

{$define binkd}
{$ifdef os2}
{$define gpm}
{$endif}
{$define dlc}
{$define alpha}
{.$define beta}
{.$define release}
{$M 50000,50000,350000}
{$E+}
{$N+}
{$ifdef ver70}
{$G+}
{$S-}
{$endif}
uses dos,support,lng{$ifndef ver70},use32,vputils{$endif}{$ifdef os2},os2sup{$endif};
type soc=set of char;
const vernum='0.34';
      vername='T-LAN';
      ver=vernum+'/'+{$ifdef alpha}'Alpha'+{$endif}
                     {$ifdef beta}'Beta'{'Alpha'}+{$endif}
                     {$ifndef release}'-11'+{$endif}
                     {$ifndef release}'/'+{$endif}
                     {$ifdef ver70}'DOS'{$endif}
                     {$ifdef os2}'OS2'{$endif}
                     {$ifdef win32}'W32'{$endif};
      vercopy='1996-2000';
      verdate='27-Feb-00';
{$ifndef ver70}
      SMaxIdx=1000;
      OMaxIdx=500;
{$else}
      SMaxIdx=200;
      OMaxIdx=200;
{$endif}
      FMaxIdx=500;
      FMax=500;
      MMaxIdx=500;
      MaxAli=500;
      cpstbl=9;
      maxbuf=8192;
      defzone=2;
      nochr=['!','~'];
      MaxEvt=6;
      OS2Slice=36;
      VDMSlice=130;

type Long=System.LongInt;
     Wrd=System.Word;
     Int=System.Integer;
     TAli=record
             Alias:long;
             SAlias:string[16];
             z,net,node,pnt:int;
          end;
     TPFil=record
              fz,fnet,fnode,fpnt:int
           end;
     TFil=record
             name:string[12];
             btime,etime,size,txsize:long;
             fstat:byte;
             fz,fnet,fnode,fpnt:int
             {0 - sent/received
              1 - failed/ok
              2..7 - reserved}
          end;
     TSes=record
             z,net,node,pnt:int;
             t_itraf,t_otraf,t_time,b_time,e_time:long;
             speed:long;
             status,mincps,maxcps:wrd;
             zyz:string[zyzl];
             mlr:string[mlrl];
            {0 - password protection    1/0   1
             1 - password error         1/0   2
             2 - finished ok           1/0    4
             3 - handshake EMSI/YooHoo 1/0    8
             4 \  010 - ZedZap  100 Janus    16 16,32,48,64,80,96,112
             5  | 011 - DirZap  101 Hydra    32
             6 /  001 - zmodem  110 Hydra/hdx 64 111 Xmodem
             7 - Unlisted              1/0  128
             8 - Incoming/Outgoing     1/0  256
             9 - CRC-32/16             1/0  512
            10 - External freq         1/0 1024
            11 - Additional to 4..6    1/0 2048 1000 - BinkP 2048}
          end;
     TOvr=record
             oz,onet,onode,opnt:int;
             online,okonline:long;
             rcvd,sent:comp;
             incalls,outcalls,sessions,mincps,maxcps:wrd;
             ozyz:string[zyzl];
             omlr:string[mlrl];
             {Lower 4 bits of sessions:
              0 - passwrd protection   1/0    1
              1 - passwrd error        1/0    2
              2 - finished ok          1/0    4
              3 - reserved             1/0    8}
          end;
     TCPS=record
             cz,cnet,cnode,cpnt:int;
             cps:wrd
          end;
     TCPSW=record
              cz,cnet,cnode,cpnt:int;
              ccps:array[0..2] of wrd
           end;

     TPktHdr=record
                origNode,destNode,year,month,day,hour,minute,second,baud,
                pkttype,origNet,destNet:wrd;
                ProductCode_Lo,Revision_Maj:byte;
                password:array[1..8] of char;
                origZone,destZone,AuxNet,CWvalidationCopy:wrd;
                ProductCode_Hi,Revision_Min:byte;
                CapabilWord,orig_Zone,dest_Zone,origPoint,destPoint:wrd;
                Specific_Data:array[1..4] of char
             end;
     TPktHdr0=record
                 pkttype,origNode,destNode,origNet,destNet:wrd;
                 Specific_Data:long
              end;
     PPktHdr=^TPktHdr;
     TSet=array[1..nrkw+rkw] of string;
     PSes=array[0..SMaxIdx-1] of TSes;
     POvr=array[0..OMaxIdx-1] of TOvr;
     PCPSW=array[0..OMaxIdx-1] of TCPSW;
     PFil=array[0..FMaxIdx-1] of TPFil;
     PFBf=array[0..FMax-1] of TFil;
     PCPS=array[0..cpstbl] of TCPS;
     TGrf=array[0..71,1..maxevt] of wrd;
     TBuf=array[1..maxbuf] of char;
     PBuf=^TBuf;
     str2=string[2];
     talias=array[1..MaxAli] of tali;

const TPFilS=sizeof(TPFil);
      TFilS=sizeof(TFil)-8;
      TSesS=sizeof(TSes);
      TOvrS=sizeof(TOvr);
      SoP=sizeof(tpkthdr);
      {$ifdef ver70}
      MemReq:long=300000;
      {$else}
      MemReq:long=500000;
      {$endif}

var lf,f:file;
    fptr,swpptr,_tmp,_nodes,tltm,oltm,otm,itm,ctm,etm,ertm,htm,flsize,fssize,
    cpsdiv,date0,date1,time0_,time1_,time0,time1,l0,
    mem0,hilog,lolog:long;
    buf:pbuf;
    busytime:tgrf;
    bufptr,bufmax,flmode,skp,ii,ji,qi,ki,part,wi,i0,j0:word;
    msgatr,cps_max,kbyte:wrd;
    parts,maxp,kb,li,maxtask,tasks,mtsk,mg,cps_opt:byte;
    d0,d1,t0,t1,cd0,cd1,bdir,ldir,lnam,ps1,tearline,vialine,
    hdr,kludges,mlname,s,pwd,pid,sll:string;
    fcps,onestep,no_ev,
    netmail,opened,hide_a,hide_n,hide_t,hide_f,
    hid_arc,hid_net,hid_tic,hid_fil,hid_skp,
    log_cut,log_bak,
    t_hid_det,t_hid_ext,t_hid_fai,t_hid_pwd,
    s_hid_ext,s_hid_fai,s_hid_pwd,
    g_wide,g_fake,g_spc,g_skp,
    cps_rev,cps_adr,cps_top,
    p_1st,
    a_4d,
    log_kil,
    run,mline,frst,q,s_wi,bdf,kcase,fsc46
    {------------------}
    :boolean;
    sr:searchrec;
    packet:ppkthdr;
    p_buf:ptxtbuf;
    smaxcps,smincps,amaxcps,amincps:pcps;
    smax,smin,amax,amin,d_opt:byte;
    taskset:set of byte;
    itask,jtask:byte;
    VSet:^TSet;
    id8,id14:int;
    alias:^talias;
    aidx:int;
    ocps:pcpsw;
{---------------------------------------------------------------------------}
function ResetLf(exiting:boolean):boolean; forward;

procedure SkipChr(s:string;var i:byte;term:soc);
begin
   while (i<=length(s)) and (s[i] in term) do inc(i);
end;
function ReadWord(s:string;var i:byte;term:soc):string;
var s0:string;
begin
   s0:='';
   if (' ' in term) or (#9 in term) then SkipChr(s,i,spc);
   while (i<=length(s)) and not (s[i] in term) do
      begin
         s0:=s0+s[i];
         inc(i)
      end;
   if i<=length(s) then inc(i);
   timeslice;
   ReadWord:=s0
end;
function Dec2Str(l:comp;o:byte):string;
var s:string;
    i,b:byte;
begin
   i:=0;
   while l>999999 do
      begin
         inc(i);
         l:=l/kbyte
      end;
   case i+o of
      0: s:=' ';
      1: s:='K';
      2: s:='M';
      3: s:='G'
   end;
   if (kbyte=1000) and kcase then s[1]:=lowcase(s[1]);
   i:=0;
   repeat
      if i=3 then s:=','+s;
      b:=trunc(l) mod 10;
      s:=chr(b+$30)+s;
      inc(i);
      l:=(l-b)/10
   until l=0;
   Dec2Str:=s
end;
function strzna(n:comp;p:byte):string;
var s:string;
begin
   if n=-1 then strzna:='--- ' else strzna:=dec2str(n,0)
end;
function DT2Str(t:long):string;
var dt:datetime;
    s:string;
begin
   sec2dt(t,dt);
   with dt do s:=strz(day,2)+'/'+strz(month,2)+' '+
                 strz(hour,2)+':'+strz(min,2)+':'+strz(sec,2);
   DT2Str:=s
end;
function Str2Sec(s:string):long;
var dt:datetime;
    t:long;
begin
   with dt do
      begin
         Str2Date(copy(s,1,5),day,month);
         Str2Time(copy(s,7,8),hour,min,sec);
         year:=nyear;
         if (month*32+day)>(nym*32+nyd) then dec(year)
      end;
   Str2Sec:=dtm2sec(dt)
end;
function NewName(c:char):string;
begin
   if mline then NewName:=bdir+'Station.St'+c
            else NewName:=bdir+copy(lnam,1,pos('.',lnam))+'st'+c
end;
function TplName(c:char):string;
var s:string;
begin
   s:=VSet^[30];
   if (pos(':',s)<>2) and (pos('\',s)<>1) then s:=rdir+s;
   TplName:=big(s+'St'+c+'.Tpl')
end;
function Code_Addr(z,net,node,pnt:int;zeropnt,needalias:boolean):string;
var s:string;
    i:int;
begin
   if (z=0) and (net=0) and (node=0) and (pnt=0) then Code_Addr:=lang^[Code_Addr_1] else
   if (z=-1) and (net>=0) and (node>=0) and (pnt>=0) then Code_Addr:=lang^[Code_Addr_2] else
   if (z=-2) and (net>=0) and (node>=0) and (pnt>=0) then Code_Addr:=lang^[Code_Addr_3] else
   if (z=-3) and (net>=0) and (node>=0) and (pnt>=0) then Code_Addr:=lang^[Code_Addr_4] else
      begin
         s:='';
         if needalias then
            begin
               if not a_4d then
                  for i:=1 to aidx do
                     if (z=alias^[i].z) and (net=alias^[i].net) and
                        (node=alias^[i].node) and (pnt=alias^[i].pnt) then
                        begin
                           s:=alias^[i].salias;
                           break
                        end
            end;
         if s='' then
            begin
{$ifdef alpha}
               s:=strz(z,1)+':'+strz(net,1)+'/'+strz(node,1);
               if (pnt<>0) or zeropnt then s:=s+'.'+strz(pnt,1)
{$else}
               s:=astr(z)+':'+astr(net)+'/'+astr(node);
               if (pnt<>0) or zeropnt then s:=s+'.'+astr(pnt)
{$endif}
            end;
         if length(s)>16 then s:=copy(s,1,16);
         Code_Addr:=s
      end
end;

function AddrCRC32(z,net,node,pnt:int):long;
begin
   AddrCRC32:=strcrc32(code_addr(z,net,node,pnt,false,false));
end;

function getalias(s:string;var z,net,node,pnt:int):byte;
var i:int;
    l:long;
    s0:string;
begin
   s0:='unknown';
   while (s<>'') and (s[length(s)]=' ') do delete(s,length(s),1);
   while (s<>'') and (s[1]=' ') do delete(s,1,1);
   s:=lower(s);
   l:=strcrc32(s);
   for i:=1 to aidx do
      if alias^[i].alias=l then
         begin
            z:=alias^[i].z; net:=alias^[i].net;
            node:=alias^[i].node; pnt:=alias^[i].pnt;
            s0:=code_addr(z,net,node,pnt,false,true);
            break
         end;
   getalias:=ord(s0='unknown')
end;

function Decode_Addr(addr:string;var z,net,node,pnt:int;single:boolean):byte;
var i:byte;
    s:string;
function SNum:int;
var n:int;
    i:byte;
begin
   n:=1;
   for i:=1 to length(s) do
      begin
         if (s[i]='?') and (n<10000) then n:=n*10 else
         if (s[i]='*') then n:=10001 else
            begin
               n:=1;
               break
            end
      end;
   if n>1 then dec(n);
   if n=10000 then n:=32767;
   SNum:=-n
end;
begin
   i:=1;
   while addr[i]=' ' do inc(i);
   if ((addr[i]<'0') or (addr[i]>'9')) and (addr[i]<>'?') and (addr[i]<>'*') then decode_addr:=getalias(addr,z,net,node,pnt)
                                                                             else
   begin
      if pos('.',addr)=0 then addr:=addr+'.0';
      if pos(':',addr)=0 then insert(strz(home.z,1)+':',addr,i);
      s:=readword(addr,i,[':']); z:=snum;
      if z=-1 then z:=lval(s);
      s:=readword(addr,i,['/']); net:=snum;
      if net=-1 then net:=lval(s);
      s:=readword(addr,i,['.']); node:=snum;
      if node=-1 then node:=lval(s);
      s:=readword(addr,i,['@',#0]); pnt:=snum;
      if pnt=-1 then pnt:=lval(s);
      if single then
         decode_addr:=ord(z<0)*128+ord(net<0)*64+ord(node<0)*32+ord(pnt<0)*16
                else
         decode_addr:=ord(z=-1)*128+ord(net=-1)*64+ord(node=-1)*32+ord(pnt=-1)*16
   end
end;
function InTime(var b_time,e_time:long;time0:long):boolean;
var dtb,dte,dt0,dt1:datetime;
    hb,he,h0,h1,mb,me,m0,m1:long;
begin
   {-----------------------}
   {Changed at 0.34/Alpha-11}
   {InTime:=(b_time>=time0) and (b_time<=time1) and
          ((e_time>=time0) and (e_time<=time1+delta_t));}
   sec2dt(b_time,dtb);
   sec2dt(e_time,dte);
   sec2dt(time0,dt0);
   sec2dt(time1,dt1);
   with dtb do begin hb:=sec+60*(min+60*hour); mb:=day+32*month end;
   with dte do begin he:=sec+60*(min+60*hour); me:=day+32*month end;
   with dt0 do begin h0:=sec+60*(min+60*hour); m0:=day+32*month end;
   with dt1 do begin h1:=sec+60*(min+60*hour); m1:=day+32*month end;
   if me<mb then inc(me,500);
   if he<hb then inc(he,86400);
   if m1<m0 then inc(m1,500);
   if h1<h0 then inc(h1,86400);
   InTime:=(hb>=h0) and (hb<=h1) and (he>=h0) and (he<=h1) and
           (mb>=m0) and (mb<=m1) and (me>=m0) and (me<=m1);
   {------------------------}
   {In this case: recalculating all session}
   {if e_time>time1 then e_time:=time1}
end;
function In_Addr(zt,nett,nodet,pntt:int;addrm:string):boolean;
var zm,netm,nodem,pntm:int;
    q:boolean;
begin
   q:=decode_addr(addrm,zm,netm,nodem,pntm,false)=0;
   if q then
      begin
         if zm<0 then q:=q and (zt<=-zm) else q:=q and (zt=zm);
         if netm<0 then q:=q and (nett<=-netm) else q:=q and (nett=netm);
         if nodem<0 then q:=q and (nodet<=-nodem) else q:=q and (nodet=nodem);
         if pntm<0 then q:=q and (pntt<=-pntm) else q:=q and (pntt=pntm)
      end;
   In_Addr:=q
end;
function InAddr(z,net,node,pnt:int;s:string):boolean;
var q,r,ni:boolean;
    i:byte;
    adrm:string;
begin
   q:=false;
   i:=1;
   while i<length(s) do
      begin
         adrm:=readword(s,i,spc);
         ni:=(adrm[1] in nochr);
         if ni then delete(adrm,1,1);
         r:=In_Addr(z,net,node,pnt,adrm);
         if ni then q:=q and not r else q:=q or r
      end;
   InAddr:=q
end;
{---------------------------------------------------------------------------}
function CreatePktHdr(_from,_fadr,_to,_tadr,_subj,area:string;
                      var packet:ppkthdr;var msgid:byte;var hdr:string):string;
var i,s1:word;
    z,net,node,pnt,pnt0:int;
    s,s0:string;
    dt:datetime;
begin
   for i:=1 to length(area) do area[i]:=upcase(area[i]);
   CreatePktHdr:='';
   with packet^ do
      begin
         pkttype:=2;
         with dt do
            begin
               getdate(year,month,day,s1);
               gettime(hour,min,sec,s1);
               minute:=min; second:=sec
            end;
         year:=dt.year; month:=pred(dt.month); day:=dt.day; hour:=dt.hour;
         if length(_from)>35 then _from:=copy(_from,1,35);
         if length(_to)>35 then _to:=copy(_to,1,35);
         if length(_subj)>71 then _subj:=copy(_subj,1,71);
         hdr:=#0+_to+#0+_from+#0+_subj+#0;
         baud:=0;
         decode_addr(_tadr,z,net,node,pnt,true);
         if netmail then s:=#1'INTL '+code_addr(z,net,node,0,false,false)+' '
                    else s:='AREA:'+area;
         destNode:=node;
         destNet:=net;
         destZone:=z;
         dest_Zone:=z;
         decode_addr(VSet^[12],z,net,node,pnt0,true);
         origNode:=node; origNet:=net; AuxNet:=net;
         origZone:=z; orig_Zone:=z;
         origPoint:=pnt0; destPoint:=pnt;
         decode_addr(_fadr,z,net,node,pnt0,true);
         if netmail then
            begin
               s:=s+strz(z,1)+':'+strz(net,1)+'/'+strz(node,1);
               if pnt0<>0 then s:=s+#13#1'FMPT '+strz(pnt0,1);
               if pnt<>0 then s:=s+#13#1'TOPT '+strz(pnt,1);
            end;
         Specific_Data[1]:=chr(lo(msgatr));
         Specific_Data[2]:=chr(hi(msgatr));
         Specific_Data[3]:=#0;
         Specific_Data[4]:=#0;
         s:=s+#13#1'MSGID: '+VSet^[13]+' ';
         msgid:=length(s)+1;
         for i:=1 to 8 do
            if i<=length(pwd) then password[i]:=pwd[i]
                              else password[i]:=#0;
         ProductCode_Lo:=lval(copy(vernum,1,1));
         ProductCode_Hi:=0;
         Revision_Maj:=0;
         Revision_Min:=lval(copy(vernum,3,length(vernum)-2));
         CapabilWord:=1;
         CWvalidationCopy:=hi(CapabilWord)+lo(CapabilWord) shl 8;
         s:=s+#13#1'PID: '+pid+{$ifdef alpha}' ('+verdate+')'+{$endif}#13
      end;
   CreatePktHdr:=s
end;

function ImportFile(name:string;post,continuous,last:boolean):long;
var z,net,node,pnt,utc:int;
    jj,bpart:word;
    sbuf:tpkthdr0;
    s:string;
    txt:text;
    f:file;
    k:long;
    io:byte;
    newpkt:boolean;
procedure Wrt2Buf(s:string);
var i0,k0:byte;
begin
   k0:=length(s);
   for i0:=1 to k0 do p_buf^[ji+i0-1]:=s[i0];
   inc(ji,k0); inc(ii,k0)
end;
function ImpFile:long;
begin
   if not opened then
      begin
         part:=0;
         ki:=0;
         ImpFile:=0;
         ji:=0;
         kludges:=CreatePktHdr(VSet^[nrkw+1],VSet^[13],VSet^[nrkw+2],VSet^[14],VSet^[nrkw+3],VSet^[10],packet,li,hdr);
         if kludges='' then exit;
         if newpkt then
            begin
               blockwrite(f,packet^,sop,ii);
               if ii<sop then exit
            end;
         opened:=true
      end;
   with packet^ do
     begin
        sbuf.pkttype:=pkttype;
        sbuf.origNode:=origNode;
        sbuf.destNode:=destNode;
        if origNet+1=0 then sbuf.origNet:=AuxNet
                       else sbuf.origNet:=origNet;
        sbuf.destNet:=destNet
     end;
   sbuf.Specific_Data:=msgatr;
   repeat
      if ji=0 then
         begin
            blockwrite(f,sbuf,sizeof(sbuf),jj);
            if jj<sizeof(sbuf) then exit;
            inc(ii,jj);
            inc(part);
            s:=kludges;
            insert(ftnrnd,s,li); {MSGID}
            if part>1 then s:=s+' '+lang^[Imp_File_1]+' '+strz(part,1)+') '#13;
            wrt2buf(date(timeofs)+hdr+s);
         end;
      while (ii<bpart) and not eof(txt) do
         begin
            readln(txt,s);
            wrt2buf(s+#13)
         end;
      inc(ki,ii);
      if eof(txt) then s:='' else s:=' '+lang^[Imp_File_2]+' '#13;
      if not continuous or (ii>=bpart) or last then
         begin
            if not continuous and (s='') then part:=0;
            s:=s+#13'--- '+VSet^[NRkw+6]+#13;
            if not netmail then
               begin
                  decode_addr(VSet^[13],z,net,node,pnt,true);
                  s:=s+' * Origin: '+VSet^[nrkw+4]+' ('+VSet^[13]+')'#13'SEEN-BY: '+strz(net,1)+'/'+strz(node,1)
               end
                           else
               begin
                  ii:=0;
                  s:=s+#1'Via '+VSet^[13]+', '+date(ii)+' '+vialine
               end;
            wrt2buf(s+#13#0);
            blockwrite(f,p_buf^,ji,ii);
            if ii<ji then exit;
            inc(ki,ii);
            ii:=0;
            ji:=0
         end
   until eof(txt);
   ImpFile:=ki
end;
begin
   if post then
      begin
         k:=0;
         bpart:=kb*1024-sop;
         opened:=timeofs<>0;
         newpkt:=true;
         if not opened then
            begin
               ImportFile:=k;
               assign(f,VSet^[11]+ftnrnd+'.PKT');
               {$I-}
               reset(f,1);
               {$I+}
               io:=ioresult;
               if io=0 then
                  begin
                     {$I-}
                     seek(f,filesize(f)-2);
                     {$I+}
                     io:=ioresult
                  end;
               if io=0 then newpkt:=false
                       else
                  begin
                     {$I-}
                     rewrite(f,1);
                     {$I+}
                     io:=ioresult
                  end;
               if io<>0 then exit;
               new(packet);
               getmem(p_buf,bpart+512);
            end;
         assign(txt,name);
         {$I-}
         reset(txt);
         {$I+}
         io:=ioresult;
         if io=0 then k:=impfile else k:=1;
         if last then
            begin
               freemem(p_buf,bpart+512);
               dispose(packet);
               if filesize(f)>=75 then {Non-empty packet}
                  begin
                     jj:=0;
                     blockwrite(f,jj,2);
                  end
                                  else k:=0;
               close(f)
            end;
         if io=0 then close(txt);
         if k=0 then
            begin
               if not last then close(f);
               opened:=false;
               {$I-}
               erase(f);
               {$I+}
               if ioresult<>0 then wlog(2,'Can''t erase '+name);
            end
      end
           else k:=1;
   ImportFile:=k
end;
{---------------------------------------------------------------------------}
function ReadLogStr(var s:string):boolean;
var q:boolean;
begin
   q:=false;
   if fptr=0 then
      begin
         bufptr:=0;
         bufmax:=0;
         getmem(buf,maxbuf)
      end;
   if (bufptr=0) or (bufptr>bufmax) then
      begin
         filemode:=$40;
         {$I-}
         reset(lf,1);
         {$I+}
         if ioresult=0 then
            begin
               if fptr<filesize(lf) then
                  begin
                     seek(lf,fptr);
                     blockread(lf,buf^,maxbuf,bufmax);
                     bufptr:=1;
                     inc(fptr,bufmax)
                  end
                                    else
                  begin
                     freemem(buf,maxbuf);
                     fptr:=-1 {eof}
                  end;
               close(lf)
            end;
         filemode:=flmode
      end;
   if bufmax>0 then
      begin
         while (bufptr<=bufmax) and (buf^[bufptr]<>#13) do
            begin
               s:=s+buf^[bufptr];
               inc(bufptr)
            end;
         q:=(bufptr<=bufmax) and (buf^[bufptr]=#13);
         if q then
            begin
               inc(bufptr);
               if bufptr<=bufmax then if buf^[bufptr]=#10 then inc(bufptr) {Case for Unix lines}
            end
      end;
   ReadLogStr:=q
end;
function ReadLogStrn(var s:string):boolean;
begin
   s:=sll;
   if sll<>'' then sll:=''
              else
      {$ifdef binkd}
      if cbidx<>0 then s:=bnd2tml_get else
      {$endif}
      while not ReadLogStr(s) and (fptr<>-1) do {Nothing};
   ReadLogStrn:=fptr<>-1;
   timeslice
end;
{-------------------------- Added at 0.18/Alpha-5 ---------------------------}
{Type conversion procedures}
var {TFil}
    FCurIdx,FCurBlk,FIdx:long;
    Fil:^PFil;
    FBf:^PFBf;
    FChg:boolean;
    {TSes}
    SCurIdx,SCurBlk:long;
    Ses:^PSes;
    SChg:boolean;
    {TOvr}
    OCurIdx,OCurBlk:long;
    Ovr:^POvr;
    OChg:boolean;
    {----}
function RealArrayIdx(CurIdx,MaxIdx:int;var NewBlk:int):int;
begin
   NewBlk:=CurIdx div MaxIdx;
   RealArrayIdx:=CurIdx-long(MaxIdx)*NewBlk
end;
function TypeDef(arrtype:byte;var C:char;var CurIdx,CurBlk,MaxIdx,RecSize:int):boolean;
var chg:boolean;
begin
   case arrtype of
      0: begin
            c:='-';
            Chg:=SChg;
            RecSize:=TSesS;
            CurIdx:=SCurIdx;
            CurBlk:=SCurBlk;
            MaxIdx:=SMaxIdx
         end;
      1: begin
            c:='%';
            Chg:=OChg;
            RecSize:=TOvrS;
            CurIdx:=OCurIdx;
            CurBlk:=OCurBlk;
            MaxIdx:=OMaxIdx
         end;
      2: begin
            c:='$';
            Chg:=FChg;
            RecSize:=TPFilS;
            CurIdx:=FCurIdx;
            CurBlk:=FCurBlk;
            MaxIdx:=FMaxIdx
         end
   end;
   typedef:=chg
end;
function ReadArray(arrtype:byte):int; {0 - Ses, 1 - Ovr, 2 - Fil}
var f:file;
    rr:integer;
    CurIdx,CurBlk,MaxIdx,RecSize,i:int;
    c:char;
begin
   TypeDef(arrtype,c,CurIdx,CurBlk,MaxIdx,RecSize);
   assign(f,newname(c));
   {$I-}
   reset(f,1);
   {$I+}
   if ioresult=0 then
      begin
         seek(f,long(MaxIdx)*CurBlk*RecSize);
         {$ifdef alpha}
         write('r'#8);
         {$endif}
         for i:=0 to MaxIdx-1 do
            begin
               case arrtype of
                  0: blockread(f,Ses^[i],RecSize,rr);
                  1: blockread(f,Ovr^[i],RecSize,rr);
                  2: blockread(f,Fil^[i],RecSize,rr)
               end;
               if rr<>RecSize then break
            end;
         {$ifdef alpha}
         write(' '#8);
         {$endif}
         close(f);
         ReadArray:=i
      end
                 else ReadArray:=0
end;
function FlushArray(arrtype:byte;MaxCel:int):boolean;
var f:file;
    ww:integer;
    CurIdx,CurBlk,MaxIdx,RecSize,i:int;
    c:char;
begin
   TypeDef(arrtype,c,CurIdx,CurBlk,MaxIdx,RecSize);
   assign(f,newname(c));
   {$I-}
   reset(f,1);
   {$I+}
   ww:=ioresult;
   if (ww<>0) and (CurBlk=0) then
      begin {Create a new file}
         {$I-}
         rewrite(f,1);
         {$I+}
         ww:=ioresult
      end;
   if ww=0 then
      begin
         seek(f,long(MaxIdx)*CurBlk*RecSize);
         {$ifdef alpha}
         write('w'#8);
         {$endif}
         for i:=0 to MaxCel-1 do
            begin
               case arrtype of
                  0: begin blockwrite(f,Ses^[i],RecSize,ww); SChg:=false end;
                  1: begin blockwrite(f,Ovr^[i],RecSize,ww); OChg:=false end;
                  2: begin blockwrite(f,Fil^[i],RecSize,ww); FChg:=false end
               end;
               if ww<>RecSize then break
            end;
         {$ifdef alpha}
         write(' '#8);
         {$endif}
         close(f);
         FlushArray:=ww=RecSize
      end
end;
procedure Common(arrtype:byte;var Idx:int);
var CurIdx,CurBlk,MaxIdx,RecSize,NewBlk:int;
    c:char;
    chg:boolean;
begin
   Chg:=TypeDef(arrtype,c,CurIdx,CurBlk,MaxIdx,RecSize);
   Idx:=RealArrayIdx(Idx,MaxIdx,NewBlk);
   if NewBlk<>CurBlk then
      begin
         if NewBlk>CurBlk then CurIdx:=MaxIdx
                          else
            begin
               CurIdx:=CurIdx-NewBlk*MaxIdx;
               if CurIdx>MaxIdx then CurIdx:=MaxIdx
            end;
         if Chg then FlushArray(arrtype,CurIdx);
         case arrtype of
            0: SCurBlk:=NewBlk;
            1: OCurBlk:=NewBlk;
            2: FCurBlk:=NewBlk
         end;
         ReadArray(arrtype)
      end
end;
procedure Ses_(Idx:int;Wrt:boolean;var ss:tses);
begin
   Common(0,Idx);
   if wrt then
      begin
         Ses^[Idx]:=ss;
         SChg:=true
      end
          else ss:=Ses^[Idx]
end;
procedure Ovr_(Idx:int;Wrt:boolean;var ss:tovr);
begin
   Common(1,Idx);
   if wrt then
      begin
         Ovr^[Idx]:=ss;
         OChg:=true
      end
          else ss:=Ovr^[Idx]
end;
procedure Fil_(Idx:int;Wrt:boolean;var ss:tpfil);
begin
   Common(2,Idx);
   if wrt then
      begin
         Fil^[Idx]:=ss;
         FChg:=true
      end
          else ss:=Fil^[Idx]
end;
procedure SwpIdxInit;
begin
   FIdx:=0;
   SCurIdx:=0; SCurBlk:=0; SChg:=false;
   OCurIdx:=0; OCurBlk:=0; OChg:=false;
   FCurIdx:=0; FCurBlk:=0; FChg:=false
end;
procedure SwpInit;
begin
   swpidxinit;
   new(Ses);
   new(Ovr);
   if s_[4] then
      begin
         new(Fil);
         new(FBf)
      end
end;
procedure KillFil;
var pfl:tpfil;
    rr:word;
    f:file;
begin
   kill(newname('-'));
   assign(f,newname('$'));
   {$I-}
   reset(f,1);
   {$I+}
   if ioresult=0 then
      begin
         repeat
            blockread(f,pfl,TPFilS,rr);
            if rr=TPFilS then with pfl do
               kill(bdir+hex(AddrCrc32(fz,fnet,fnode,fpnt),8)+'.ST$')
         until rr<>TPFilS;
         close(f);
         erase(f)
      end
end;
procedure MemDone;
begin
   killfil;
   if s_[4] then
      begin
         dispose(Fil);
         dispose(FBf)
      end;
   dispose(Ovr);
   kill(newname('%'));
   dispose(Ses)
end;
function FilWrt(z,net,node,pnt:int;fnam:tfil;flush:boolean):boolean;
var f:file;
    ww,i:integer;
    q,dupe:boolean;
begin
   dupe:=false;
   if (FIdx>=FMax) or flush and not dupe then
      begin
         q:=false;
         for i:=0 to FIdx-1 do with FBf^[i] do
            begin
               assign(f,bdir+hex(AddrCrc32(fz,fnet,fnode,fpnt),8)+'.ST$');
               {$I-}
               reset(f,1);
               if ioresult<>0 then rewrite(f,1);
               {$I+}
               if ioresult=0 then
                  begin
                     seek(f,filesize(f));
                     blockwrite(f,FBf^[i],TFilS,ww);
                     close(f);
                     setfattr(f,hidden);
                     q:=q or (ww=TFilS)
                  end
            end;
         FIdx:=0;
         FilWrt:=q
      end;
   if not (dupe or flush) then
      with FBf^[FIdx] do
         begin
            fz:=z; fnet:=net; fnode:=node; fpnt:=pnt;
            name:=fnam.name; fstat:=fnam.fstat;
            btime:=fnam.btime; etime:=fnam.etime;
            size:=fnam.size; txsize:=fnam.txsize;
            inc(FIdx);
            FilWrt:=true
         end
end;
procedure WrtDone(arrtype:byte);
var newblk:int;
    fnam:tfil;
begin
   case arrtype of
      0: FlushArray(arrtype,RealArrayIdx(SCurIdx,SMaxIdx,NewBlk));
      1: FlushArray(arrtype,RealArrayIdx(OCurIdx,OMaxIdx,NewBlk));
      2: if s_[4] then
            begin
               FlushArray(arrtype,RealArrayIdx(FCurIdx,FMaxIdx,NewBlk));
               FilWrt(newblk,newblk,newblk,newblk,fnam,true)
            end
   end
end;
procedure FilIns(z,net,node,pnt:int;fnam:tfil);
var i,j:int;
    q,r:boolean;
    f:tpfil;
begin
   q:=false;
   r:=q;
   for i:=0 to FCurIdx-1 do
      begin
         Fil_(i,false,f);
         with f do
            begin
               q:=(fz=z) and (fnet=net) and (fnode=node) and (fpnt=pnt);
               r:=(fz>z) or ((fz=z) and (fnet>net)) or
                  ((fz=z) and (fnet=net) and (fnode>node)) or
                  ((fz=z) and (fnet=net) and (fnode=node) and (fpnt>pnt));
               if q or r then break
            end
      end;
   if not q then
      begin
         if r then for j:=FCurIdx downto i+1 do
            begin
               Fil_(j-1,false,f);
               Fil_(j,true,f)
            end
              else i:=FCurIdx;
         with f do
            begin
               fz:=z; fnet:=net; fnode:=node; fpnt:=pnt
            end;
         Fil_(i,true,f);
         inc(FCurIdx)
      end;
   FilWrt(z,net,node,pnt,fnam,false)
end;
{----------------------------------------------------------------------------}
procedure PInit(s:string);
begin
   write('[ ] '+s+':','%':5,#8#8#8#8);
   skp:=0
end;
procedure PDone(q:boolean);
var c:char;
begin
   if q then c:='๛' else c:='-';
   writeln(100,#13'['+c)
end;
procedure Percent(p1,p2:long;divider:byte);
begin
   if skp mod divider=0 then
      begin
         p2:=trunc((p1*ord(p2<>0))/(p2+ord(p2=0))*100);
         write(p2:3,#8#8#8)
      end;
   inc(skp);
   timeslice
end;
procedure FillKnown(s:string);
type lngbuf=array[0..24000] of byte;
var i,os:word;
    j,k,l:byte;
    lbuf:^lngbuf;
begin
   assign(lf,VSet^[1]);
   if resetlf(false) then
      begin
         dec(flsize,2);
         getmem(lbuf,flsize);
         blockread(lf,lbuf^,flsize);
         close(lf);
         filemode:=flmode;
         i:=0;
         os:=0;
         while os<flsize do
            begin
               s:='';
               repeat
                  k:=lbuf^[os];
                  inc(os);
                  if k<>0 then s:=s+lowcase(chr(k))
               until k=0;
               inc(i);
               for j:=7 to items do
                  if known_num[j]=i then
                     begin
                        if j in [7..15] then
                           begin
                              while (s[length(s)]<>' ') and (s<>'') do delete(s,length(s),1);
                              k:=length(s);
                              while (s[k]<>'%') do dec(k);
                              delete(s,1,k+1+ord(s[k+1]<>'s'))
                           end
                                        else
                           begin
                              k:=pos('%',s);
                              if k>0 then delete(s,k,length(s)-k+1)
                           end;
                        known^[j]:=s
                     end
            end;
         freemem(lbuf,flsize)
      end
end;
procedure InitAlias(name:string);
var al:text;
    s,s0,s1:string;
    i:byte;
begin
   aidx:=0;
   if name<>'' then
      begin
         assign(al,name);
         {$I-}
         reset(al);
         {$I+}
         if ioresult=0 then
            begin
               new(alias);
               while not eof(al) and (aidx<MaxAli) do
                  begin
                     readln(al,s);
                     i:=1;
                     inc(aidx);
                     with alias^[aidx] do
                        begin
                           s0:=readword(s,i,spc+[';']);
                           if (s0='') or (s0[1]=';') then dec(aidx)
                                                     else
                              begin
                                 if pos('/',s0)=0 then s0:='/'+s0;
                                 if pos(':',s0)=0 then s0:=strz(home.z,1)+':'+s0;
                                 if pos(':/',s0)<>0 then insert(strz(home.net,1),s0,pos(':/',s0)+1);
                                 if pos('/.',s0)<>0 then insert(strz(home.node,1),s0,pos('/.',s0)+1);
                                 decode_addr(s0,z,net,node,pnt,true);
                                 s1:=readword(s,i,[#0]);
                                 while (s1<>'') and (s1[length(s1)]=' ') do delete(s1,length(s1),1);
                                 while (s1<>'') and (s1[1]=' ') do delete(s1,1,1);
                                 salias:=s1;
                                 alias:=strcrc32(lower(s1))
                              end
                        end
                  end;
               close(al)
            end
                       else
            begin
               writeln('[?] ',lang^[Start_16]);
               wlog(2,lang^[Start_16])
            end
      end
end;
procedure MakeSes(var ss:tses);
var s,s0,s1,s2:string;
    i,j,k,em,g:byte;
    fnam:tfil;
    q,ring,call,fail,frq,brk,ok,dm,extmail,runbbs:boolean;
    h,m,sc,mi0,se0:word;
    temptime,prevtime,tcps,fromsize,absize:long;
    r:real;
procedure SomeCall(flag:boolean;var speed:long;var tt:long);
var j:byte;
    s2,s3:string;
begin
   j:=pos('connect',s)+8;
   if j=8 then j:=pos('carrier',s)+8;
   if j>8 then i:=j;
   j:=pos(':tx/',s)+4;
   if j>4 then i:=j;
   j:=pos('/tx:',s)+4;
   if j>4 then i:=j;
   s2:=readword(s,i,spc);
   if i<length(s) then
      if (s[i-1]=' ') and (s[i+1]>='0') and (s[i+1]<='9') then s2:=readword(s,i,spc);
   j:=1;
   if pos('tcp/ip',s2)>0 then speed:=1 else
   if pos('binkp',s2)>0 then speed:=2 else
      begin
         s1:=readword(s2,j,[#0..'/',':'..#255]); {speed}
         if s1='' then s1:='300';
         speed:=lval(s1);
      end;
   if flag then tt:=Str2Sec(s0)-ss.b_time
           else
      begin
         ss.b_time:=Str2Sec(s0);
         tt:=0
      end
end;
function Address(addr:string;var z,net,node,pnt:int;first:boolean):byte;
var z0,net0,node0,pnt0:int;
    i:byte;
begin
   i:=decode_addr(addr,z0,net0,node0,pnt0,true);
   if (i=0) and ((z=0) or first or ((z>0) and not InAddr(z,net,node,pnt,VSet^[8]))) then
      begin
         z:=z0; net:=net0; node:=node0; pnt:=pnt0
      end;
   address:=i
end;
begin
   ring:=false;
   call:=false;
   fail:=false;
   frq:=false;
   brk:=false;
   ok:=false;
   dm:=false;
   extmail:=false;
   runbbs:=false;
   em:=0;
   with ss do
      begin
         z:=0; net:=0; node:=0; pnt:=0;
         t_itraf:=0; t_otraf:=0;
         mincps:=65535; maxcps:=0;
         zyz:=''; mlr:='';
         speed:=0; status:=0; b_time:=0; e_time:=0; t_time:=0
      end;
   {G.P.Mail}
   radr:='';
   fts1:='';
   {--------}
   while readlogstrn(s0) do
      begin
         {$ifdef binkd}
         if length(s0)>24 then log_bnd:=s0[19]='[';
         if log_bnd then bnd2tml_put(s0) else
         {$endif}
         {$ifdef gpm}
         if length(s0)>24 then log_gpm:=(s0[19]='G') and (s0[20]='P') and (s0[21]='M');
         if log_gpm then s0:=gpm2tml(s0);
         {$endif}
         if (length(s0)>16) and (s0[1] in ['0'..'3']) then
            begin {Analysing}
               temptime:=Str2Sec(s0);
               s:=lower(copy(s0,16,length(s0)-15));
               if s[1] in ['1'..'9'] then with ss do
                     begin
                        if brk then
                           begin
                              z:=0;
                              brk:=false
                           end;
                        i:=1;
                        if address(readword(s,i,['@',',']),z,net,node,pnt,true)=0 then
                           begin
                              if s_[7] or s_[8] then
                                 begin
                                    i:=pos(known^[41],s0);
                                    if i>0 then
                                       begin
                                          inc(i,length(known^[41])+1);
                                          mlr:=twitinfo(readword(s0,i,[#0]))
                                       end
                                 end;
                              continue
                           end
                     end;
               if brk and (ss.z<=0) then
                  begin
                     sll:=s0;
                     break
                  end;
               for j:=1 to items do if not (j in [7..15]) and (known^[j]<>'') then
                  begin
                     if j in [38,43] then q:=pos(known^[j],s)>0
                                     else
                        begin
                           i:=length(known^[j]);
                           q:=(copy(s,1,i)=known^[j])
                        end;
                     if q then break
                  end;
               if ((ss.e_time-temptime)<15724800) and (temptime<ss.e_time) and (j<>29) then continue;
               prevtime:=ss.e_time;
               ss.e_time:=temptime;
               if q then with ss do
                  begin
                     inc(i);
                     if brk and (j<>21) then
                        begin
                           sll:=s0;
                           e_time:=prevtime;
                           break
                        end;
                     sll:='';
                     if ring and (j<>19) then
                        begin
                           ring:=false;
                           ss.b_time:=0
                        end;
                     if extmail and not (j in [32..34]) then
                        begin
                            if em>1 then
                               begin
                                  extmail:=false;
                                  em:=0
                               end
                                    else inc(em)
                        end;
                     case j of
                     1..6: begin {File transfer}
                              ok:=true;
                              frq:=false;
                              tcps:=-1;
                              s1:=readword(s,i,spc+[',']); {bits in CRC}
                              if s1='32' then status:=status or 512;
                              with fnam do
                                 begin
                                    if s[i-1]<>' ' then while s[i]<>' ' do inc(i);
                                    s2:=readword(s,i,spc); {name or "requesting" on janus}
                                    if pos(s2,known^[13+(j-1) div 2])=0 then
                                       begin
                                          name:=shortname(s2);
                                          s1:=readword(s,i,spc{$ifdef gpm}+[',']{$endif}); {size or "skipped"}
                                          fromsize:=0;
                                          size:=lval(s1);
                                          if size>=0 then
                                             begin
                                                s1:=readword(s,i,spc);
                                                if s1[1]='(' then
                                                   begin
                                                      fromsize:=lval(readword(s,i,[')']));
                                                      s1:=readword(s,i,spc)
                                                   end
                                                {$ifdef gpm}
                                                             else
                                                if (pos('skipped',s1)=1) or (pos('refused',s1)=1) then tcps:=0
                                                {$endif}
                                             end
                                                     else tcps:=0;
                                          k:=pos(known^[((j-1) div 2*2+7)+(j-1) mod 2],s); {aborted}
                                          fail:=k<>0;
                                          if fail then absize:=lval(readword(s,k,spc))
                                                  else absize:=size;
                                          if not fail then
                                             begin
                                                if (tcps=-1) and (s1='ok:') then
                                                   begin
                                                      {$ifdef dlc}
                                                      if fle and ((j-1) and 1=0) then {Counter ok and Sent}
                                                         begin
                                                            wlog(4,'last='+strz(lc,1)+' cur.='+strz(temptime,1)+' '+s2);
                                                            if (temptime>lc) then
                                                               begin
                                                                  g:=1;
                                                                  q:=false;
                                                                  while g<=length(VSet^[27]) do
                                                                     begin
                                                                        s1:=readword(VSet^[27],g,spc);
                                                                        q:=match(s1,name);
                                                                        if q then break
                                                                     end;
                                                                  if not q then
                                                                     begin
                                                                        writeln(fl,s2);
                                                                        lc:=temptime
                                                                     end
                                                               end
                                                         end;
                                                      {$endif}
                                                      mi0:=lval(readword(s,i,[':']));
                                                      se0:=lval(readword(s,i,[',']))+mi0*60;
                                                      tcps:=lval(readword(s,i,spc))
                                                   end
                                                            else se0:=1; {skipped}
                                                if size>=0 then txsize:=size-fromsize else txsize:=1;
                                                if tcps<=0 then txsize:=-txsize;
                                                if s_[4] then {File downloaded}
                                                   begin
                                                      fstat:=(j-1) and 1;
                                                      btime:=temptime-se0;
                                                      etime:=temptime;
                                                      if intime(b_time,e_time,time0) then
                                                         FilIns(z,net,node,pnt,fnam)
                                                   end;
                                                if (txsize>0) and (tcps>0) then
                                                   begin
                                                      if mincps>tcps then mincps:=tcps;
                                                      if maxcps<tcps then maxcps:=tcps
                                                   end
                                             end
                                       end
                                                                          else fail:=false
                                 end
                           end;
                     16,17,39: begin {Polling/Calling/Trying}
                                  if (z or net or node or pnt<>0) then
                                     begin
                                        fail:=true;
                                        break
                                     end;
                                  address(readword(s,i,['@',',']),z,net,node,pnt,false);
                                  b_time:=Str2Sec(s0);
                                  speed:=0;
                                  if pos(': ',s)=0 then dm:=true
                                                   else
                                  begin
                                     i:=length(s);
                                     while (s[i]<>':') and (i>20) do dec(i);
                                     k:=i; inc(i);
                                     while (s[k]<>' ') and (k>20) do dec(k);
                                     call:=(lval(readword(s,k,spc+[':','/']))<>-1);
                                     t_time:=lval(readword(s,i,spc));
                                     if t_time<0 then t_time:=0;
                                     if t_time>200 then t_time:=120;
                                     if not call then
                                        begin
                                           e_time:=b_time+t_time;
                                           fail:=true;
                                           break
                                        end
                                  end
                               end;
                     18: begin {Ring detected}
                            b_time:=Str2Sec(s0);
                            z:=0; net:=0; node:=0; pnt:=0;
                            speed:=0;
                            ring:=true
                         end;
                     19,20: begin {Incoming/Outgoing calls}
                               if brk then break;
                               if j=19 then
                                  begin
                                     z:=0; net:=0; node:=0; pnt:=0;
                                     SomeCall(ring,speed,t_time);
                                     ring:=false;
                                     status:=status or $100
                                  end
                                       else SomeCall(call,speed,t_time)
                            end;
                     21: begin {Session result}
                            if s[i+1] in ['1'..'9'] then
                               begin
                                  address(readword(s,i,[',']),z,net,node,pnt,false);
                                  s1:=readword(s,i,spc);
                                  t_itraf:=lval(readword(s,i,spc+['/']));
                                  if t_itraf<0 then t_itraf:=0;
                                  t_otraf:=lval(readword(s,i,[',']));
                                  if t_otraf<0 then t_otraf:=0;
                                  s1:=readword(s,i,spc);
                                  Str2Time('0'+readword(s,i,spc),h,m,sc);
                                  t_time:=sc+60*(m+60*h);
                                  break {Session over}
                               end
                         end;
                     22,23: begin {Handshake failure}
                                fail:=true;
                                brk:=true
                            end;
                     24: begin {Handshake: EMSI/YooHoo, protocol:}
                            s1:=readword(s,i,spc+[',']);
                            if s1='emsi' then status:=status or 8;
                            s1:=readword(s,i,spc);
                            s1:=readword(s,i,spc+[',']);
                            if s1='binkp' then status:=status or 2048 else
                            if s1='xmodem' then status:=status or 112 else
                            if s1='zmodem' then status:=status or 16 else
                            if s1='zedzap' then status:=status or 32 else
                            if s1='dirzap' then status:=status or 48 else
                            if s1='janus' then status:=status or 64 else
                            if pos('hydra',s1)<>0 then
                               begin
                                  if pos('/hdx',s1)<>0 then status:=status or 96
                                                       else status:=status or 80
                               end
                         end;
                     25: status:=status or 2; {Password error}
                     26: status:=status or 1; {Password protected}
                     27: status:=status or $80; {Unlisted node}
                     28: begin {Human caller}
                            z:=-2;
                            {$ifdef gpm}
                            if log_gpm then runbbs:=true
                            {$endif}
                         end;
                     29: {System clock synchronized}
                         b_time:=e_time-(prevtime-b_time);
                     30,31: begin {Running}
                               frq:=(pos('.req',s)>0) or (pos('.rq',s)>0);
                               if not frq and (z<=0) then
                                  begin
                                     if (b_time=0) then b_time:=Str2Sec(s0);
                                     if z=-2 then
                                        begin
                                           if e_time-prevtime<3 then runbbs:=true
                                                                else
                                              begin
                                                 e_time:=prevtime;
                                                 sll:=s0;
                                                 brk:=true
                                              end
                                        end
                                             else
                                     if z<>-3 then z:=-1
                                  end
                            end;
                     32: begin {Exiting from T-Mail}
                            fail:=z<>0;
                            break
                         end;
                     33..34: begin
                                if b_time=0 then b_time:=e_time;
                                if (j=33) and frq then {Returned to T-Mail}
                                   begin
                                      status:=status or 1024;
                                      frq:=false
                                   end
                                                  else
                                if (j=33) and (z=-2) and not runbbs then runbbs:=true else
                                if extmail then break else
                                if z<=0 then brk:=true
                             end;
                     35: begin {Terminal emulator}
                            b_time:=Str2Sec(s0);
                            speed:=0;
                            z:=-3;
                            call:=true
                         end;
                     37: if dm then {-DM option}
                            begin
                               s1:=copy(s,i,length(s)-i+1);
                               if (pos('busy',s1)=1) or (pos('no ',s1)=1) then
                                  begin
                                     fail:=true;
                                     break
                                  end
                                                                           else
                               if (pos('connect',s1)>0) or (pos('carrier',s1)>0) then
                                  begin
                                     call:=true;
                                     dm:=false
                                  end
                            end;
                     38: begin
                            e_time:=b_time;
                            fail:=true;
                            break
                         end;
                     40: begin
                            extmail:=true;
                            z:=-1
                         end;
                     41: {nothing};
                     42: if s_[7] then
                         begin
                            inc(i,16);
                            zyz:=twitinfo(readword(s0,i,[#0]))
                         end;
                     43: break;
                     end
                  end
            end
      end;
   if ss.b_time=0 then ss.b_time:=ss.e_time;
   if (ss.e_time-ss.b_time-ss.t_time)>120 then ss.t_time:=ss.e_time-ss.b_time;
   if not fail then ss.status:=ss.status or 4
end;
procedure CountStat;
var ses:tses;
    ina,err:boolean;
    i:wrd;
    fil:tfil;
    s:string;
begin
   _nodes:=0;
   skp:=0;
   pinit(lang^[Count_Stat_1]);
   while fptr<>-1 do
      begin
         MakeSes(ses);
         percent(fptr,flsize,250);
         with ses do
         if (e_time-b_time<>0) or (z<>0) then
            begin
               err:=(z=0) and (net=0) and (node=0) and (pnt=0);
               ina:=inaddr(z,net,node,pnt,VSet^[8]) or err or (z<0) or not g_fake;
               if loglevel>3 then
                  begin
                     if ina then s:=' ' else s:='-';
                     s:='Ses '+strz(scuridx,5)+' ('+dt2str(b_time)+' - '+dt2str(e_time)+')'+s+
                        code_addr(z,net,node,pnt,true,false);
                     wlog(4,s)
                  end;
               if intime(b_time,e_time,time0) and ina then
                  begin
                     Ses_(SCurIdx,true,ses);
                     inc(SCurIdx)
                  end;
               inc(_nodes)
            end
      end;
   wrtdone(0); {All to the SWAP}
   if s_[4] then wrtdone(2);
   pdone(true);
   swpptr:=0
end;
procedure ReadInit;
var i,j:int;
    c:char;
begin
   for i:=0 to maxp do
      for j:=1 to maxevt do busytime[i,j]:=0
end;
procedure OvrPos(ses:tses;var k:integer);
var i,j:int;
    q,r:boolean;
    ovr:tovr;
    sort:byte; {0 - address, 1 - cps}
begin
   q:=false;
   r:=q;
   for i:=0 to OCurIdx-1 do
      begin
         Ovr_(i,false,ovr);
         with ses do with ovr do
            begin
               if z<=0 then
                  begin
                     if net>0 then net:=0;
                     if node>0 then node:=0;
                     if pnt>0 then pnt:=0
                  end;
               q:=(oz=z) and (onet=net) and (onode=node) and (opnt=pnt);
               r:=(oz>z) or ((oz=z) and (onet>net)) or
                 ((oz=z) and (onet=net) and (onode>node)) or
                 ((oz=z) and (onet=net) and (onode=node) and (opnt>pnt));
               if q or r then break
            end
      end;
   if not q then
      begin
         if r then for j:=OCurIdx downto i+1 do
            begin
               Ovr_(j-1,false,ovr);
               Ovr_(j,true,ovr)
            end
              else i:=OCurIdx;
         with ses do with ovr do
            begin
               wlog(4,'Making '+code_addr(z,net,node,pnt,false,false)+' at pos '+strz(i,1));
               oz:=z; onet:=net; onode:=node; opnt:=pnt;
               sessions:=0; incalls:=0; outcalls:=0; online:=0; okonline:=0;
               rcvd:=0; sent:=0; maxcps:=0; mincps:=65535;
               ozyz:=''; omlr:=''
            end;
         Ovr_(i,true,Ovr);
         inc(OCurIdx)
      end;
   k:=i
end;
function Delta2Str(t:long):string;
var s,s0:string;
    j,k:byte;
    dol:int;
begin
   s:=dt2str(t);
   k:=lval(copy(s,4,2));
   dol:=lval(copy(s,1,2))-1;
   for j:=2 to k do dol:=dol+days[k];
   if dol>0 then s0:=strz(dol,1)+'/' else s0:='';
   while length(s0)<3 do s0:=' '+s0;
   if s[7]='0' then s[7]:=' ';
   Delta2Str:=s0+copy(s,7,8)
end;
function okcps(cps:long):string;
var i:byte;
    s:string[2];
begin
   if (cps=0) or (cps=65535) then okcps:='   -' else
      begin
         i:=0;
         if cps>9999 then
            begin
               cps:=cps div 1024;
               i:=1
            end;
         while (cps>999) and (i>0) do
            begin
               cps:=cps div 1024;
               inc(i);
            end;
         case i of
            0: s:='';
            1: s:='K';
            2: s:='M';
            3: s:='G'
         end;
         okcps:=right(strz(cps,1)+s,4)
      end
end;
procedure pmaxcps(cps:wrd;z,net,node,pnt:int;var table:pcps;var idx:byte);
var i,j,k:byte;
begin
   if idx<=cpstbl then
      begin {New}
         table[idx].cps:=0;
         inc(idx)
      end;
   k:=idx-1;
   for i:=0 to k do
      if (table[i].cps<cps) then {Shift}
         begin
            if i<k then
               for j:=k downto i+1 do
                  table[j]:=table[j-1];
            with table[i] do
               begin
                  cz:=z; cnet:=net;
                  cnode:=node; cpnt:=pnt
               end;
            table[i].cps:=cps;
            break
         end
end;

procedure pmincps(cps:wrd;z,net,node,pnt:int;var table:pcps;var idx:byte);
var i,j,k:byte;
begin
   if idx<=cpstbl then
      begin {New}
         table[idx].cps:=65535;
         inc(idx)
      end;
   k:=idx-1;
   for i:=0 to k do
      if (table[i].cps>cps) then {Shift}
         begin
            if i<k then
               for j:=k downto i+1 do
                  table[j]:=table[j-1];
            with table[i] do
               begin
                  cz:=z; cnet:=net;
                  cnode:=node; cpnt:=pnt
               end;
            table[i].cps:=cps;
            break
         end
end;
{ Mode: 00 - constant
        01 - help
        02 - online variable
}
function MacroLngWord(s:string;mode:byte;var p:byte):string;
const mkw=8;
      macros:array[1..mkw] of string[7]=
     ('filerun','key','spc','pid','longpid','date','uptime','os');
var i,j,k:byte;
    par:long;
    c:string[1];
    q:boolean;
begin
   c:='';
   j:=p+1;
   while not (s[j] in [' ',#9,'@',')']) and (j<length(s)) do inc(j);
   s:=lower(copy(s,p+1,j-p+1));
   q:=false;
   for i:=1 to mkw do
      begin
         q:=pos(macros[i],s)=1;
         if q then break
      end;
   if not q or ((i in [2,3]) and (mode<>1)) or ((i in [6]) and (mode<>2)) then MacroLngWord:='@' else
      begin
         j:=length(macros[i])+1;
         if s[j]='(' then
            begin
               k:=j;
               while not (s[k] in [')','@']) and (k<length(s)) do inc(k);
               par:=lval(copy(s,j+1,k-j-1));
               inc(p,k)
            end
                     else
            begin
               inc(p,j-1);
               par:=-1
            end;
         case i of {Definitions}
            1: MacroLngWord:=shortname(paramstr(0));
            2: begin
                  {$ifndef ver70}
                  waitsec(1);
                  {$else}
                  writeln;
                  if par>60 then par:=60;
                  waitorkey(par);
                  {$endif}
                  MacroLngWord:=#13
               end;
            3: begin
                  if par<=0 then par:=1;
                  s:='';
                  for k:=1 to par do s:=s+' ';
                  MacroLngWord:=s
               end;
            4: MacroLngWord:=pid+c;
            5: MacroLngWord:=vialine+c;
            6: MacroLngWord:=cd0+' - '+cd1;
            7: MacroLngWord:=supUptime(lang^[Macro_1]);
            8: MacroLngWord:=supOSver;
         end
      end
end;
function ExpandStr(s:string;mode:byte):string;
var s1:string;
    i:byte;
begin
   s1:='';
   for i:=1 to length(s) do
      if s[i]<>'@' then s1:=s1+s[i]
                   else s1:=s1+macrolngword(s,mode,i);
   ExpandStr:=s1
end;
procedure total;
label 1;
var txt,tpl:text;
    tmpbin:file;
    s,s0,s1,cd,bd:string;
    c:char;
    dbtm,tm,tm0,tm1,tm2,dtm,t_traf,sptr:long;
    ss:tses;
    fil:tfil;
    i,j,k,m,w:integer;
    bt:byte;
    cps:word;
    err,ina,q,body:boolean;
    dt:datetime;
    ovr:tovr;
begin
   assign(txt,newname('t'));
   if not s_[1] then goto 1;
   assign(tpl,tplname('t'));
   {$I-}
   reset(tpl);
   {$I+}
   if ioresult<>0 then
      begin
         writeln('[?] Can''t read '+tplname('t'));
         wlog(1,'Can''t read '+tplname('t'));
         halt(2)
      end;
   rewrite(txt);
   cd:='';
   bd:='';
   readinit;
   tltm:=0; otm:=0; itm:=0; ctm:=0; skp:=0; etm:=0; ertm:=0; htm:=0;
   no_ev:=true;
   pinit(lang^[Total_28]);
   tplmod:=_none; curtpl:=_none; body:=false;
   while tplmod<>_end do
      begin
         q:=TplGet(tpl,s1);
         case tplmod of
            _body_div: bd:=s1;
            _body:
               if not body then
               begin
               body:=true;
               for sptr:=0 to scuridx-1 do
                  begin
                     Ses_(sptr,false,ss);
                     with ss do
                        begin
                           if sptr=0 then no_ev:=false;
                           percent(sptr,scuridx,250);
                           err:=(z=0) and (net=0) and (node=0) and (pnt=0);
                           ina:=inaddr(z,net,node,pnt,VSet^[8]) or err or ((z<0) and not t_hid_ext);
                           if ina or not g_fake then
                           begin
                              {Date/time operations}
                              if intime(b_time,e_time,time0) then
                                 begin
                                    tm0:=e_time;
                                    tm:=tm0-b_time;
                                    if tltm=0 then tltm:=b_time;
                                    {Graph table}
                                    sec2dt(b_time,dt);
                                    m:=60 div parts;
                                    j:=dt.hour*parts+dt.min div m;
                                    dt.hour:=(j+1) div parts;
                                    dt.min:=(j+1) mod parts*m;
                                    dt.sec:=0;
                                    tm1:=dtm2sec(dt);
                                    if e_time<=tm1 then tm1:=tm
                                                   else tm1:=tm1-b_time;
                                    sec2dt(e_time,dt);
                                    k:=dt.hour*parts+dt.min div m;
                                    dt.hour:=k div parts;
                                    dt.min:=k mod parts*m;
                                    dt.sec:=0;
                                    tm2:=e_time-dtm2sec(dt);
                                    t_traf:=t_itraf+t_otraf;
                                    if (z=-1) or (z=-3) then
                                       begin
                                          bt:=4;
                                          inc(etm,tm)
                                       end
                                                        else
                                    if z=-2 then
                                       begin
                                          bt:=5;
                                          inc(htm,tm)
                                       end
                                            else
                                    if err then
                                       begin
                                          bt:=maxevt;
                                          inc(ertm,tm)
                                       end
                                           else
                                    if (speed=0) and (t_traf=0) then
                                       begin
                                          bt:=3;
                                          inc(ctm,tm)
                                       end
                                                                else
                                    if status and 256=0 then
                                       begin
                                          bt:=1;
                                          inc(otm,tm)
                                       end
                                                        else
                                       begin
                                          bt:=2;
                                          inc(itm,tm)
                                       end;
                                    dbtm:=tm1;
                                    inc(busytime[j,bt],tm1);
                                    if j<k then
                                       begin
                                          inc(busytime[k,bt],tm2);
                                          inc(dbtm,tm2)
                                       end;
                                    if k<j then
                                       begin
                                          for i:=j+1 to 24*parts-1 do
                                             begin
                                                inc(busytime[i,bt],m*60);
                                                inc(dbtm,m*60)
                                             end;
                                          j:=-1
                                       end;
                                    for i:=j+1 to k-1 do
                                       begin
                                          inc(busytime[i,bt],m*60);
                                          inc(dbtm,m*60)
                                       end;
                                    if ina or err then
                                       begin
                                          if t_hid_ext and (z<0) then continue; {no externals}
                                          ovrpos(ss,w);
                                          ovr_(w,false,ovr);
                                          if s_[7] then if zyz<>'' then ovr.ozyz:=zyz;
                                          if s_[7] or s_[8] then if mlr<>'' then ovr.omlr:=mlr;
                                          if ovr.mincps>mincps then ovr.mincps:=mincps;
                                          if ovr.maxcps<maxcps then ovr.maxcps:=maxcps;
                                          if status and 256=0 then inc(ovr.outcalls)
                                                              else inc(ovr.incalls);
                                          if fcps then cpsdiv:=t_time else cpsdiv:=tm;
                                          if (speed<>0) or (z<=0) then with ovr do
                                             begin
                                                if z>0 then
                                                   begin
                                                      sent:=sent+t_otraf;
                                                      rcvd:=rcvd+t_itraf;
                                                      inc(okonline,cpsdiv)
                                                   end;
                                                inc(sessions,16);
                                                sessions:=sessions or (status and 7) or ((status shr 7) and 8);
                                                inc(online,tm)
                                             end;
                                          ovr_(w,true,ovr);
                                          if t_hid_det and (err or ((t_traf=0) and (speed=0))) then continue;
                                          cps:=t_traf div (cpsdiv+ord(cpsdiv=0));
                                          s:=dt2str(b_time);
                                          if cd<>copy(s,1,5) then
                                             begin
                                                if cd='' then cd0:=s;
                                                cd:=copy(s,1,5);
                                                MacPut('Date',s);
                                                writeln(txt,tplmacro(bd))
                                             end;
                                          MacPut('BTime',copy(dt2str(b_time),7,8));
                                          MacPut('ETime',copy(dt2str(e_time),7,8));
                                          if status and 128=0 then c:=' ' else c:='U';
                                          MacPut('IsListed',c);
                                          if status and 1=0 then c:=' ' else c:='*';
                                          if status and 2=2 then c:='?';
                                          if t_hid_pwd then c:='*';
                                          MacPut('IsProtected',c);
                                          if status and 256=0 then c:='o' else c:='i';
                                          MacPut('Direction',c);
                                          if z>0 then
                                             case status div 16 and $87 of
                                                0: c:='-';
                                                1: c:='z';
                                                2: c:='Z';
                                                3: c:='D';
                                                4: c:='J';
                                                5: c:='H';
                                                6: c:='h';
                                                7: c:='X';
                                                $80: c:='B'
                                             end
                                                               else c:=' ';
                                          MacPut('Protocol',c);
                                          if status and 1024=0 then c:=' ' else c:='f';
                                          MacPut('IsExtFreq',c);
                                          if status and 4=0 then c:='' else c:='๚';
                                          MacPut('IsSuccess',c);
                                          MacPut('Address',code_addr(z,net,node,pnt,false,true));
                                          MacPut('Online',copy(delta2str(tm),4,8));
                                          if z>0 then
                                             begin
                                                MacPut('Received',dec2str(t_itraf,0));
                                                MacPut('Sent',dec2str(t_otraf,0));
                                                MacPut('CPS',okcps(cps))
                                             end
                                                            else
                                             begin
                                                MacPut('Received','');
                                                MacPut('Sent','');
                                                MacPut('CPS','    ')
                                             end;
                                          case speed of
                                            -1: s:='??? ';
                                             0: s:='n/a ';
                                             1: s:='tcpip';
                                             2: s:='binkp';
                                          else s:=strz(speed,1);
                                          end;
                                          MacPut('Speed',s);
                                          if s1<>'' then writeln(txt,tplmacro(s1))
                                       end
                                 end
                           end
                        end
                  end
               end;
            _print: writeln(txt,tplmacro(s1));
         else {nothing};
         end
      end;
   close(tpl);
   close(txt);
   tltm:=tm0-tltm;
   if tltm<0 then inc(tltm,31622400);
   cd1:=dt2str(tm0);
   wrtdone(1);
1:
   for i:=1 to nrkw+rkw do VSet^[i]:=expandstr(VSet^[i],2);
   pdone(not no_ev);
   if no_ev then
      begin
         inc(mtsk);
         erase(txt)
      end
end;

procedure overall;
var txt,tpl:text;
    s,s0:string;
    q,body:boolean;
    c,l:char;
    b:byte;
    i,j,m,sss:word;
    oclls,iclls,sess,cps,k,micps,macps,cpsol:long;
    trcd,tsnt:comp;
    ovr:tovr;
begin
   assign(txt,newname('a'));
   if not s_[1] or not s_[2] then exit;
   if no_ev then
      begin
         kill(newname('a'));
         exit
      end;
   assign(tpl,tplname('a'));
   {$I-}
   reset(tpl);
   {$I+}
   if ioresult<>0 then
      begin
         writeln('[?] Can''t read '+tplname('a'));
         wlog(1,'Can''t read '+tplname('a'));
         halt(2)
      end;
   rewrite(txt);
   MacPut('Date','('+cd0+' - '+cd1+')');
   iclls:=0; oclls:=0; sess:=0; oltm:=0; trcd:=0; tsnt:=0; cpsol:=0; micps:=65535; macps:=0; m:=0; cps_max:=0;
   smax:=0; smin:=0; amax:=0; amin:=0;
   tplmod:=_none; curtpl:=_none; body:=false;
   while tplmod<>_end do
      begin
         q:=TplGet(tpl,s0);
         case tplmod of
            _body:
               if not body then
               begin
                  body:=true;
                  for k:=0 to ocuridx-1 do
                     begin
                        Ovr_(k,false,ovr);
                        with ovr do if inaddr(oz,onet,onode,opnt,VSet^[8]) or
                                       ((oz=0) and (onet=0) and (onode=0) and (opnt=0)) or (oz<0) then
                           begin
                              cps:=round(rcvd+sent) div (okonline+ord(okonline=0));
                              {CPS tables}
                              if (oz>0) and (rcvd+sent>0) then
                                 begin
                                    if cps>0 then
                                       begin
                                          pmaxcps(cps,oz,onet,onode,opnt,smaxcps,smax);
                                          pmincps(cps,oz,onet,onode,opnt,smincps,smin)
                                       end;
                                    if maxcps>0 then pmaxcps(maxcps,oz,onet,onode,opnt,amaxcps,amax);
                                    if mincps<>65535 then pmincps(mincps,oz,onet,onode,opnt,amincps,amin)
                                 end;
                              {----------}
                              if sessions and 1=1 then c:='*' else c:=' ';
                              if sessions and 2=2 then c:='?';
                              if oz=0 then c:=' ';
                              if s_hid_pwd then c:='*';
                              if online=0 then l:=' ' else
                              if sessions and 4=4 then l:='๚' else l:='';
                              sss:=sessions div 16;
                              if not ((s_hid_fai and (oz=0)) or (s_hid_ext and (oz<0))) then
                                 begin
                                    if oz>0 then with ocps[cps_max] do
                                       begin
                                          cz:=oz; cnet:=onet; cnode:=onode; cpnt:=opnt;
                                          ccps[0]:=cps; ccps[1]:=maxcps; ccps[2]:=mincps;
                                          if ccps[0] or ccps[1] or not ccps[2]>0 then inc(cps_max)
                                       end;
                                    inc(m);
                                    MacPut('IsProtected',c);
                                    MacPut('IsSuccess',l);
                                    MacPut('InCalls',strz(incalls,1));
                                    MacPut('OutCalls',strz(outcalls,1));
                                    MacPut('Sessions',strz(sss,1));
                                    MacPut('Address',code_addr(oz,onet,onode,opnt,false,true));
                                    if online>0 then s:=delta2str(online)
                                                else s:='-------';
                                    MacPut('Online',s);
                                    if (oz>0) and (online>0) then
                                       begin
                                          MacPut('MinCPS',okcps(mincps));
                                          MacPut('MaxCPS',okcps(maxcps));
                                          MacPut('AvgCPS',okcps(cps));
                                          MacPut('Received',dec2str(rcvd,0));
                                          MacPut('Sent',dec2str(sent,0))
                                       end
                                                             else
                                       begin
                                          MacPut('MinCPS','    ');
                                          MacPut('MaxCPS','    ');
                                          MacPut('AvgCPS','    ');
                                          MacPut('Received','');
                                          MacPut('Sent','')
                                       end;
                                    if s0<>'' then writeln(txt,tplmacro(s0));
                                    if micps>mincps then micps:=mincps;
                                    if macps<maxcps then macps:=maxcps;
                                    inc(sess,sss); inc(oclls,outcalls); inc(iclls,incalls);
                                    inc(oltm,online); inc(cpsol,okonline); trcd:=trcd+rcvd; tsnt:=tsnt+sent
                                 end
                           end
                     end;
                  MacPut('TInCalls',strz(iclls,1));
                  MacPut('TOutCalls',strz(oclls,1));
                  MacPut('TSessions',strz(sess,1));
                  MacPut('TStations',strz(m,1));
                  if oltm>0 then s:=delta2str(oltm)
                            else s:='-------';
                  MacPut('TOnline',s);
                  MacPut('TReceived',dec2str(trcd,0));
                  MacPut('TSent',dec2str(tsnt,0));
                  if micps=65535 then s:='   -' else s:=okcps(micps);
                  MacPut('TMinCPS',s);
                  if macps=0 then s:='   -' else s:=okcps(macps);
                  MacPut('TMaxCPS',s);
                  MacPut('TAvgCPS',okcps(round((trcd+tsnt)/(cpsol+ord(cpsol=0)))))
               end;
            _print: writeln(txt,tplmacro(s0));
         else {nothing};
         end
      end;
   dec(cps_max);
   close(tpl);
   close(txt)
end;

procedure Filelist;
var txt,tpl:text;
    f:file;
    fl:tpfil;
    fnam:tfil;
    s,s0,s1,s2,cdq,adr,scps,bd:string;
    k:long;
    netsize,arcsize,ticsize,filsize,nettime,arctime,tictime,filtime,dltime:long;
    c:char;
    dtm:long;
    was,ina,q,body:boolean;
procedure MP(time,size:long;s:string);
begin
   if size<>0 then
      begin
         MacPut('BTime','');
         MacPut('ETime','');
         MacPut('Dash',' ');
         MacPut('Direction',' ');
         MacPut('Online',copy(delta2str(time),4,8));
         MacPut('Name',center(s,12));
         MacPut('Size',strzna(size,1));
         MacPut('CPS',okcps(size div (time+ord(time=0))));
         writeln(txt,tplmacro(s2));
         MacPut('OneAddress','')
      end
end;
procedure HiddenFiles;
begin
   if hid_net then netsize:=0;
   if hid_arc then arcsize:=0;
   if hid_fil then filsize:=0;
   if hid_tic then ticsize:=0;
   if netsize+arcsize+filsize+ticsize<>0 then
   begin {Hidden mail counter}
      if was then MacPut('OneAddress','') else
         begin
            if not was then
               writeln(txt,tplmacro(bd));
            MacPut('OneAddress',adr)
         end;
      MP(nettime,netsize,lang^[FileList_10]);
      MP(arctime,arcsize,lang^[FileList_11]);
      MP(tictime,ticsize,lang^[FileList_12]);
      MP(filtime,filsize,lang^[FileList_13])
   end
end;
begin
   assign(txt,newname('f'));
   if not (s_[1] and s_[4]) then exit;
   if no_ev then
      begin
         kill(newname('f'));
         exit
      end;
   assign(tpl,tplname('f'));
   {$I-}
   reset(tpl);
   {$I+}
   if ioresult<>0 then
      begin
         writeln('[?] Can''t read '+tplname('f'));
         wlog(1,'Can''t read '+tplname('f'));
         halt(2)
      end;
   rewrite(txt);
   pinit(lang^[FileList_8]);
   netsize:=0; arcsize:=0; ticsize:=0; filsize:=0;
   nettime:=0; arctime:=0; tictime:=0; filtime:=0;
   s1:=VSet^[18];
   if s1[1] in NoChr then delete(s1,1,1);
   MacPut('Date','('+cd0+' - '+cd1+')');
   bd:=''; tplmod:=_none; curtpl:=_none;
   body:=false;
   while tplmod<>_end do
      begin
         q:=TplGet(tpl,s2);
         case tplmod of
            _body_div: bd:=s2;
            _body:
               if not body and (fcuridx>0) then
                  begin
                  body:=true;
                  for k:=0 to fcuridx-1 do
                     begin
                        cdq:='';
                        MacPut('Date','');
                        Fil_(k,false,fl);
                        percent(k,fcuridx,10);
                        with fl do
                           begin
                              ina:=inaddr(fz,fnet,fnode,fpnt,VSet^[8]);
                              adr:=code_addr(fz,fnet,fnode,fpnt,false,true);
                              MacPut('Address',adr);
                              assign(f,bdir+hex(AddrCrc32(fz,fnet,fnode,fpnt),8)+'.ST$')
                           end;
                        {$I-}
                        reset(f,1);
                        {$I+}
                        if ioresult=0 then
                           begin
                              while not eof(f) and ina do
                                 begin
                                    blockread(f,fnam,TFilS);
                                    with fnam do
                                       begin
                                          dtm:=etime-btime;
                                          dltime:=dtm;
                                          s:=copy(dt2str(btime),1,5); {new time}
                                          if cdq<>s then
                                             begin
                                                if cdq<>'' then hiddenfiles;
                                                cdq:=s;
                                                MacPut('Date',cdq);
                                                netsize:=0; arcsize:=0; ticsize:=0; filsize:=0;
                                                nettime:=0; arctime:=0; tictime:=0; filtime:=0;
                                                was:=false
                                             end;
                                          if hide_n and (match('*.pk?',name) or
                                                         match('*.?ut',name) or
                                                         match('*.xma',name)) then {NetMail}
                                             begin
                                                if size>=0 then inc(netsize,size);
                                                inc(nettime,dltime)
                                             end
                                                                                      else
                                          if hide_t and match('*.tic',name) then
                                             begin
                                                if size>=0 then inc(ticsize,size);
                                                inc(tictime,dltime)
                                             end
                                                                            else
                                          if hide_a and ( {ArcMail}
                                          match('*.mo?',name) or match('*.tu?',name) or match('*.we?',name) or
                                          match('*.th?',name) or match('*.fr?',name) or match('*.sa?',name) or
                                          match('*.su?',name)) then
                                             begin
                                                if size>=0 then inc(arcsize,size);
                                                inc(arctime,dltime)
                                             end
                                                               else
                                          if hide_f or not (match(s1,name) xor (VSet^[18][1] in NoChr)) or
                                             match('*.req',name) then
                                             begin
                                                if size>=0 then inc(filsize,size);
                                                inc(filtime,dltime)
                                             end
                                                                          else
                                          if not (hid_skp and (txsize<0)) then
                                             begin {Other files}
                                                if not was then writeln(txt,tplmacro(bd));
                                                if fstat and 1=1 then c:='i' else c:='o';
                                                if txsize<0 then scps:=left(lang^[FileList_9],4)
                                                            else scps:=okcps(txsize div (dtm+ord(dtm=0)));
                                                if was then MacPut('OneAddress','')
                                                       else MacPut('OneAddress',adr);
                                                MacPut('BTime',copy(dt2str(btime),7,8));
                                                MacPut('ETime',copy(dt2str(etime),7,8));
                                                MacPut('Dash','-');
                                                MacPut('Online',copy(delta2str(dtm),4,8));
                                                MacPut('Direction',c);
                                                MacPut('Name',name);
                                                MacPut('Size',strzna(size,1));
                                                MacPut('CPS',scps);
                                                writeln(txt,tplmacro(s2));
                                                was:=true
                                             end;
                                          timeslice
                                       end
                                 end;
                              close(f);
                              {$I-}
                              erase(f);
                              {$I+}
                              if ioresult<>0 then wlog(1,'Can''t erase filelist for '+adr);
                              if ina then hiddenfiles
                                     else
                                 begin
                                    netsize:=0; arcsize:=0; ticsize:=0; filsize:=0;
                                    nettime:=0; arctime:=0; tictime:=0; filtime:=0;
                                    was:=false
                                 end
                           end
                     end
                  end;
            _print: writeln(txt,tplmacro(s2));
         else {nothing};
         end
      end;
   close(tpl);
   close(txt);
   pdone(fcuridx>0)
end;

procedure GraphLog;
const maxt=7;
var txt:text;
    s,s1,s2:string;
    c:char;
    i,j,k,m,t,n,w,shift,z:byte;
    days:int;
    tmp:wrd;
    btm:long;
    q:boolean;
    times:array[0..maxt] of string[10];
function l(i:byte):long;
begin
   case i of
      0: l:=tltm;
      1: l:=oltm;
      2: l:=ctm;
      3: l:=itm;
      4: l:=otm;
      5: l:=etm;
      6: l:=htm;
      7: l:=ertm
   end
end;
begin
   assign(txt,newname('g'));
   if not (s_[1] and s_[3]) then exit;
   if no_ev then
      begin
         kill(newname('g'));
         exit
      end;
   for i:=0 to maxt do
      if i<2 then times[i]:=center(lang^[GraphLog_1+i],10)
             else times[i]:=left(lang^[GraphLog_1+i+ord(i>7)],10);
   n:=length(VSet^[24]);
   if n>6 then n:=6;
   for i:=1 to n do times[i+1][1]:=VSet^[24][i];
   rewrite(txt);
   z:=24*parts;
   w:=z+6;
   oltm:=ctm+otm+itm+etm+ertm+htm;
   days:=round(tltm/long(86400)+0.3);
   if days<1 then days:=1;
   if mline then
      begin
         if mg=tasks then dec(mg);
         days:=days*int(tasks-mg);
         tltm:=tltm*long(tasks-mg)
      end;
   n:=parts*10;
   t:=(parts-1);
   k:=10*t+ord(t=1)*6;
   if mline and (tasks>1) then
      begin
         s1:=' ('+strz(tasks-mg,1)+' '+lang^[GraphLog_10]+')';
         if (s1[length(s1)-1]='จ') and (tasks>4) then s1[length(s1)-1]:='ฉ'
      end
            else s1:='';
   {Added at 0.32/Alpha-6 - suggested by Igor Vanin}
   shift:=lval(t0[1]+t0[2])*parts; {sections}
   for j:=1 to z-shift do
      for m:=1 to maxevt do
         begin
            tmp:=busytime[z-1,m];
            for i:=z-1 downto 1 do busytime[i,m]:=busytime[i-1,m];
            busytime[0,m]:=tmp
         end;
   {------------------------------------------------}
   writeln(txt,centernr(' '+lang^[GraphLog_9]+s1+' ',w+8));
   writeln(txt,centernr('('+cd0+' - '+cd1+')',w+8));
   writeln(txt);
   s1:='';
   for j:=k downto 1 do
      begin
         if parts=2 then
            begin
               i:=j;
               case i of
                  16: s1:='ษออออ['+times[0]+']ออออป';
                  14,12,10,8,6,4,2: s1:='ฬออออ['+times[maxt-i div 2+1]+']ออออน';
                  15,13,11,9,7,5,3,1:
                     begin
                        s:=copy(delta2str(l(maxt-i div 2)),1,13);
                        if pos('/',s)<>4 then s:=' '+s;
                        s1:='บ'+s+right('('+strz(l(maxt-i div 2)*100 div (tltm+ord(tltm=0)),1),5)+'%) บ'
                     end
               end;
               s1:=' '+s1
            end;
         if j mod 4=0 then s:=strz(100*j div k,1)+'% ด'
                      else s:='ณ';
         for i:=0 to maxp do
            begin
               btm:=0;
               for m:=1 to maxevt do
                  begin
                     q:=(busytime[i,m]+btm)*long(k)*long(parts)/(long(3600)*long(days))>=long(j);
                     if q then break
                          else inc(btm,busytime[i,m])
                  end;
               if not q then
                  begin
                     if g_spc then c:=' ' else c:='๚'
                  end
                        else
               case m of
                  1: c:=times[4][1];
                  2: c:=times[3][1];
                  3: c:=times[2][1];
                  4: c:=times[5][1];
                  5: c:=times[6][1];
                  6: c:=times[maxt][1]
               end;
               s:=s+c
            end;
         writeln(txt,s:w,s1);
      end;
   gl_final(s,s1,parts,shift);
   if parts=2 then s2:=' ศออออออออออออออออออออผ' else s2:='';
   writeln(txt,s:w,s2);
   writeln(txt,s1:w);
   if parts=3 then
      begin
         writeln(txt);
         writeln(txt,'ษออออออออออออัออออออออออออออออออออหออออออออออออัออออออออออออออออออออป':w);
         for i:=0 to maxt div 2 do
            begin
               writeln(txt,'บ '+times[i]+' ณ '+delta2str(l(i))+right('('+strz(l(i)*100 div (tltm+ord(tltm=0)),1),5)+'%) บ '+
                       times[i+4]+' ณ '+delta2str(l(i+4))+right('('+strz(l(i+4)*100 div (tltm+ord(tltm=0)),1),5)+'%) บ':w);
               if i<maxt div 2 then writeln(txt,'ฬออออออออออออุออออออออออออออออออออฮออออออออออออุออออออออออออออออออออน':w)
            end;
         writeln(txt,'ศออออออออออออฯออออออออออออออออออออสออออออออออออฯออออออออออออออออออออผ':w)
      end;
   if parts=2 then w:=w+23;
   writeln(txt,tearline:w);
   close(txt)
end;

procedure CPSWide;
var txt,tpl:text;
    s,s0,s1:string;
    step,cpa,cpo:long;
    i,j:wrd;
    g,g4:byte;
    cp:tcpsw;
    cs:char;
    q,body:boolean;
begin
   assign(txt,newname('c'));
   if not (s_[1] and s_[5]) then exit;
   if no_ev or (cps_max=65535) then
      begin
         kill(newname('c'));
         exit
      end;
   if length(VSet^[24])>6 then cs:=VSet^[24][7] else cs:='þ';
   g:=10;
   g4:=g*4;
   assign(tpl,tplname('c'));
   {$I-}
   reset(tpl);
   {$I+}
   if ioresult<>0 then
      begin
         writeln('[?] Can''t read '+tplname('c'));
         wlog(1,'Can''t read '+tplname('c'));
         halt(2)
      end;
   rewrite(txt);
   case cps_opt of
      0: s:=lang^[CPSWide_6]; {cps}
      1: s:=lang^[CPSWide_4]; {maxcps}
      2: s:=lang^[CPSWide_5]; {mincps}
   end;
   if cps_max>0 then
      for i:=0 to cps_max-1 do
         for j:=i+1 to cps_max do with ocps[j] do
            begin
               if ((ocps[i].ccps[cps_opt]<ccps[cps_opt]) and not cps_adr) xor cps_rev then
                  begin
                     cp:=ocps[i];
                     ocps[i]:=ocps[j];
                     ocps[j]:=cp
                  end
            end;
   cpo:=0;
   for i:=0 to cps_max do with ocps[i] do inc(cpo,ccps[cps_opt]);
   cpo:=(cpo div (i+ord(i=0)))*2;
   cpa:=250;
   for i:=0 to cps_max do with ocps[i] do
      begin
         if ccps[2]=65535 then ccps[2]:=0;
         if (cpa<ccps[cps_opt]) and (ccps[cps_opt]<cpo) then cpa:=ccps[cps_opt]
      end;
   step:=(cpa+cpa mod 100) div 200*50;
   MacPut('Date','('+cd0+' - '+cd1+')');
   MacPut('CPSMode',s+' '+lang^[CPSWide_3]);
   MacPut('Scale',right(kbt(step),g)+right(kbt(step*2),g)+right(kbt(step*3),g)+right(kbt(step*4),g));
   tplmod:=_none; curtpl:=_none; body:=false;
   while tplmod<>_end do
      begin
         q:=TplGet(tpl,s0);
         case tplmod of
            _body:
               if not body then
               begin
               body:=true;
               for i:=0 to cps_max do with ocps[i] do
                  begin
                     j:=long(ccps[cps_opt])*long(g) div step;
                     s:=strz(i+1,1);
                     if i<99 then s:=s+'.';
                     MacPut('Num',s);
                     MacPut('Address',code_addr(cz,cnet,cnode,cpnt,false,true));
                     MacPut('Bar',pg4(j,g4,cs));
                     MacPut('MinCPS',okcps(ocps[i].ccps[2]));
                     MacPut('MaxCPS',okcps(ocps[i].ccps[1]));
                     MacPut('AvgCPS',okcps(ocps[i].ccps[0]));
                     writeln(txt,tplmacro(s0))
                  end
               end;
            _print: writeln(txt,tplmacro(s0));
         else {nothing};
         end
      end;
   close(tpl);
   close(txt)
end;

procedure load(i:byte);
var num:string;
begin
   num:=strz(i+1,1)+'.';
   MacPut('MaxNum',num);
   MacPut('MinNum',num);
   MacPut('AMaxNum',num);
   MacPut('AMinNum',num);
   if i<amax then
      with amaxcps[i] do
         begin
            MacPut('MaxAddress',code_addr(cz,cnet,cnode,cpnt,false,true));
            MacPut('MaxCPS',okcps(cps))
         end
              else MacPut('MaxNum','');
   if i<smax then
      with smaxcps[i] do
         begin
            MacPut('AMaxAddress',code_addr(cz,cnet,cnode,cpnt,false,true));
            MacPut('AMaxCPS',okcps(cps))
         end
              else MacPut('AMaxNum','');
   if i<amin then
      with amincps[i] do
         begin
            MacPut('MinAddress',code_addr(cz,cnet,cnode,cpnt,false,true));
            MacPut('MinCPS',okcps(cps))
         end
              else MacPut('MinNum','');
   if i<smin then
      with smincps[i] do
         begin
            MacPut('AMinAddress',code_addr(cz,cnet,cnode,cpnt,false,true));
            MacPut('AMinCPS',okcps(cps))
         end
              else MacPut('AMinNum','')
end;
procedure CPSLog;
var txt,tpl:text;
    bd,s0,s1:string;
    i:byte;
begin
   assign(txt,newname('c'));
   if not (s_[1] and s_[5]) then exit;
   if no_ev or (smin or smax or amin or amax=0) then
      begin
         kill(newname('c'));
         exit
      end;
   assign(tpl,tplname('1'));
   {$I-}
   reset(tpl);
   {$I+}
   if ioresult<>0 then
      begin
         writeln('[?] Can''t read '+tplname('1'));
         wlog(1,'Can''t read '+tplname('1'));
         halt(2)
      end;
   rewrite(txt);
   bd:=''; tplmod:=_none; curtpl:=_none;
   while tplmod<>_end do
      begin
         q:=TplGet(tpl,s0);
         case tplmod of
            _body_div: bd:=s0;
            _body: for i:=0 to 9 do
                      begin
                         load(i);
                         s1:=tplmacro(bd);
                         if s1<>'' then writeln(txt,tplmacro(s0))
                      end;
            _print: writeln(txt,tplmacro(s0));
         else {nothing};
         end
      end;
   close(tpl);
   close(txt)
end;

procedure DiskSpc;
var txt,tpl:text;
    d,cs:char;
    i,j,k,w:byte;
    {$ifdef os2}
    e:word;
    {$endif}
    ds,df:comp;
    drv,s,s0,s1:string;
    q,u,body:boolean;
begin
   drv:=big(VSet^[7]);
   if pos('*',drv)<>0 then drv:='*';
   if not s_[6] or (drv='') then
      begin
         kill(newname('d'));
         exit
      end;
   assign(txt,newname('d'));
   if length(VSet^[24])>7 then cs:=VSet^[24][8] else cs:='þ';
   w:=40;
   assign(tpl,tplname('d'));
   {$I-}
   reset(tpl);
   {$I+}
   if ioresult<>0 then
      begin
         writeln('[?] Can''t read '+tplname('d'));
         wlog(1,'Can''t read '+tplname('d'));
         halt(2)
      end;
   rewrite(txt);
   {d_opt = 1 - used
    d_opt = 0 - free}
   MacPut('DiskMode',' '+lang^[Disk_1+5*(1-d_opt)]+' ');
   MacPut('Date','('+cd0+' - '+cd1+')');
   i:=1; k:=0; q:=false;
   write('  ] '+lang^[disk_3]+#13'[');
   tplmod:=_none; curtpl:=_none; body:=false;
   while tplmod<>_end do
      begin
         u:=TplGet(tpl,s1);
         case tplmod of
            _body:
               if not body then
               begin
               body:=true;
               while (i<=length(drv)) do
                  begin
                     d:=drv[i];
                     inc(k);
                     if d='*' then
                        begin
                           d:=chr(k+$40);
                           if d='Z' then inc(i)
                        end
                              else inc(i);
                     j:=ord(d)-$40;
                     if (j>2) and (j<27) then
                        begin
                           write(d,#8);
                           MacPut('Drive',d+':');
                           if not diskinfo(j,ds,df,s) then wlog(2,'Drive '+d+': not ready');
                           if ds>0 then
                              begin
                                 q:=true;
                                 MacPut('Label',s);
                                 MacPut('Bar',pg4(trunc(abs(d_opt-df/ds)*w),w,cs));
                                 MacPut('Space',dec2str(ds,1));
                                 MacPut('Free',dec2str(df,1));
                                 writeln(txt,tplmacro(s1))
                              end
                        end
                  end
               end;
            _print: writeln(txt,tplmacro(s1));
         else {nothing};
         end
      end;
   writeln('๛');
   close(tpl);
   close(txt);
   if not q then kill(newname('d'))
end;

procedure zyzmlr;
var txt,tpl:text;
    s0,s1,s2,bd:string;
    k,lso:int;
    ovr:tovr;
    q,u:boolean;
begin
   assign(txt,newname('s'));
   if not (s_[1] and s_[2] and s_[7]) then exit;
   if no_ev then
      begin
         kill(newname('s'));
         exit
      end;
   assign(tpl,tplname('s'));
   {$I-}
   reset(tpl);
   {$I+}
   if ioresult<>0 then
      begin
         writeln('[?] Can''t read '+tplname('s'));
         wlog(1,'Can''t read '+tplname('s'));
         halt(2)
      end;
   rewrite(txt);
   q:=true;
   bd:=''; tplmod:=_none; curtpl:=_none;
   while tplmod<>_end do
      begin
         u:=TplGet(tpl,s2);
         case tplmod of
            _body_div: bd:=s2;
            _body:
               for k:=0 to ocuridx-1 do
                  begin
                     Ovr_(k,false,ovr);
                     with ovr do if inaddr(oz,onet,onode,opnt,VSet^[8]) then
                        begin
                           if (ozyz<>'') or (omlr<>'') then
                              begin
                                 if q then
                                    writeln(txt,tplmacro(bd));
                                 q:=false;
                                 MacPut('Address',code_addr(oz,onet,onode,opnt,false,true));
                                 MacPut('SysOp',ozyz);
                                 MacPut('Mailer',omlr);
                                 writeln(txt,tplmacro(s2))
                              end
                        end;
                  end;
            _print: writeln(txt,tplmacro(s2));
         else {nothing};
         end
      end;
   close(tpl);
   close(txt)
end;

procedure mailer;
var txt,tpl:text;
    s,s0,bd:string;
    i,j,k,cmax,ctt:int;
    ovr:tovr;
    q:boolean;
begin
   assign(txt,newname('m'));
   if not (s_[1] and s_[2] and s_[8]) then exit;
   if no_ev then
      begin
         kill(newname('m'));
         exit
      end;
   assign(tpl,tplname('m'));
   {$I-}
   reset(tpl);
   {$I+}
   if ioresult<>0 then
      begin
         writeln('[?] Can''t read '+tplname('m'));
         wlog(1,'Can''t read '+tplname('m'));
         halt(2)
      end;
   rewrite(txt);
   new(mlrs);
   cmax:=0; ctt:=0;
   for k:=0 to ocuridx-1 do
      begin
         Ovr_(k,false,ovr);
         with ovr do
         if inaddr(oz,onet,onode,opnt,VSet^[8]) then
            if omlr<>'' then
               begin
                  inc(ctt);
                  mlrpos(omlr,cmax)
               end
      end;
   bd:=''; tplmod:=_none; curtpl:=_none;
   while tplmod<>_end do
      begin
         q:=TplGet(tpl,s0);
         case tplmod of
            _body_div: bd:=s0;
            _body:
               begin
                  if ctt>0 then writeln(txt,tplmacro(bd));
                  for k:=0 to cmax-1 do with mlrs^[k] do
                     begin
                        s:=strz(k+1,1);
                        if k<99 then s:=s+'.';
                        MacPut('Num',s);
                        MacPut('Mailer',name);
                        MacPut('Count',strz(num,1));
                        str(long(num)*100/(ctt+ord(ctt=0)):3:1,s);
                        MacPut('Percent',s+'%');
                        writeln(txt,tplmacro(s0))
                     end;
               end;
            _print: writeln(txt,tplmacro(s0));
         else {nothing};
         end
      end;
   dispose(mlrs);
   close(tpl);
   close(txt)
end;

procedure Help(msgn:byte);
var s:string;
    n,i:byte;
    hlp:text;
begin
   if msgn=Start_19 then writeln('[?] '+lang^[msgn])
                    else writeln('[?] '+lang^[Help_1]+': '+lang^[msgn]);
   assign(hlp,rdir+pname+'.hlp');
   {$I-}
   reset(hlp);
   {$I+}
   if ioresult=0 then
      begin
         while not eof(hlp) do
            begin
               readln(hlp,s);
               writeln(expandstr(s,1))
            end;
         close(hlp)
      end
                 else writeln('[?] '+lang^[Help_2]+': '+pname+'.HLP');
   dispose(lang);
   showcursor;
   halt(1)
end;

procedure HelpS(msg:string);
begin
   lang^[0]:=msg;
   help(0)
end;

procedure start(ctask:byte);
var i,j,k,nn:byte;
    z,net,node,pnt,ts:int;
    hour,min,sec,code:word;
    s,tmp:string;
    keys:soc;
    c:char;
    next,ka,mr:boolean;
    sr:searchrec;
    bin:file;
procedure binstart;
var r,ti,did:boolean;
    i,j,id,ip,fid,task,fields,fieldi,lll,ll0:byte;
    t:long;
    s:string;
    cp:boolean;
begin
   no_bak:=false;
   log_cut:=false; log_kil:=false;
   log_ren:=0; log_bak:=false;
   t_hid_det:=false; t_hid_ext:=false; t_hid_fai:=false;
   s_hid_ext:=false; s_hid_fai:=false;
   g_wide:=false; g_fake:=false; g_spc:=false; g_skp:=false;
   p_1st:=true; a_4d:=false; fcps:=false;
   cps_rev:=false; cps_adr:=false; cps_opt:=0; cps_top:=false;
   hid_arc:=false;hid_net:=false;hid_tic:=false;hid_fil:=false; hid_skp:=false;
   hide_a:=false; hide_n:=false; hide_t:=false; hide_f:=false;
   t_hid_pwd:=false; s_hid_pwd:=false; s_wi:=false;
   ti:=true; lll:=0; hilog:=0; lolog:=0; fsc46:=false;
   ip:=0; d_opt:=1;
   for i:=1 to rpt do
      begin
         s_[i]:=(i=1);
         k_[i]:=false;
         c_[i]:=true;
         p_[i]:=0
      end;
   p_[1]:=3; p_[2]:=2;
   run:=false; mline:=false;
   msgatr:=0;
   for i:=1 to nrkw+rkw do vset^[i]:='';
   VSet^[nrkw+8]:=',-1';
   id8:=-1;
   id14:=-1;
   assign(bin,rdir+pname+'.bin');
   {$I-}
   reset(bin,1);
   {$I+}
   r:=ioresult=0;
   if r then
      begin
         repeat
            blockread(bin,id,1,code);
            if code<>1 then id:=0;
            if id<>0 then
               begin
                  did:=true;
                  ll0:=0; {Cutlog}
                  blockread(bin,fields,1);
                  blockread(bin,task,1);
                  taskset:=taskset+[task];
                  if (task=MTask) or (task=ctask) then
                     for i:=1 to fields do
                        begin
                           blockread(bin,fid,1);
                           cp:=fid and $40>0;
                           fid:=fid and $bf;
                           case fid of
                              $80: begin {string}
                                      blockread(bin,fid,1);
                                      seek(bin,filepos(bin)-1);
                                      blockread(bin,s,fid+1);
                                      s:=expandstr(s,0)
                                   end;
                              $81: begin {long}
                                      blockread(bin,t,4);
                                      if id=6 then
                                         case lll of
                                            0: begin
                                                  hilog:=t;
                                                  inc(lll)
                                               end;
                                            1: lolog:=t
                                         end
                                              else
                                      if cutter and (id=28) then
                                         case ll0 of
                                            0: begin
                                                  lilg[ilg]^.hilog:=t;
                                                  inc(ll0)
                                               end;
                                            1: lilg[ilg]^.lolog:=t
                                         end;
                                      s:=strz(t,1)
                                   end;
                           else
                              begin
                                 s:='';
                                 case id of {ennumerated variables definition}
                                    3: no_bak:=fid=1;
                                    4: k_[fid]:=true;
                                    5: loglevel:=fid;
                                    6: case fid of
                                          1: log_cut:=true;
                                          2: log_kil:=true;
                                          3,4: log_ren:=fid-2;
                                          5: log_bak:=true;
                                       end;
                                    7: d_opt:=fid-1;
                                    10: msgatr:=msgatr or (wrd(1) shl (fid-1));
                                    15: case fid of
                                           1: t_hid_det:=true;
                                           2: t_hid_ext:=true;
                                           3: t_hid_fai:=true;
                                           4: fcps:=true;
                                           5: t_hid_pwd:=true;
                                        end;
                                    16: case fid of
                                           1: s_hid_ext:=true;
                                           2: s_hid_fai:=true;
                                           3: fcps:=true;
                                           4: s_hid_pwd:=true;
                                        end;
                                    17: case fid of
                                           1: g_wide:=true;
                                           2: g_fake:=true;
                                           3: g_spc:=true;
                                           4: g_skp:=true;
                                        end;
                                    18: case fid of
                                           1: hide_n:=true;
                                           2: hide_a:=true;
                                           3: hide_t:=true;
                                           4: hide_f:=true;
                                           5: begin hid_net:=true; hide_n:=true end;
                                           6: begin hid_arc:=true; hide_a:=true end;
                                           7: begin hid_tic:=true; hide_t:=true end;
                                           8: begin hid_fil:=true; hide_f:=true end;
                                           9: hid_skp:=true
                                        end;
                                    19: case fid of
                                           1: cps_rev:=true;
                                           2..4: cps_opt:=fid-2;
                                           5: cps_adr:=true;
                                           6: cps_top:=true;
                                        end;
                                    20: case fid of
                                           1..8: s_[fid]:=true;
                                           9: run:=true;
                                           10: mline:=true;
                                        end;
                                    21: case fid of
                                           1: a_4d:=true;
                                        end;
                                    25: case fid of
                                           1: s_wi:=true;
                                        end;
                                    nrkw+5: begin
                                               if p_1st then
                                                  begin
                                                     p_1st:=false;
                                                     p_[1]:=0;
                                                     p_[2]:=0;
                                                     for j:=1 to rpt do c_[j]:=false
                                                  end;
                                               inc(ip);
                                               p_[ip]:=fid;
                                               c_[ip]:=cp
                                            end
                                    {$ifdef alpha}
                                    else
                                 begin
                                    writeln('[?] Unknown type variable ['+strz(itask,1)+'] at '+hex(filepos(bin)-1,4)+'h: ',
                                             hex(id,2));
                                    wlog(2,'[?] Unknown type variable ['+strz(itask,1)+'] at '+hex(filepos(bin)-1,4)+'h: '+
                                            hex(id,2))
                                 end
                                    {$endif}
                                end
                              end
                           end;
                           if id=8 then
                              begin
                                 if id8=-1 then id8:=task;
                                 if id8=task then VSet^[8]:=VSet^[8]+' '+s
                              end
                                   else
                           if id=14 then
                              begin
                                 if id14=-1 then id14:=task;
                                 if id14=task then VSet^[14]:=VSet^[14]+' '+s
                              end
                                    else
                           if did and cutter and (id=28) then
                              begin
                                 did:=false;
                                 inc(ilg);
                                 new(lilg[ilg]);
                                 lilg[ilg]^.s:=s;
                                 lilg[ilg]^.hilog:=0;
                                 lilg[ilg]^.lolog:=0
                              end
                                    else
                           if (id=nrkw+8) and ti then
                              begin
                                 VSet^[id]:='';
                                 ti:=false
                              end;
                           if VSet^[id]='' then VSet^[id]:=VSet^[id]+s
                        end
                                              else {Seek unused}
                     for i:=1 to fields do
                        begin
                           blockread(bin,fid,1);
                           case fid of
                              $80: begin {string}
                                      blockread(bin,fid,1);
                                      seek(bin,filepos(bin)+fid)
                                   end;
                              $81: seek(bin,filepos(bin)+4) {long}
                           else {Nothing};
                           end
                        end
               end
         until id=0
      end;
   cutter:=false;
   twit:=VSet^[nrkw+8];
   if nl then VSet^[3]:=VSet^[nrkw+8]
end;
procedure DefPeriod(s:string);
begin
   d0:=readword(s,i,['-',',']);
   mr:=pos('/',d0)=0;
   if s[i-1]='-' then d1:=readword(s,i,[','])
                 else if mr then d1:='1'
                            else d1:=d0;
   if mr and (pos('/',d1)<>0) then help(Start_3);
   if s[i-1]=',' then
      begin
         t0:=readword(s,i,['-']);
         if s[i-1]='-' then t1:=readword(s,i,spc)
                       else t1:=t0
      end;
   if mr then
      begin
         if not backday(d0,'') then help(Start_2);
         if not backday(d1,d0) then help(Start_3)
      end;
   s:=d0+' '+t0;
   if not CheckDT(s) then help(Start_4);
   d0:=copy(s,1,5); t0:=copy(s,7,8);
   s:=d1+' '+t1;
   if not CheckDT(s) then help(Start_5);
   d1:=copy(s,1,5); t1:=copy(s,7,8)
end;
begin
  {1*language   2=registername 3=dirlist       4=kill
   5=log        6=t-log        7=disk          8*nodes
   9=period     10*area        11*areapath     12*frompkt
   13*frommsgid 14=topkt       15=total        16=summary
   17=graphic   18=filelist    19=cps          20=statistics
   21=aliases   22=address     23=output       24=charset
   25=flag      26=zerocounter 27=ignorefiles}
  {1=from        2=to       3=subj          4=origin
   5=postfiles   6=tearline 7=flag          8=twitinfo}
   d0:='01/01'; d1:='31/12'; t0:='00:00:00'; t1:='23:59:59';
   parts:=2;
   binstart; {Read T-LAN.CTL}
   if mline and g_skp then inc(mg);
   if VSet^[9]<>'' then
      begin
         i:=1;
         defperiod(VSet^[9])
      end;
   ka:=false;
   keys:=[];
   for j:=1 to paramcount do
      begin
         s:=paramstr(j);
         if s[1] in ['-','/'] then
            begin {Switches}
               c:=lowcase(s[2]);
               i:=3;
               if c in keys then helps(lang^[Start_1]+' -'+upcase(c));
               keys:=keys+[c];
               case c of
                  'c': {Nothing};
                  'd': for i:=3 to length(s) do
                          case lowcase(s[i]) of
                             'c': kcase:=true;
                             'k': kbyte:=1000;
                             'f': fsc46:=true;
                             {$ifdef os2}
                             'n': network:=false;
                             {$else}
                             'w': fat32:=false
                             {$endif}
                          else
                             begin
                                writeln('[?] '+lang^[Start_9]+upcase(c)+': '+upcase(s[i]));
                                wlog(2,lang^[Start_9]+upcase(c)+': '+upcase(s[i]))
                             end
                          end;
                  'g': for i:=3 to length(s) do
                          case lowcase(s[i]) of
                             'f': g_fake:=true;
                             'r': g_wide:=false;
                             'w': g_wide:=true
                          else
                             begin
                                writeln('[?] '+lang^[Start_9]+upcase(c)+': '+upcase(s[i]));
                                wlog(2,lang^[Start_9]+upcase(c)+': '+upcase(s[i]))
                             end
                          end;
                  'h','?': help(Start_19);
                  'l': VSet^[1]:=copy(s,i,length(s)-2);
                  'm': mline:=true;
                  'n': begin
                          nn:=0;
                          taskset:=[];
                          repeat
                             ts:=lval(readword(s,i,[',']));
                             if (ts<0) or (ts>253) then
                                begin
                                   writeln('[?] '+lang^[Start_10]+': '+strz(ts,1));
                                   ts:=0
                                end;
                             taskset:=taskset+[lo(ts)];
                             inc(nn)
                          until i>length(s);
                          if nn<2 then mline:=false
                       end;
                  'p': defperiod(s);
                  'q': VSet^[10]:='';
                  's': begin
                          VSet^[6]:=copy(s,i,length(s)-2);
                          taskset:=[0]
                       end;
                  'x': loglevel:=4;
                  'z': begin
                          if length(s)<3 then s:=s+'ts';
                          for i:=3 to length(s) do
                             case lowcase(s[i]) of
                                't': t_hid_pwd:=true;
                                's': s_hid_pwd:=true
                             else
                                begin
                                   writeln('[?] '+lang^[Start_9]+upcase(c)+': '+upcase(s[i]));
                                   wlog(2,lang^[Start_9]+upcase(c)+': '+upcase(s[i]))
                                end
                             end
                       end;
               else helps(lang^[Start_6]+' -'+upcase(c))
               end;
            end
      end;
   if g_wide then parts:=3;
   if VSet^[nrkw+5]<>'' then kb:=lval(VSet^[nrkw+5]);
   if not (kb in [1..{$ifndef ver70}255{$else}32{$endif}]) then kb:=12;
   if VSet^[11]<>'' then
      if VSet^[11][length(VSet^[11])]<>'\' then VSet^[11]:=VSet^[11]+'\';
   if VSet^[30]='' then VSet^[30]:=rdir else
      if VSet^[30][length(VSet^[30])]<>'\' then VSet^[30]:=VSet^[30]+'\';
   if (VSet^[10]<>'') and (VSet^[12]<>'') then
      begin
         i:=1;
         s:=VSet^[14];
         tmp:=readword(s,i,spc+[';']); VSet^[14]:=tmp;
         if s[i-1]=' ' then pwd:=readword(s,i,spc+[';']);
         if pos('netmail',lower(VSet^[10]))<>0 then netmail:=true
                                               else netmail:=false;
         if decode_addr(VSet^[12],z,net,node,pnt,true)<>0 then help(Start_7);
         VSet^[12]:=code_addr(z,net,node,pnt,false,false);
         if VSet^[13]<>'' then
            begin
               if decode_addr(VSet^[13],z,net,node,pnt,true)<>0 then help(Start_7);
               VSet^[13]:=code_addr(z,net,node,pnt,false,false)
            end
                          else VSet^[13]:=VSet^[12];
         if netmail and (VSet^[12]<>VSet^[13]) then VSet^[13]:=VSet^[12];
         if decode_addr(VSet^[14],z,net,node,pnt,true)<>0 then
            begin
               if netmail then help(Start_8)
                          else VSet^[14]:=VSet^[12]
            end;
         if VSet^[14]<>VSet^[12] then VSet^[14]:=code_addr(z,net,node,pnt,true,false);
         if VSet^[nrkw+1]='' then VSet^[nrkw+1]:=pname;
         if VSet^[nrkw+4]='' then VSet^[nrkw+4]:=lang^[Poster_2];
         if VSet^[nrkw+2]='' then
            begin
               if netmail then VSet^[nrkw+2]:='SysOp'
                          else VSet^[nrkw+2]:='All'
            end;
         if VSet^[nrkw+3]='' then VSet^[nrkw+3]:=lang^[Poster_1]
      end
                    else for j:=1 to rpt do p_[j]:=0;
   for j:=1 to rpt do
      begin
         p_[j]:=p_[j]*ord(s_[p_[j]]);
         k_[j]:=k_[j] and s_[j]
      end;
   if (s_[5] or s_[7] or s_[8]) and not s_[2] then {*.sta required for c,s,m}
      begin
         s_[2]:=true;
         k_[2]:=true
      end;
   if VSet^[8]='' then VSet^[8]:='*:*/*.*';
   if not (length(VSet^[26]) in [2..6]) then VSet^[26]:='[00]';
   home.z:=defzone; home.net:=0; home.node:=0; home.pnt:=0;
   if not ((VSet^[22]='') or (VSet^[22][1]<'0') or (VSet^[22][1]>'9')) then
      decode_addr(VSet^[22],home.z,home.net,home.node,home.pnt,true);
   if not onestep then
      begin
         {.LNG file}
         write('[ ] '+lang^[Start_11]+' ');
         for j:=1 to items do
            begin
               s:=c_known[j];
               known^[j]:=s
            end;
         onestep:=true;
         next:=false;
         if exist(VSet^[1],sr,next) then FillKnown(lower(sr.name))
                                    else write(lang^[Start_12]);
         i:=1;
         tmp:=lower(readword(known^[36],i,spc));
         if tmp='session' then write(lang^[Start_13]) else {English}
         if tmp='‘ฅแแจ๏' then write(lang^[Start_14]) else  {Russian}
         if tmp='sitzung' then write(lang^[Start_17]) else {German}
         if tmp='relace' then write(lang^[Start_18]) else {Czech}
         if tmp<>'' then write(lang^[Start_15]);
         writeln(#13'[๛')
      end;
   cd0:=d0+' '+t0;
   cd1:=d1+' '+t1;
   time0:=Str2Sec(cd0);
   time1:=Str2Sec(cd1);
   {$ifdef dlc}
   InitDLC(VSet^[3],ctask)
   {$endif}
end;
function ResetLf(exiting:boolean):boolean;
var tries,io:byte;
    s:string;
begin
   filemode:=$40;
   tries:=0;
   repeat
      if tries>0 then
         begin
            if tries=1 then write(lang^[ResetLf_1]+' (#01)'#8) else write(#8#8+strz(tries,2));
            waitsec(1)
         end;
      inc(tries);
      {$I-}
      reset(lf,1);
      {$I+}
      io:=ioresult;
   until not (io in [{$ifdef os2}32{$else}5,162{$endif}]) or (tries>10);
   if tries>1 then for tries:=0 to length(lang^[ResetLf_1])+4 do write(#8);
   case io of
        0: exiting:=false;
        {$ifdef os2}32{$else}5,162{$endif}: s:=lang^[ResetLf_2];
   else
      begin
         {$I-}
         rewrite(lf,1);
         {$I+}
         io:=ioresult;
         exiting:=io<>0;
         if not exiting then
            begin
               writeln('[?] '+lang^[main_4]);
               inc(mg)
            end;
         s:=lang^[ResetLf_3]{$ifdef alpha}+': #'+strz(io,1){$endif}
      end
   end;
   if exiting then helps(s) else resetlf:=(io=0);
   if io=0 then flsize:=filesize(lf)
end;
procedure Init;
var pfl:tpfil;
    _tmp:long;
    i:wrd;
    f,t:file;
    rr:integer;
begin
   _tslc:=timer;
   sll:='';
   fptr:=0; {closed}
   skp:=0;
   if aidx>0 then dispose(alias);
   InitAlias(VSet^[21]);
   if (mline and frst) or not mline then swpinit;
   timeofs:=0;
   maxp:=24*parts-1;
   assign(lf,ldir+lnam);
   if resetlf(true) then close(lf);
   filemode:=flmode;
   kill(newname('%'));
   kill(newname('#'));
   if (mline and frst) or not mline then killfil;
   {$ifdef binkd}
   bnd2tml_init;
   {$endif}
   frst:=false
end;
procedure Done;
var i:wrd;
    f:file;
begin
   write('  ] '+lang^[Main_7]+#13'[');
   memdone;
   writeln('๛');
   writeln
end;
procedure AllPost;
var i,j,k:byte;
    last:boolean;
begin
   ok:=true;
   for i:=1 to rpt do
      begin
         last:=true;
         for j:=rpt downto i+1 do last:=last and (p_[j]=0);
         k:=p_[i];
         ok:=ok and (ImportFile(newname(let[k]),k>0,c_[i],last)>0)
      end;
   for i:=1 to rpt do
      if k_[i] then
         if not kill(newname(let[i])) then wlog(2,'Can''t erase '+newname(let[i]))
end;
procedure AllStt;
begin
   TOTAL;
   OVERALL;
   FILELIST;
   if cps_top then CPSLog else CPSWide;
   GRAPHLOG;
   zyzmlr;
   mailer;
   DiskSpc;
   AllPost;
   Flag(VSet^[nrkw+7]);
   Done
end;
{Main}
begin
   kbyte:=1024;
   kcase:=false;
   tasks:=0;
   mtsk:=0;
   aidx:=0;
   mg:=0;
   ilg:=0;
   randomize;
   frst:=true;
   bdf:=true;
   fle:=false;
   cutter:=true;
   pname:=vername;
   vialine:=pname+' '+ver;
   itask:=pos('a-',vialine)+2;
   bdir:='';
   pid:=pname{$ifdef os2}+'/2'{$endif}{$ifdef win32}+'/W32'{$endif}+
        ' '+vernum{$ifndef release}+'.'{$ifdef alpha}+'a'{$endif}+
        copy(vialine,itask,length(vialine)-itask-3{$endif});
   tearline:=' '+vialine+' ';
   MacPut('Version',tearline);
   {$ifndef os2}
   dver:=DosVersion;
   os2:=lo(dver)=20;
   fat32:=(dver=$0a07);
   if os2 then cslice:=os2slice
          else cslice:=vdmslice;
   {$endif}
   {$ifdef os2}
   network:=true;
   {$endif}
   filemode:=$42;
   flmode:=filemode;
   writeln;
   timeofs:=0;
   tsl:=unixnow;
   writeln(vialine,' (C) ',vercopy,' Vitaly Lunyov (2:5025/18@fidonet)');
   mem0:=memavail;
   rdir:=pdir(paramstr(0));
   assign(fl,rdir+pname+'.Lst');
   {$I-}
   erase(fl);
   {$I+}
   if ioresult<>0 then {Nothing};
   ldir:=shortname(paramstr(0));
   nl:=not readlng(rdir+pname+'.lng');
   if nl then
      begin
         writeln('Can''t accept language file');
         halt(2)
      end;
   hidecursor;
   writeln('[๛] '+lang^[Main_1]+' ('+verdate+')');
   q:=false;
   for itask:=1 to paramcount do
      begin
         s:=lower(paramstr(itask));
         q:=(pos('-c',s)=1) or (pos('/c',s)=1);
         if q then
            begin
               s:=copy(s,3,length(s)-2);
               break
            end
      end;
   if not q then s:=rdir+pname+'.ctl';
   s:=readctl(s);
   if s<>'' then helps(s);
   onestep:=false;
   _tmp:=timer;
   new(known);
   new(VSet);
   taskset:=[];
   Start(MTask);
   if mline then writeln('[๛] '+lang^[Main_9]);
   for itask:=0 to MTask do
      if itask in taskset then
         begin
            start(itask);
            initmylog(vset^[5]);
            if vset^[6]<>'' then ps1:=fexpand(vset^[6]) else ps1:='';
            ldir:=pdir(ps1);
            if (mline and bdf) or not mline then
               begin
                  bdf:=false;
                  if vset^[23]='' then bdir:=ldir else bdir:=vset^[23];
                  if bdir='' then bdir:='.';
                  if bdir[length(bdir)]<>'\' then bdir:=bdir+'\'
               end;
            assign(f,bdir+'t-lan.t$t');
            {$I-}
            rewrite(f,1);
            {$I+}
            if ioresult<>0 then help(Main_2)
                           else
               begin
                  close(f);
                  {$I-}
                  erase(f);
                  {$I+}
                  if ioresult<>0 then {Nothing};
               end;
            lnam:=lower(shortname(ps1));
            if lnam<>'' then
               begin
                  wlog(1,'þ Starting ('+strz(mem0,1)+') '+vialine+'/'+lang^[Main_1]);
                  writeln('[๛] '+lang^[Main_5]+' '+lnam);
                  Init;
                  {$ifdef alpha}
                  writeln('[*] Required:',memreq div 1024+155:4,'k');
                  writeln('[*] Looking from '+d0+' '+t0+' to '+d1+' '+t1);
                  writeln('[*] Nodes: '+Vset^[8]);
                  {$endif}
                  if itask=MTask then s:='*' else s:=strz(itask,1);
                  wlog(2,'['+s+'] Processing: '+lnam);
                  wlog(2,'Looking from '+d0+' '+t0+' to '+d1+' '+t1);
                  wlog(3,'Nodes: '+Vset^[8]);
                  wlog(3,'Memory required:'+right(strz(memreq div 1024+130,1),4)+'k');
                  if mem0>memreq then
                     begin
                        COUNTSTAT;
                        {$ifdef dlc}
                        if fle then
                           begin
                              {$I-}
                              reset(lr,1);
                              {$I+}
                              if ioresult<>0 then
                                 begin
                                    {$I-}
                                    rewrite(lr,1);
                                    {$I+}
                                    l0:=0;
                                    if ioresult=0 then for i0:=0 to MTask do blockwrite(lr,l0,4,j0)
                                 end;
                              seek(lr,itask*4);
                              blockwrite(lr,lc,4,j0);
                              close(lr)
                           end;
                        {$endif}
                        inc(tasks);
                        {$ifdef alpha}
                        writeln('[*] Processed: ',_nodes,', speed: ',round(_nodes*18/(timer-_tmp+1)),' events/sec');
                        {$endif};
                        wlog(2,'Nodes processed: '+strz(_nodes,1));
                        if not mline then AllStt
                                     else writeln;
                        if log_kil then
                           begin
                              kill(ldir+lnam);
                              wlog(2,'Deleted: '+lnam)
                           end
                                   else
                           begin
                              if log_bak then backuplog(ldir,lnam,VSet^[29]);
                              if log_cut then cutlog(ldir+lnam,VSet^[nrkw+9],hilog,lolog);
                              if log_ren>0 then renlog(ldir+lnam,itask);
                           end
                     end
                                     else
                     begin
                        writeln('[?] '+lang^[Main_6]);
                        Done
                     end
               end
         end;
   {$ifdef dlc}
   if fle then close(fl);
   {$endif}
   if mline then
      begin
         Start(MTask);
         dec(tasks,mtsk);
         AllStt
      end;
   {$ifdef dlc}
   if ProcessFreqList(rdir+pname+'.Lst',VSet^[3],VSet^[26])<>0 then wlog(3,'Error updating download counters!');
   {$endif}
   if ilg>0 then CutLogs;
   bnd2tml_done;
   if aidx>0 then dispose(alias);
   dispose(known);
   dispose(VSet);
   s:='[๛] '+lang^[Main_8];
   dispose(lang);
   dispose(mtable);
   wlog(1,'þ Shutdown ('+strz(memavail,1)+')');
   _tmp:=(timer-_tmp+1) div 18;
   writeln(s+' '+copy(dt2str(_tmp),7,8));
   showcursor
end.
