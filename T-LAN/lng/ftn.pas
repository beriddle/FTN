(*****************************************************************************
 * T-LAN - Universal Log Analyser
 *
 * $Id: ftn.pas,v 0.34.11 2000/11/19 00:08:00 riddle Exp $
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

unit ftn;

interface

uses dos{$ifndef ver70}{$ifdef os2},use32{$endif}{$endif};

type Long=System.LongInt;
     Wrd=System.Word;
     Int=System.Integer;
     soc=set of char;

     TAdr=record
             z,net,node,pnt:int
          end;
     TPktHdr=record
                origNode,destNode,year,month,day,hour,minute,second,baud,
                pkttype,origNet,destNet:wrd;
                ProductCode_Lo,Revision_Maj:byte;
                password:array[1..8] of char;
                origZone,destZone,AuxNet,CWvalidationCopy:wrd;
                ProductCode_Hi,Revision_Min:byte;
                CapabilWord,orig_Zone,dest_Zone,origPoint,destPoint:wrd;
                Specific_Data:long
             end;
     TPktHdrR=record
                 pkttype,origNode,destNode,origNet,destNet:wrd;
                 Specific_Data:long
              end;
     TMsgHdr=record
                from,to_:array[1..36] of char;
                subj:array[1..72] of char;
                datetim:array[1..20] of char;
                timesread,destnode,orignode,cost,orignet,destnet,destzone,
                origzone,destpoint,origpoint,replyto,attr,nextreply:wrd
             end;

const Spc:soc=[#9,' '];
      NoChr:soc=['~','!'];
      FtnRev=1;
      Mnth:array[1..12] of string[3]=
     ('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec');

      MsgPrivate             =$0001;
      MsgCrash               =$0002;
      MsgRecd                =$0004;
      MsgSent                =$0008;
      MsgFileAttached        =$0010;
      MsgInTransit           =$0020;
      MsgOrphan              =$0040;
      MsgKillSent            =$0080;
      MsgLocal               =$0100;
      MsgHoldForPickup       =$0200;
      Msgunused              =$0400;
      MsgFileRequest         =$0800;
      MsgReturnReceiptRequest=$1000;
      MsgIsReturnReceipt     =$2000;
      MsgAuditRequest        =$4000;
      MsgFileUpdateReq       =$8000;
      OS2Slice=13;
      VDMSlice=130;

{$ifdef ver70}
var _ftn_slc:long;
    _ftn_cslc:byte;
    _ftn_os2:boolean;
    timer:longint absolute $0040:$006C;
{$endif}
function Crc32Init:long;
function Crc32(b:byte;crc:long):long;
function Unix2Dos(UnixDate:long):long;
function Dos2Unix(DOSTime:long):long;
procedure TimeSlice;
function RenameF(var pathname:string):string; {***}
function Exist(pathname:string;var sr:searchrec;var next:boolean):boolean;
function Hex(n:long;z:byte):string;
function lval(s:string):long;
function strz(n:long;p:byte):string;
procedure SkipChr(s:string;var i:byte;term:soc);
function ReadWord(s:string;var i:byte;term:soc):string;
function CodeAddr(adr:tadr;zeropnt:boolean):string;
function DecodeAddr(addr:string;var adr:tadr;single:boolean):byte;
function InAddr(adr:tadr;masklst:string):boolean;
function AddrCRC32(adr:tadr):long;
function BinkFile(binkzone:int;var adr:tadr):string;
function FDFile(var adr:tadr):string;
function Busy(adr:tadr;DefaultZone:int;bink,fd:boolean):boolean;
function Center(s:string;len:byte):string;
function Left(s:string;len:byte):string;
function Right(s:string;len:byte):string;
function LowCase(c:char):char;
function Lower(s:string):string;
function Big(s:string):string;
function XLat(c:char):char;
procedure Now(var dt:datetime);
function FtnDate(dt:datetime):string;
procedure Str2Array(s:string;var a:array of char);
procedure CreatePktHdr(fpkt,topkt:tadr;sdat:long;var pkthdr:tpkthdr);
procedure CreateMsgHdr(_from,_to,_subj,_dt:string;fadr,toadr:tadr;atr:wrd;var msghdr:tmsghdr);
function Kludges(fadr,toadr:tadr;msgid,msgidr:long;area,pid:string):string;
function MsgExport(var txt:text;var f:file):boolean;

implementation
{---------------------------------------------------------------------------}
const Crc32Tab:array[0..255] of long=
     ($00000000,$77073096,$ee0e612c,$990951ba,$076dc419,$706af48f,$e963a535,$9e6495a3,
      $0edb8832,$79dcb8a4,$e0d5e91e,$97d2d988,$09b64c2b,$7eb17cbd,$e7b82d07,$90bf1d91,
      $1db71064,$6ab020f2,$f3b97148,$84be41de,$1adad47d,$6ddde4eb,$f4d4b551,$83d385c7,
      $136c9856,$646ba8c0,$fd62f97a,$8a65c9ec,$14015c4f,$63066cd9,$fa0f3d63,$8d080df5,
      $3b6e20c8,$4c69105e,$d56041e4,$a2677172,$3c03e4d1,$4b04d447,$d20d85fd,$a50ab56b,
      $35b5a8fa,$42b2986c,$dbbbc9d6,$acbcf940,$32d86ce3,$45df5c75,$dcd60dcf,$abd13d59,
      $26d930ac,$51de003a,$c8d75180,$bfd06116,$21b4f4b5,$56b3c423,$cfba9599,$b8bda50f,
      $2802b89e,$5f058808,$c60cd9b2,$b10be924,$2f6f7c87,$58684c11,$c1611dab,$b6662d3d,
      $76dc4190,$01db7106,$98d220bc,$efd5102a,$71b18589,$06b6b51f,$9fbfe4a5,$e8b8d433,
      $7807c9a2,$0f00f934,$9609a88e,$e10e9818,$7f6a0dbb,$086d3d2d,$91646c97,$e6635c01,
      $6b6b51f4,$1c6c6162,$856530d8,$f262004e,$6c0695ed,$1b01a57b,$8208f4c1,$f50fc457,
      $65b0d9c6,$12b7e950,$8bbeb8ea,$fcb9887c,$62dd1ddf,$15da2d49,$8cd37cf3,$fbd44c65,
      $4db26158,$3ab551ce,$a3bc0074,$d4bb30e2,$4adfa541,$3dd895d7,$a4d1c46d,$d3d6f4fb,
      $4369e96a,$346ed9fc,$ad678846,$da60b8d0,$44042d73,$33031de5,$aa0a4c5f,$dd0d7cc9,
      $5005713c,$270241aa,$be0b1010,$c90c2086,$5768b525,$206f85b3,$b966d409,$ce61e49f,
      $5edef90e,$29d9c998,$b0d09822,$c7d7a8b4,$59b33d17,$2eb40d81,$b7bd5c3b,$c0ba6cad,
      $edb88320,$9abfb3b6,$03b6e20c,$74b1d29a,$ead54739,$9dd277af,$04db2615,$73dc1683,
      $e3630b12,$94643b84,$0d6d6a3e,$7a6a5aa8,$e40ecf0b,$9309ff9d,$0a00ae27,$7d079eb1,
      $f00f9344,$8708a3d2,$1e01f268,$6906c2fe,$f762575d,$806567cb,$196c3671,$6e6b06e7,
      $fed41b76,$89d32be0,$10da7a5a,$67dd4acc,$f9b9df6f,$8ebeeff9,$17b7be43,$60b08ed5,
      $d6d6a3e8,$a1d1937e,$38d8c2c4,$4fdff252,$d1bb67f1,$a6bc5767,$3fb506dd,$48b2364b,
      $d80d2bda,$af0a1b4c,$36034af6,$41047a60,$df60efc3,$a867df55,$316e8eef,$4669be79,
      $cb61b38c,$bc66831a,$256fd2a0,$5268e236,$cc0c7795,$bb0b4703,$220216b9,$5505262f,
      $c5ba3bbe,$b2bd0b28,$2bb45a92,$5cb36a04,$c2d7ffa7,$b5d0cf31,$2cd99e8b,$5bdeae1d,
      $9b64c2b0,$ec63f226,$756aa39c,$026d930a,$9c0906a9,$eb0e363f,$72076785,$05005713,
      $95bf4a82,$e2b87a14,$7bb12bae,$0cb61b38,$92d28e9b,$e5d5be0d,$7cdcefb7,$0bdbdf21,
      $86d3d2d4,$f1d4e242,$68ddb3f8,$1fda836e,$81be16cd,$f6b9265b,$6fb077e1,$18b74777,
      $88085ae6,$ff0f6a70,$66063bca,$11010b5c,$8f659eff,$f862ae69,$616bffd3,$166ccf45,
      $a00ae278,$d70dd2ee,$4e048354,$3903b3c2,$a7672661,$d06016f7,$4969474d,$3e6e77db,
      $aed16a4a,$d9d65adc,$40df0b66,$37d83bf0,$a9bcae53,$debb9ec5,$47b2cf7f,$30b5ffe9,
      $bdbdf21c,$cabac28a,$53b39330,$24b4a3a6,$bad03605,$cdd70693,$54de5729,$23d967bf,
      $b3667a2e,$c4614ab8,$5d681b02,$2a6f2b94,$b40bbe37,$c30c8ea1,$5a05df1b,$2d02ef8d);

function Crc32Init:long;
begin
   Crc32Init:=$ffffffff
end;

function Crc32(b:byte;crc:long):long;
begin
   Crc32:=Crc32Tab[byte(crc xor longint(b))] xor ((crc shr 8) and $00FFFFFF)
end;

function Dos2Unix(DOSTime:long):long;
const DaysInMonth:array[1..12] of word=
     (31,28,31,30,31,30,31,31,30,31,30,31);
var i,j:word;
    UnixDate:long;
    DTR:DateTime;
begin
   UnPackTime(DOSTime,DTR);
   UnixDate:=0;
   UnixDate:=(DTR.year-1970)*365+((DTR.year-1971) div 4);
   j:=pred(DTR.day);
   if DTR.month<>1 then
      for i:=1 to pred(DTR.month) do j:=j+DaysInMonth[i];
   if ((DTR.year mod 4)=0) and (DTR.month>2) then inc(j);
   UnixDate:=UnixDate+j; (* Add number of days this year *)
   UnixDate:=(UnixDate*24)+DTR.hour;
   UnixDate:=(UnixDate*60)+DTR.min;
   UnixDate:=(UnixDate*60)+DTR.sec;
   Dos2Unix:=UnixDate
end;

function Unix2Dos(UnixDate:long):long;
const DaysInMonth:array[1..12] of word=
     (31,28,31,30,31,30,31,31,30,31,30,31);
var i,j:word;
    DTR:DateTime;
    DosTime:long;
begin
   DaysInMonth[2]:=28;
   DTR.sec:=UnixDate mod 60; UnixDate:=UnixDate div 60;
   DTR.min:=UnixDate mod 60; UnixDate:=UnixDate div 60;
   DTR.hour:=UnixDate mod 24; UnixDate:=UnixDate div 24;
   DTR.day:=UnixDate mod 365; UnixDate:=UnixDate div 365;
   DTR.year:=UnixDate+1970;
   DTR.day:=1+DTR.day-((DTR.year-1972) div 4);
   if (DTR.day>(31+29)) and ((DTR.year mod 4)=0) then inc(DaysInMonth[2]);
   DTR.month:=1;
   while DTR.day>DaysInMonth[DTR.Month] do
      begin
         DTR.day:=DTR.day-DaysInMonth[DTR.Month];
         inc(DTR.month)
      end;
   PackTime(DTR,DosTime);
   Unix2Dos:=DosTime
end;
{---------------------------------------------------------------------------}
{$ifdef ver70}
function Wait(time:long):boolean;
var q:byte;
begin
   while time>0 do
      begin
         dec(time);
         if _ftn_os2 then
            asm
               mov q,1
               mov ax,55
               mov dx,0
               hlt
               db 35h,0cah
            end
                else
            asm
               int 28h
               mov ax,1680h
               int 2fh
               mov q,al
            end
      end;
   Wait:=q=0
end;
{$endif}
procedure TimeSlice;
begin
   {$ifdef ver70}
   if timer-_ftn_slc>_ftn_cslc then
      begin
         _ftn_slc:=timer;
         wait(1)
      end
   {$endif}
end;
{---------------------------------------------------------------------------}
function RenameF(var pathname:string):string; {***}
var dir:dirstr;
    name:namestr;
    ext:extstr;
    i:byte;
    next:boolean;
    sr:searchrec;
begin
   next:=false;
   while exist(pathname,sr,next) do
      begin
         fsplit(pathname,dir,name,ext);
         while length(ext)<4 do ext:=ext+' ';
         i:=5;
         repeat
            dec(i);
            inc(ext[i]);
            if ext[i]<'0' then ext[i]:='0' else
            if (ext[i]>'9') and (big(ext[i])<'A') then ext[i]:='A' else
            if upcase(ext[i])>'Z' then ext[i]:='0'
         until (ext[i]<>'0') or (i<4);
         pathname:=dir+name+ext;
         next:=false
      end;
   RenameF:=pathname
end;
function Exist(pathname:string;var sr:searchrec;var next:boolean):boolean;
begin
   if next then findnext(sr) else
                findfirst(pathname,anyfile xor hidden xor directory{$ifndef __TMT__} xor volumeid{$endif},sr);
   next:=(doserror=0);
   exist:=next
end;
function Hex(n:long;z:byte):string;
var s:string;
    q:byte;
begin
   s:='';
   repeat
      q:=n and 15;
      n:=n shr 4;
      if q>9 then q:=q+7;
      s:=chr(q+$30)+s;
      dec(z)
   until (n=0) and (z=0);
   hex:=s
end;

function lval(s:string):long;
var code:{$ifdef os2}long{$else}integer{$endif};
    l,k:long;
    i:byte;
begin
   if s='' then s:='-1';
   val(s,l,code);
   if code<>0 then l:=-1;
   lval:=l
end;

function strz(n:long;p:byte):string;
var s:string;
begin
   str(n,s);
   while length(s)<p do s:='0'+s;
   strz:=s
end;

function astr(n:integer):string;
begin
   if n<-9999 then astr:='*' else
   if n<-999 then astr:='????' else
   if n<-99 then astr:='???' else
   if n<-9 then astr:='??' else
   if n<0 then astr:='?' else astr:=strz(n,1)
end;

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
   TimeSlice;
   ReadWord:=s0
end;
{---------------------------------------------------------------------------}
function CodeAddr(adr:tadr;zeropnt:boolean):string;
var s:string;
begin
   with adr do
      begin
         s:=astr(z)+':'+astr(net)+'/'+astr(node);
         if (pnt<>0) or zeropnt then s:=s+'.'+astr(pnt)
      end;
   CodeAddr:=s
end;
{---------------------------------------------------------------------------}
function DecodeAddr(addr:string;var adr:tadr;single:boolean):byte;
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
   with adr do
      begin
         i:=1;
         if pos('.',addr)=0 then addr:=addr+'.0';
         s:=readword(addr,i,[':']); z:=snum;
         if z=-1 then z:=lval(s);
         s:=readword(addr,i,['/']); net:=snum;
         if net=-1 then net:=lval(s);
         s:=readword(addr,i,['.']); node:=snum;
         if node=-1 then node:=lval(s);
         s:=readword(addr,i,['@',#0]); pnt:=snum;
         if pnt=-1 then pnt:=lval(s);
         if single then
            decodeaddr:=ord(z<0)*128+ord(net<0)*64+ord(node<0)*32+ord(pnt<0)*16
                   else
            decodeaddr:=ord(z=-1)*128+ord(net=-1)*64+ord(node=-1)*32+ord(pnt=-1)*16
      end
end;
{---------------------------------------------------------------------------}
function In_Addr(adr:tadr;adrs:string):boolean;
var q:boolean;
    adrm:tadr;
begin
   q:=DecodeAddr(adrs,adrm,false)=0;
   with adrm do
      begin
         if z<0 then q:=q and (adr.z<=-z) else q:=q and (adr.z=z);
         if net<0 then q:=q and (adr.net<=-net) else q:=q and (adr.net=net);
         if node<0 then q:=q and (adr.node<=-node) else q:=q and (adr.node=node);
         if pnt<0 then q:=q and (adr.pnt<=-pnt) else q:=q and (adr.pnt=pnt)
      end;
   In_Addr:=q
end;

function InAddr(adr:tadr;masklst:string):boolean;
var q,r,ni:boolean;
    i:byte;
    adrm:string;
begin
   q:=false;
   i:=1;
   while i<length(masklst) do
      begin
         adrm:=readword(masklst,i,spc);
         ni:=(adrm[1] in nochr);
         if ni then delete(adrm,1,1);
         r:=In_Addr(adr,adrm);
         if ni then q:=q and not r else q:=q or r
      end;
   InAddr:=q
end;
{---------------------------------------------------------------------------}
function AddrCRC32(adr:tadr):long;
var i:byte;
    crc:long;
    s:string;
begin
   crc:=CRC32Init;
   s:=CodeAddr(adr,false); {???}
   for i:=1 to length(s) do crc:=CRC32(ord(s[i]),crc);
   AddrCRC32:=crc
end;

function BinkFile(binkzone:int;var adr:tadr):string;
var s:string;
begin
   with adr do
      begin
         if z=binkzone then s:='\' else s:='.'+hex(z,3)+'\';
         s:=s+hex(net,4)+hex(node,4);
         if pnt<>0 then s:=s+'.PNT\'+hex(pnt,8);
         BinkFile:=s+'.'
      end
end;

function FDFile(var adr:tadr):string;
begin
   FDFile:=hex(AddrCRC32(adr),8)+'.'
end;

function Busy(adr:tadr;DefaultZone:int;bink,fd:boolean):boolean;
var q,next:boolean;
    sr:searchrec;
begin
   next:=false;
   if bink then q:=exist(binkfile(DefaultZone,adr)+'BSY',sr,next);
   if not q and fd then q:=exist(fdfile(adr)+'???',sr,next);
   busy:=q
end;
{---------------------------------------------------------------------------}
function Center(s:string;len:byte):string;
begin
   if length(s)>len then s:=copy(s,1,len);
   while length(s)<len do
      begin
         s:=s+' ';
         if length(s)<len then s:=' '+s
      end;
   center:=s
end;
function Left(s:string;len:byte):string;
begin
   if length(s)>len then s:=copy(s,1,len);
   while length(s)<len do s:=s+' ';
   left:=s
end;
function Right(s:string;len:byte):string;
begin
   if length(s)>len then s:=copy(s,1,len);
   while length(s)<len do s:=' '+s;
   right:=s
end;
function LowCase(c:char):char;
begin
   case c of
      'A'..'Z': c:=chr(ord(c)+32);
      else c:=c
   end;
   LowCase:=c
end;
function Lower(s:string):string;
var i:byte;
begin
   for i:=1 to length(s) do s[i]:=lowcase(s[i]);
   lower:=s
end;
function Big(s:string):string;
var i:byte;
begin
   for i:=1 to length(s) do s[i]:=upcase(s[i]);
   Big:=s
end;
{---------------------------------------------------------------------------}
function XLat(c:char):char;
begin
   if c='' then c:='H' else
   if c='à' then c:='p' else
   if c='ã' then c:='y';
   XLat:=c
end;
procedure Now(var dt:datetime);
var s1:word;
begin
   with dt do
      begin
         getdate(year,month,day,s1);
         gettime(hour,min,sec,s1);
      end
end;
function FtnDate(dt:datetime):string;
var s:string;
    s1:word;
begin
   with dt do
      ftndate:=strz(day,2)+' '+Mnth[month]+' '+strz(year-1900,2)+right(strz(hour,2),4)+':'+strz(min,2)+':'+strz(sec,2)
end;
procedure CreatePktHdr(fpkt,topkt:tadr;sdat:long;var pkthdr:tpkthdr);
var dt:datetime;
    s1:word;
    i:byte;
begin
   with pkthdr do
      begin
         pkttype:=2;
         with dt do
            begin
               getdate(year,month,day,s1);
               gettime(hour,min,sec,s1);
               minute:=min; second:=sec
            end;
         year:=dt.year; month:=dt.month; day:=dt.day; hour:=dt.hour;
         baud:=0;
         with topkt do
            begin
               destNode:=node;
               destNet:=net;
               destZone:=z;
               dest_Zone:=z;
               destPoint:=pnt
            end;
         with fpkt do
            begin
               origNode:=node;
               origNet:=net;
               origZone:=z;
               orig_Zone:=z;
               origPoint:=pnt;
               AuxNet:=net
            end;
         Specific_Data:=sdat;
         for i:=1 to 8 do password[i]:=#0;
         ProductCode_Lo:=$fe;
         ProductCode_Hi:=0;
         Revision_Maj:=0;
         Revision_Min:=ftnrev;
         CapabilWord:=1;
         CWvalidationCopy:=hi(CapabilWord)+lo(CapabilWord) shl 8
      end
end;
{---------------------------------------------------------------------------}
procedure Str2Array(s:string;var a:array of char);
var i,j:byte;
begin
   j:=high(a);
   for i:=0 to j-1 do
      if i<length(s) then a[i]:=xlat(s[i+1])
                     else a[i]:=#0;
   a[j]:=#0
end;
procedure CreateMsgHdr(_from,_to,_subj,_dt:string;fadr,toadr:tadr;atr:wrd;var msghdr:tmsghdr);
var i:byte;
begin
   with msghdr do
      begin
         Str2Array(_from,from);
         Str2Array(_to,to_);
         Str2Array(_subj,subj);
         Str2Array(_dt,datetim);
         timesread:=0;
         replyto:=0;
         nextreply:=0;
         cost:=0;
         attr:=atr;
         with fadr do
            begin
               orignode:=node;
               orignet:=net;
               origpoint:=pnt;
               origzone:=z
            end;
         with toadr do
            begin
               destnode:=node;
               destnet:=net;
               destpoint:=pnt;
               destzone:=z
            end
      end
end;
function Kludges(fadr,toadr:tadr;msgid,msgidr:long;area,pid:string):string;
var s:string;
begin
   area:=big(area);
   if (area='') or (area='NETMAIL') then
      begin
         s:=#1'INTL '+CodeAddr(toadr,false)+' '+CodeAddr(fadr,false)+#13;
         with fadr do  if pnt<>0 then s:=s+#1'FMPT '+strz(pnt,1)+#13;
         with toadr do if pnt<>0 then s:=s+#1'TOPT '+strz(pnt,1)+#13;
      end
              else
      begin
         s:='AREA:'+area+#13;
      end;
   s:=s+#1'MSGID: '+CodeAddr(fadr,false)+' '+lower(hex(msgid,8))+#13;
   if msgidr<>0 then s:=s+#1'REPLY: '+CodeAddr(toadr,false)+' '+lower(hex(msgidr,8))+#13;
   if pid<>'' then s:=s+#1'PID: '+pid+#13;
   Kludges:=s
end;
function MsgExport(var txt:text;var f:file):boolean;
var s:string;
    i,j:byte;
    k:word;
    a:array[1..256] of char;
begin
   MsgExport:=false;
   {$I-}
   reset(txt);
   {$I+}
   if ioresult<>0 then exit;
   while not eof(txt) do
      begin
         readln(txt,s);
         j:=length(s);
         for i:=1 to j do a[i]:=xlat(s[i]);
         inc(j);
         a[j]:=#13;
         blockwrite(f,a,j,k);
         if k<>j then break
      end;
   if k=j then
      begin
         i:=0; j:=1;
         blockwrite(f,i,j,k)
      end;
   {$I-}
   close(f);
   {$I+}
   if ioresult<>0 then k:=j+1;
   {$I-}
   close(txt);
   {$I+}
   if ioresult<>0 then k:=j+1;
   MsgExport:=(k=j)
end;
{---------------------------------------------------------------------------}
begin
   {$ifdef ver70}
   _ftn_os2:=lo(DosVersion)=$14;
   if _ftn_os2 then _ftn_cslc:=os2slice
               else _ftn_cslc:=vdmslice;
   {$endif}
end.
