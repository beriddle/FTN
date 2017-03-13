(*****************************************************************************
 * T-LAN - Universal Log Analyser
 *
 * $Id: support.pas,v 0.34.11 2000/11/19 00:08:00 riddle Exp $
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
{.$define release}
{$N+,E+}
unit support;

interface

uses dos,lng,copyfile{$ifdef virtualpascal},use32,vputils,vpsyslow{$endif}{$ifdef os2},os2sup{$endif};

type soc=set of char;
const FilesBBS='Files.Bbs';
      dlcmask={$ifndef ver70}'*'{$else}'*.*'{$endif};
      Mnth:array[1..12] of string[3]=
     ('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec');
      days:array[1..12] of byte=(31,28,31,30,31,30,31,31,30,31,30,31);
      {For date/time}
      spc=[#9,' '];
      MTask=255;
      MMlr=300;
      ZyzL=24;
      MlrL=50;
      MaxLogs=256;
      rpt=8;
      let:string[rpt]='tagfcdsm';
{---------------------------------------------------------------------------}
      _C:soc=['0'..'9','A'..'Z','a'..'z','!','#'..')','-','_','@','`','~','^'];
      NRkw=30;
      Rkw=9;
      KeyWrd:array[1..NRkw+Rkw] of string[91]=
     ('language @n','registername @s','dirlist @n nobackup',
      'kill total,summary,graphic,filelist,cps,disk,sysop,mailer',
      'selflog @n none,tiny,normal,debug','log @n cut,kill,renext,renlog,backup @l @l',
      'disk @w free,used','nodes @a.','period @t',
      'area @e pvt,cra,rcv,snt,att,trs,orp,k/s,loc,hld,U,frq,rrq,rrc,arq,urq',
      'areapath @p','frompkt @a','frommsgid @a','topkt @a @s',
      'total hidedetails,hideexternals,hidefailures,filecps,protected',
      'summary hideexternals,hidefailures,filecps,protected','graphic wide,fake,space,skip',
      'filelist @w sizepkt,sizearc,sizetic,sizefiles,hidepkt,hidearc,hidetic,hidefiles,hideskipped',
      'cps reverse,avg,max,min,addr,top',
      'statistics total,summary,graphic,filelist,cps,disk,sysop,mailer,run,multiline',
      'aliases @n 4d','address @a','output @p','charset @s','sysop wide',
      'zerocounter @s','ignorefiles @s','cutlog @n @l @l','backupdir @p',
      'templates @p',
      'from @s','to @s','subj @s','origin @s',
      'postfiles @l total,summary,graphic,filelist,cps,disk,sysop,mailer',
      'tearline @s','flag @s','twitinfo @s','t-hist @n'
      );
     {@s - string; @n - pathname, @p - path, @a - address group, @e - echotag,
      @t - time period, @w - wildcard, @l - longint}
      items=43;
      c_known:array[1..items] of string[34]=
     ('js-','jr-','zs-','zr-','hs-','hr-', {1..6}
{$ifdef old}
      ' aborted at pos ',' aborted at pos ',{7..8 Janus}
      ' aborted at pos ',' aborted at pos ',{9..10 ZModem}
      ' cancelled at pos ',' cancelled at pos ',{11..12 Hydra}
{$else}
      ' cancelled at pos ',' cancelled at pos ',{7..8 Janus}
      ' cancelled at pos ',' cancelled at pos ',{9..10 ZModem}
      ' cancelled at pos ',' cancelled at pos ',{11..12 Hydra}
{$endif}
      ' requesting ','','',{13..15 Janus,ZModem,Hydra}
      'polling','calling','ring detected:','˛ incoming call:','˛ outgoing call:','˛',{16..21}
      'handshake failure.'{in},'handshake failure.'{out},'handshake:',{22..24}
      'password mismatch: received','password protected session','? unlisted node',{25..27}
      'human caller.','synchronizing system clock.','! running','! running',{28..31}
      'exiting with errorlevel','returned to t-mail with errorlevel',{32..33}
      'leaving terminal emulator','entering terminal emulator'{34..35},
      '','modem reports: <','restoring from crash','trying',{36..39}
      'detected','using','sysop:','starting after normal shutdown'{40..43});
      known_num:array[1..items] of word=
     (0,0,0,0,0,0,
      422,423,
      447,454,
      586,561,
      414,0,0,
      15,16,114,2,17,0,
      3,18,64,
      58,60,56,
      47,74,166,196,
      199,203,
      318,307,
      4,410,227,608,
      40,35,32,228);

type Long=System.LongInt;
     Wrd=System.Word;
     Int=System.Integer;
     TTxtBuf=array[0..0] of char;
     TiLog=record
              s:string[119];
              hilog,lolog:long
           end;
     PiLog=array[1..MaxLogs] of ^TiLog;
     PTxtBuf=^TTxtBuf;
     TAdr=record
             z,net,node,pnt:int
          end;
     language=array[0..255] of string[64];
     TMlr=record
             num:byte;
             name:string[mlrl]
          end;
     AMlr=array[0..MMlr] of TMlr;
     tdbuf=record
              s_size:word;
              s_ver:word;
              sec_clu,bytes_sec,cl_avail,cl_total,
              sec_avail,sec_total,unit_avail,unit_total:longint;
              reserved:array[1..8] of byte;
           end;
     thist=record
              z,net,node,pnt:int;
              tim,online,bin,bout:long;
              fin,fout:byte;
              status:wrd;
              pos1,pos2:long;
              reserv:array[0..63] of char
           end;
     DirList=^DirLst;
     DirLst=record
               s:string;
               p:DirList
            end;
     tblist=^tblst;
     tblst=record
              s:string[80];
              p:tblist
           end;
     tablst=record
               id:wrd;
               st:byte;
               ml:string[mlrl];
               pf,pl:tblist
            end;
     {     0     1
      0 -  Out   In
      1
      2
      3
      4
      5
      6
      7 }
     tknown=array[1..items] of string;

const hrs=sizeof(thist);
      maxbnd=256;

var rdir,pname,twit,radr,fts1:string;
    sdone,bink_log,fle,nolog,nl,no_bak,cutter,ok
    {$ifdef gpm},log_gpm{$endif}
    {$ifdef binkd},log_bnd{$endif}
    {$ifndef os2},fat32,os2{$endif}:boolean;
    log_ren:byte;
    kp:char;
    lilg:pilog;
    home:tadr;
    lang:^language;
    langcnt,loglevel,cslice:byte;
    mlrs:^amlr;
    ddrv:array[0..3] of char;
    dbuf:tdbuf;
    dver,ilg:wrd;
    timeofs,nyd,nym:word;
    lr:file;
    fl,log:text;
    lc,tsl,_tslc:long;
    known:^tknown;
    {$ifdef binkd}
    blist:array[1..maxbnd] of tablst;
    pblist,pbp:^tablst;
    cbidx,nbidx,lbidx:int; {current output, free next, next and last indexes}
    {$endif}
    p_:array[1..rpt] of byte;
    s_,k_,c_:array[1..rpt] of boolean;

const macmax=100;

type tmacro=record
               hash:long;
               value:string[64]
            end;
     tmarr=array[1..macmax] of tmacro;
     tplmode=(_none,_body_div,_body,_print,_end);

var macros:byte;
    tplmod,curtpl:tplmode;
    width,wid:long;
    mtable:^tmarr;
    tpldir:string;

function Crc32Init:long;
function Crc32(b:byte;crc:long):long;
function strcrc32(s:string):long;

function strz(n:long;p:byte):string;
function astr(n:integer):string;
function centernr(s:string;len:byte):string;
function center(s:string;len:byte):string;
function left(s:string;len:byte):string;
function right(s:string;len:byte):string;
function ConvSpc(s:string):string;
function rnd:long;
function Kill(pathname:string):boolean;
function Exist(pathname:string;var sr:searchrec;var next:boolean):boolean;
function Hex(n:long;z:byte):string;
function Date(var offset:word):string;
function Now:string;
function y366(y:int):boolean;
function DTm2Sec(dt:datetime):long;
procedure Sec2DT(time:long;var dt:datetime);
function ShortName(p:string):string;
function PDir(p:string):string;
function LowCase(c:char):char;
function Lower(s:string):string;
function Big(s:string):string;
function Match(mask,filename:string):boolean;
function lval(s:string):long;
procedure Str2Date(date:string;var d,m:word);
procedure Str2Time(time:string;var h,m,s:word);
procedure SkipChr(s:string;var i:byte;term:soc);
function ReadWord(s:string;var i:byte;term:soc):string;
function ReadCtl(ctrl:string):string;
function ReadLng(lngfile:string):boolean;
function CheckNum(s:string;var i:byte;term:soc;lim:byte;var n:int):boolean;
function CheckDT(var s:string):boolean;
function BackDay(var s:string;d0:string):boolean;
function twitinfo(s:string):string;
procedure MlrPos(mlr:string;var k:int);
function DiskInfo(disk:byte;var size,free:comp;var vol:string):boolean;
function supUptime(dw:string):string;
function supOSver:string;
function pg4(j,g4:byte;cs:char):string;
function kbt(l:long):string;
function dos2unix(dt:datetime):long;
procedure unix2dos(x:long;var dt:datetime);
function UnixNow:long;
function CutLog(name,hist:string;himark,lomark:long):boolean;
function nmonth(s0:string):byte;
{$ifdef gpm}
function gpm2tml(s:string):string;
{$endif}
{$ifdef ver70}
Procedure HideCursor;
Procedure ShowCursor;
{$endif}
{$ifdef dlc}
function ProcessFreqList(flst,dlst,zc:string):byte;
procedure InitDLC(s:string;task:int);
{$endif}
procedure InitMyLog(name:string);
procedure WLog(ll:byte;s:string);
procedure CutLogs;
{$ifdef binkd}
procedure bnd2tml_init;
procedure bnd2tml_done;
procedure bnd2tml_put(s:string); {if cbidx=0, returns cbidx}
function bnd2tml_get:string; {if cbidx<>0}
{$endif}
procedure gl_final(var s,s1:string;parts:byte;shift:byte);
function ftnrnd:string;
function Wait(time:long):boolean;
procedure TimeSlice;
procedure WaitSec(sec:word);
{$ifdef ver70}
procedure waitorkey(sec:word);
{$endif}
function timer:longint;
procedure Flag(src:string);
procedure renlog(pathname:string;line:byte);
procedure backuplog(var dir:string;name,backup:string);

procedure MacPut(macro:string;value:string);
function  MacGet(macro:string;var value:string):boolean;
function  TplGet(var f:text;var s:string):boolean;
function  tplmacro(s:string):string;
{Added at 0.34/Alpha-11}
function nyear:word;
{---}

implementation

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

{$ifdef os2}
var vbuf:array[0..3] of long;
{$endif}

function nyear:word;
var y,tmp:word;
begin
   getdate(y,nym,nyd,tmp);
   nyear:=y;
end;

function timer:longint;
var dt:datetime;
    tmp:word;
begin
   with dt do
      begin
         GetDate(year,month,day,tmp);
         GetTime(hour,min,sec,tmp);
         timer:=tmp+100*(sec+60*(min+60*(hour+24*(day+32*(month+12*year)))))
      end
end;

function Crc32Init:long;
begin
   Crc32Init:=$ffffffff
end;

function Crc32(b:byte;crc:long):long;
begin
   Crc32:=Crc32Tab[byte(crc xor longint(b))] xor ((crc shr 8) and $00FFFFFF)
end;

function strcrc32(s:string):long;
var i:byte;
    crc:long;
begin
   crc:=CRC32Init;
   for i:=1 to length(s) do crc:=CRC32(ord(s[i]),crc);
   strCRC32:=crc
end;

function dos2unix(dt:datetime):long;
const daytab:array[0..11] of byte=(31,28,31,30,31,30,31,31,30,31,30,31);
var x,days,hours,y:long;
    i:int;
begin
   y:=24*60*60;
   x:=y*3652; {Convert from 1980 to 1970 base date GMT}
   i:=dt.year-1980;
   x:=x+(i shr 2)*(1461*y);
   x:=x+(i and 3)*(y*365);
   if ((i and 3)<>0) then x:=x+y;
   days:=0;
   i:=dt.month-1; {Add in months}
   while (i>0) do
      begin
         dec(i);
         days:=days+daytab[i]
      end;
   days:=days+dt.day-1;
   if ((dt.month>2) and ((dt.year and 3)=0)) then inc(days); {Currently in leap year}
   hours:=days*24+dt.hour; {Find hours}
   x:=x+hours*3600;
   x:=x+60*dt.min+dt.sec;
   dos2unix:=x
end;
{Added at 0.34/Alpha-11}
function y366(y:int):boolean;
begin
   y366:=(y mod 4=0) and (y mod 400<>0)
end;

procedure unix2dos(x:long;var dt:datetime);
const daytab:array[0..11] of byte=(31,28,31,30,31,30,31,31,30,31,30,31);
begin
   with dt do
      begin
         sec:=x mod 60;
         min:=x div 60 mod 60;
         hour:=x div 3600 mod 24;
         x:=x div 86400;
         year:=1970;
         while (x>=365+ord(y366(year))) do
            begin
               dec(x,365+ord(y366(year)));
               inc(year)
            end;
         month:=1;
         while (x>=daytab[month-1]+ord(y366(year) and (month=2))) do
            begin
               dec(x,daytab[month-1]+ord(y366(year) and (month=2)));
               inc(month)
            end;
         day:=x+1
      end
end;
{----------------------}
function ShortName(p:string):string;
var dir:dirstr;
    name:namestr;
    ext:extstr;
begin
   fsplit(p,dir,name,ext);
   ShortName:=name+ext
end;
function PDir(p:string):string;
var dir:dirstr;
    name:namestr;
    ext:extstr;
begin
   fsplit(p,dir,name,ext);
   PDir:=dir
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
function centernr(s:string;len:byte):string;
begin
   if length(s)>len then s:=copy(s,1,len)
                    else
      begin
         len:=len-(len-length(s)) div 2;
         while length(s)<len do s:=' '+s
      end;
   centernr:=s
end;
function center(s:string;len:byte):string;
begin
   if length(s)>len then s:=copy(s,1,len);
   while length(s)<len do
      begin
         s:=s+' ';
         if length(s)<len then s:=' '+s
      end;
   center:=s
end;
function left(s:string;len:byte):string;
begin
   if length(s)>len then s:=copy(s,1,len);
   while length(s)<len do s:=s+' ';
   left:=s
end;
function right(s:string;len:byte):string;
begin
   if length(s)>len then s:=copy(s,1,len);
   while length(s)<len do s:=' '+s;
   right:=s
end;

function ConvSpc(s:string):string;
var i:byte;
begin
   for i:=1 to length(s) do if s[i]='_' then s[i]:=' ';
   ConvSpc:=s
end;

function pg4(j,g4:byte;cs:char):string;
var k:byte;
    s:string;
begin
   s:=left('',g4);
   for k:=1 to j do
      if k>g4 then
         begin
            s[g4]:='>';
            break
         end
              else s[k]:=cs;
   pg4:=s
end;
function kbt(l:long):string;
var s:string;
    i,b:byte;
begin
   i:=0;
   while l>9999 do
      begin
         inc(i);
         l:=l div 1000
      end;
   case i of
      0: s:='';
      1: s:='k';
      2: s:='m'
   end;
   s:=strz(l,1)+s;
   kbt:=s
end;

function rnd:long;
begin
   rnd:=long(random(65535)) shl 16+random(65535)
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
function Date(var offset:word):string;
var s:string;
    dt:datetime;
    s1:word;
begin
   with dt do
      begin
         getdate(year,month,day,s1);
         gettime(hour,min,sec,s1);
         sec2dt(dtm2sec(dt)+offset,dt);
         s:=strz(day,2)+' '+Mnth[month]+' '+strz(year mod 100,2);
         date:=s+right(strz(hour,2),4)+':'+strz(min,2)+':'+strz(sec,2);
         inc(offset)
      end
end;
function Kill(pathname:string):boolean;
var f:file;
begin
   assign(f,pathname);
   {$I-}
   erase(f);
   {$I+}
   Kill:=ioresult=0
end;

function Exist(pathname:string;var sr:searchrec;var next:boolean):boolean;
begin
   if next then findnext(sr) else
                findfirst(pathname,anyfile xor directory,sr);
   exist:=(doserror=0);
   next:=true
end;

function Now:string;
var dt:datetime;
begin
   with dt do
      begin
         getdate(year,month,day,year);
         gettime(hour,min,sec,year);
         now:=strz(day,2)+'/'+strz(month,2)+' '+strz(hour,2)+':'+strz(min,2)+':'+strz(sec,2)
      end
end;

procedure InitMyLog(name:string);
begin
   nolog:=false;
   if name<>'' then
      begin
         assign(log,name);
         {$I-}
         append(log);
         {$I+}
         if ioresult<>0 then
            begin
               {$I-}
               rewrite(log);
               {$I+}
               nolog:=ioresult<>0;
               if nolog then writeln('[?] ',lang^[Log_1],': ',name)
            end;
         if not nolog then
            begin
               writeln(log);
               close(log)
            end
      end
end;
procedure WLog(ll:byte;s:string);
begin
   if not nolog and (loglevel>=ll) then
      begin
         {$I-}
         append(log);
         {$I+}
         if ioresult<>0 then writeln('[?] ',lang^[Log_2])
                        else
            begin
               writeln(log,now+' '+s);
               close(log)
            end
      end
end;

function DTm2Sec(dt:datetime):long;
begin
   dtm2sec:=dos2unix(dt)
end;

procedure Sec2DT(time:long;var dt:datetime);
begin
   unix2dos(time,dt)
end;

function LowCase(c:char):char;
begin
   case c of
      'A'..'Z': c:=chr(ord(c)+32);
{      'Ä'..'è': c:=chr(ord(c)+32);
      'ê'..'ü': c:=chr(ord(c)+80);
      '': c:='Ò';}
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
function Match(mask,filename:string):boolean;
var i,j:byte;
    pnt:boolean;
begin
   if pos('.',mask)=0 then mask:=mask+'.';
   if mask[length(mask)]='.' then mask:=mask+' ';
   j:=1;
   pnt:=false;
   Match:=true;
   for i:=1 to length(filename) do
      begin
         if (filename[i]=mask[j]) or (mask[j]='?') then inc(j)
                                                   else
            begin
               if mask[j]='*' then
                  begin
                     if filename[i]='.' then
                        begin
                           while mask[j]<>'.' do inc(j);
                           inc(j);
                        end
                                        else
                        if pnt then break else continue
                  end
                              else
                  begin
                     Match:=false;
                     break
                  end
            end;
         pnt:=pnt or (filename[i]='.')
      end
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
procedure Str2Date(date:string;var d,m:word);
begin
   d:=lval(copy(date,1,2));
   m:=lval(copy(date,4,2))
end;
procedure Str2Time(time:string;var h,m,s:word);
begin
   h:=lval(copy(time,1,2));
   m:=lval(copy(time,4,2));
   s:=lval(copy(time,7,2))
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
   ReadWord:=s0
end;
{$ifdef ver70}
Procedure HideCursor; assembler;
asm
   mov ah,1
   mov ch,20h
   int 10h
end;
Procedure ShowCursor; assembler;
asm
   mov ah,1
   mov cx,0607h
   int 10h
end;
{$endif}
function CheckNum(s:string;var i:byte;term:soc;lim:byte;var n:int):boolean;
begin
   n:=lval(readword(s,i,term));
   CheckNum:=not ((n<0) and (n>lim))
end;
function CheckDT(var s:string):boolean;
var i:byte;
    s0:string;
    n,n0,n1:int;
    month,year:word;
begin
   CheckDT:=false;
   i:=1;
   if not checknum(s,i,spc+['.','/'],31,n0) then exit;
   if not (s[i-1] in ['.','/']) then n:=month else
   if not checknum(s,i,spc,12,n) then exit;
   if (n0=0) or (n=0) or ((n=2) and (n0>28+ord(y366(year)))) then exit;
   s0:=strz(n0,2)+'/'+strz(n,2);
   n0:=0; n1:=0;
   if not checknum(s,i,spc+['.',':'],23,n) then exit;
   if (s[i-1] in ['.',':']) then
      begin
         if not checknum(s,i,spc+['.',':'],59,n0) then exit;
         if (s[i-1] in ['.',':']) and not checknum(s,i,spc,59,n1) then exit;
      end;
   s:=s0+' '+strz(n,2)+':'+strz(n0,2)+':'+strz(n1,2);
   CheckDT:=true
end;
function BackDay(var s:string;d0:string):boolean;
var dt:datetime;
    n:int;
    l:long;
begin
   n:=lval(s);
   if (n<0) or ((n=0) and (d0<>'')) then backday:=false else
   with dt do
      begin
         getdate(year,month,day,sec);
         if d0<>'' then
            begin
               str2date(d0,day,month);
               l:=86400*(n-1);
            end
                   else l:=-86400*n;
         hour:=0; min:=0; sec:=0;
         sec2dt(dtm2sec(dt)+l,dt);
         s:=strz(day,2)+'/'+strz(month,2);
         backday:=true
      end
end;
{-------------------------> Added at 0.26/Alpha-6 <-------------------------}
{ /C10    - delete substring '/C10'
  /C10*   - delete all characters after '/C10'
  /C10+10 - delete all characters after '/C10' + 10 chrs
  /C10-10 - delete all characters after 10 chrs before end of '/C10'
  Noncommercial=NC - replace Noncommercial with NC
  (* Added at 0.34/Alpha-4 *)
  /C10-3^10 - delete 10 characters after 3 characters before end of '/C10'
}
function twitinfo(s:string):string;
var i,j,k,l,r:byte;
    m,n,p:int;
    s0,s1,srp:string;
    q,u:boolean;
begin
   i:=1;
   while i<length(twit) do
      begin
         s0:=readword(twit,i,spc);
         s1:=lower(s0);
         l:=length(s1);
         m:=0;
         n:=0;
         srp:='';
         q:=s1[l]='*';
         if q then delete(s1,l,1) else
         if l>1 then
            begin
               r:=pos('^',s1);
               u:=r>0;
               k:=pos('+',s1);
               q:=k>0;
               if not q then
                  begin
                     k:=pos('-',s1);
                     q:=k>0
                  end;
               if q and (k<l) then
                  begin
                     q:=s1[k+1] in ['0'..'9'];
                     if q then
                        begin
                           if r>k then r:=r-k else r:=l-k+1;
                           m:=lval(copy(s1,k,r));
                           q:=abs(m)<100;
                           if q then delete(s1,k,r)
                                else m:=0
                        end
                  end
                              else q:=false;
               r:=pos('^',s1)+1;
               u:=r>1;
               if u then
                  begin
                     u:=s1[r] in ['0'..'9'];
                     if u then
                        begin
                           n:=lval(copy(s1,r,l-r));
                           u:=abs(n)<100;
                           if u then delete(s1,r-1,l-r+1)
                                else n:=0
                        end
                  end;
               if not (q or u) then
                  begin
                     k:=pos('=',s1);
                     q:=k>0;
                     if q then
                        begin
                           srp:=copy(s0,k+1,l-k);
                           delete(s1,k,l-k+1);
                           q:=false
                        end
                  end
            end;
         repeat
            k:=pos(s1,lower(s));
            if k>0 then
               begin
                  l:=length(s);
                  p:=k+length(s1)+m;
                  if p<1 then p:=1;
                  if not u then n:=l-p+1;
                  if q then
                     begin
                        if p<=l then delete(s,p,n)
                     end
                       else
                     begin
                        delete(s,k,length(s1));
                        if srp<>'' then insert(srp,s,k)
                     end;
                  k:=0
               end
         until k=0
      end;
   twitinfo:=s
end;
procedure MlrPos(mlr:string;var k:int);
var i,j,m:int;
    q:boolean;
    ml:tmlr;
begin
   q:=false;
   for i:=0 to k-1 do with mlrs^[i] do
      begin
         q:=name=mlr;
         if q then break
      end;
   if not q then
      begin
         mlrs^[k].num:=0;
         mlrs^[k].name:=mlr;
         i:=k;
         inc(k);
      end;
   inc(mlrs^[i].num);
   for j:=0 to i-1 do with mlrs^[j] do
      if (num<mlrs^[i].num) or ((num=mlrs^[i].num) and (name>mlrs^[i].name)) then {replace}
         begin
            ml:=mlrs^[i];
            for m:=i downto j+1 do mlrs^[m]:=mlrs^[m-1];
            mlrs^[j]:=ml
         end
end;

function ChkName(s:string;add:soc):boolean;
var q:boolean;
    i:byte;
begin
   i:=pos('.',s);
   if i=0 then
      begin
         s:=s+'.';
         i:=pos('.',s)
      end;
   q:=true;
   for i:=1 to length(s) do q:=q and (s[i] in _C+['.']+add);
   chkname:=q
end;
function ChkPath(s:string):boolean;
var q,d,dd,bs:boolean;
    i:byte;
    s0:string;
begin
   i:=0;
   dd:=false;
   repeat
      inc(i);
      s0:=readword(s,i,[':','\']);
      if i<=length(s) then d:=(s[i]=':') else d:=false;
      if d then
         begin
            if dd then q:=false else
               begin
                  q:=(s0=s0[1]) and (upcase(s0[1]) in ['C'..'Z']);
                  if s[i+1]='\' then bs:=true else bs:=false;
                  dd:=true
               end
         end
                  else
      if s0='' then
         begin
            if bs then bs:=false else q:=false
         end
               else q:=chkname(s0,[])
   until not q or (i>=length(s));
   chkpath:=q
end;
function NumStr(l:long;n:byte):string;
var s:string;
    i:byte;
begin
   s:='';
   for i:=1 to n do
      begin
         s:=s+chr(l and $ff);
         l:=l shr 8
      end;
   NumStr:=s
end;
{ kw - read list
  s2 - original list
  fields - fields number
  q - ok/failed
}
function EnumStr(kw,s2:string;var fields:byte;var q:boolean):string;
const delim:set of char=['+',','];
var s0,s4,s5:string;
    e,en,l:byte;
begin
   e:=1;
   s0:='';
   repeat
      s5:=readword(kw,e,delim);
      q:=false;
      l:=1;
      en:=0;
      repeat
         s4:=readword(s2,l,spc+[',']);
         inc(en);
         q:=q or (s5=s4)
      until (s2[l-1]<>',') or q;
      if q then
         begin
            s0:=s0+chr(en or $40*ord(kw[e-1]='+'));
            inc(fields)
         end;
   until not (kw[e-1] in delim) or not q;
   EnumStr:=s0
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
end;

function ReadCtl(ctrl:string):string;
const MySgn=41075;
var ctl:text;
    bin:file;
    s,kw,s0,s1,s2,s3,s4,s5:string;
    i,j,k,l,e,en,fields,task,m:byte;
    lin,code:word;
    z,net,node,pnt,sgn:int;
    q:boolean;
    t:long;

procedure Warning(n:byte);
begin
   writeln('[?] ',Lang^[ReadCtl_1+n-1],' ',Lang^[ReadCtl_7],' ',lin,': "',kw,'"');
end;
begin
   readctl:='';
   assign(ctl,ctrl);
   {$I-}
   reset(ctl);
   {$I+}
   lin:=0;
   if ioresult<>0 then
      begin
         readctl:=Lang^[ReadCtl_1]+' '+big(shortname(ctrl));
         exit
      end;
   assign(bin,rdir+pname+'.bin');
   {$I-}
   rewrite(bin,1);
   {$I+}
   if ioresult<>0 then
      begin
         readctl:=Lang^[ReadCtl_5]+' '+pname+'.BIN';
         exit
      end;
   writeln('[˚] '+Lang^[ReadCtl_2]+' '+big(shortname(ctrl)));
   while not eof(ctl) do
      begin
         readln(ctl,s);
         inc(lin);
         i:=1;
         kw:=lower(readword(s,i,spc+[';']));
         if kw<>'' then
            begin
               if kw[1]='[' then
                  begin
                     t:=lval(copy(kw,2,pos(']',kw)-2));
                     if (t<0) or (t>253) then
                        begin
                           warning(6);
                           t:=MTask
                        end;
                     task:=t;
                     i:=pos(']',kw)+1;
                     kw:=lower(readword(s,i,spc+[';']))
                  end
                            else task:=MTask;
               if kw<>'' then
                  begin
                     q:=false;
                     for k:=1 to nrkw+rkw do
                        begin
                           s1:=KeyWrd[k];
                           q:=pos(kw+' ',s1+' ')=1;
                           if q then break
                        end;
                     if q then
                        begin
                           j:=length(kw)+1;
                           s3:='';
                           fields:=0;
                           repeat
                              s2:=readword(s1,j,spc); {Invalidation string}
                              if s2<>'' then
                                 begin
                                    if s2[1]='@' then
                                       begin
                                          if s2[2]='s' then {Next string/word}
                                             begin
                                                l:=i;
                                                while (s[i]<>';') and (i<length(s)) do inc(i);
                                                if s[i]=';' then dec(i);
                                                while (s[i]=' ') and (i>l) do dec(i);
                                                while (s[l]=' ') and (i>l) do inc(l);
                                                kw:=copy(s,l,i-l+1);
                                             end
                                                       else kw:=readword(s,i,spc+[';']);
                                          s0:=#$80;
                                          if kw<>'' then
                                             begin
                                                q:=false;
                                                case s2[2] of
                                                   's': q:=true;
                                                   'e': q:=ChkName(kw,['/']);
                                                   'n','p': q:=ChkPath(kw);
                                                   'w': if kw<>'' then
                                                           begin
                                                              if (length(s2)=3) and (s2[3]='.') then dec(j,3);
                                                              q:=ChkName(kw,['?','*'])
                                                           end
                                                                  else q:=true;
                                                   'a': if kw<>'' then
                                                           begin
                                                              if (length(s2)=3) and (s2[3]='.') then dec(j,3);
                                                              l:=pos('all',lower(kw));
                                                              if l>0 then
                                                                 begin
                                                                    delete(kw,l,3);
                                                                    insert('*:*/*.*',kw,l)
                                                                 end;
                                                              if (kw[1]='!') or (kw[1]='~') then
                                                                 q:=Decode_Addr(copy(kw,2,length(kw)-1),z,net,node,pnt,false)=0
                                                                                            else
                                                                 q:=Decode_Addr(kw,z,net,node,pnt,false)=0
                                                           end
                                                                  else q:=true;
                                                   't': q:=true;
                                                   'l': begin
                                                           if kw[1]='-' then
                                                              begin
                                                                 delete(kw,1,1);
                                                                 sgn:=-1
                                                              end
                                                                        else sgn:=1;
                                                           t:=lval(kw);
                                                           q:=t<>-1;
                                                           t:=sgn*t;
                                                           s0:=#$81+numstr(t,4)
                                                        end
                                                {$ifdef alpha}
                                                else writeln('[?] Unknown internal check definition')
                                                {$endif}
                                                end
                                             end
                                       end
                                             else {Ennumerated types}
                                       begin
                                          kw:=lower(readword(s,i,spc+[';']));
                                          s0:=EnumStr(kw,s2,fields,q)
                                        end;
                                    if (s0=#$80) and (kw<>'') then s0:=s0+chr(length(kw))+kw;
                                    if not q and (kw<>'') then warning(3); {Invalid assignment}
                                    if (s0<>'') and (s0<>#$80) then
                                       begin
                                          s3:=s3+s0;
                                          if s0[1]>#$7f then inc(fields)
                                       end
                                 end
                           until (s2='') or (kw='');
                           {Save to binary}
                           blockwrite(bin,k,1);
                           blockwrite(bin,fields,1);
                           t:=filepos(bin);
                           blockwrite(bin,s3,length(s3)+1);
                           seek(bin,t);
                           blockwrite(bin,task,1);
                           seek(bin,filepos(bin)+length(s3))
                        end
                          else warning(4) {Invalid keyword}
                  end
            end
      end;
   close(ctl);
   task:=0;
   blockwrite(bin,task,1);
   truncate(bin);
   close(bin)
end;

function ReadLng(lngfile:string):boolean;
var f:file;
    i:integer;
    b,j:byte;
    s:string;
    w:wrd;
    cks,rcks:long;
    q:boolean;
begin
   ReadLng:=false;
   assign(f,lngfile);
   {$I-}
   reset(f,1);
   {$I+}
   cks:=crc32init;
   if ioresult=0 then
      if filesize(f)<memavail then
         begin
            new(lang);
            blockread(f,w,2,i);
            q:=false;
            if (i=2) and (w=lngver) then
               begin
                  langcnt:=0;
                  while not eof(f) do
                     begin
                        blockread(f,b,1,i);
                        if i<>1 then break;
                        if b<>0 then
                           begin
                              inc(langcnt);
                              if b<>255 then
                                 begin
                                    seek(f,filepos(f)-1);
                                    blockread(f,s,b+1,i);
                                    if i<>(b+1) then break;
                                    for j:=1 to b do cks:=crc32(ord(s[j]),cks);
                                    lang^[langcnt]:=s
                                 end
                           end
                                else
                           begin
                              blockread(f,rcks,4,i);
                              if i<>4 then break;
                              q:=(cks=rcks);
                              break
                           end
                     end
               end;
            close(f);
            ReadLng:=q
         end
                            else close(f)
end;
function DiskInfo(disk:byte;var size,free:comp;var vol:string):boolean;
{$ifdef ver70}
var sz,fr:comp;
    sr:searchrec;
function DrvI:boolean; assembler;
asm
   push ds
   pop es
   mov ax,7303h
   mov dx,offset ddrv
   mov di,offset dbuf
   mov cx,44
   int 21h
   xor ax,7300h
   je @1
   mov ax,-1
@1:
end;
begin
   ddrv:=' :\'#0;
   ddrv[0]:=char(disk+$40);
   size:=disksize(disk);
   free:=diskfree(disk);
   vol:='';
   if (size<>-1) and fat32 then
      begin
         if DrvI then with dbuf do
            begin
               sz:=sec_total;
               sz:=sz*bytes_sec;
               fr:=sec_avail;
               fr:=fr*bytes_sec
            end;
         if sz<>0 then
            begin
               size:=sz;
               free:=fr;
               findfirst(ddrv[0]+':\*.*',VolumeId,sr);
               if doserror=0 then vol:=sr.name;
               if length(vol)>8 then delete(vol,9,1);
               if vol='' then vol:='-'
            end
      end;
{$else}
var d:char;
    drvs:driveset;
    dsk:tdrivetype;
{$ifdef os2}
    rc:longint;
{$endif}
begin
   size:=-1;
   free:=-1;
   vol:='';
   GetValidDrives(drvs);
   d:=chr(disk+$40);
   if d in drvs then
      begin
         {$ifdef os2}
         rc:=drvstat(d);
         if (rc=0) or (rc=3) and network then
         {$endif}
            begin
               dsk:=GetDriveType(d);
               size:=SysDiskSizeLong(disk);
               free:=SysDiskFreeLong(disk);
               vol:=getvolumelabel(d);
               if vol='' then
                  case dsk of
                     dtHDFAT:  vol:='(FAT)';
                     dtHDHPFS: vol:='(HPFS)';
                     dtHDNTFS: vol:='(NTFS)';
                     dtHDExt2: vol:='(EXT2)';
                     dtTVFS:   vol:='(TVFS)';
                     dtCDROM:  vol:='(CD-ROM)';
                     dtNovellNet,dtLAN: vol:='(NETWORK)'
                  else vol:='-'
                  end
            end
      end;
{$endif}
   DiskInfo:=size<>-1
end;
function supUptime(dw:string):string;
begin
   {$ifdef os2}
   if GetStt(vbuf)=0 then
      begin
         vbuf[3]:=vbuf[3] shr 1;
         supUptime:=strz(vbuf[3] div 43200000,1)+
         ' '+dw+' '+strz((vbuf[3] mod 43200000) div 1800000,2)+
         ':'+strz(((vbuf[3] mod 43200000) mod 1800000) div 30000,2)+
         ':'+strz((((vbuf[3] mod 43200000) mod 1800000) mod 30000) div 500,2)+
         '.'+strz((((vbuf[3] mod 43200000) mod 1800000) mod 30000) mod 500,3)
      end
   {$else}
   supUptime:=''
   {$endif}
end;
function supOSver:string;
var s:string;
    b:byte;
begin
    {$ifdef os2}
    if GetStt(vbuf)=0 then
       begin
          s:='';
          if vbuf[0]=20 then
             begin
                b:=vbuf[1];
                case b of
                   0..11: s:='2.'+strz(b,1);
                   30..99: s:=strz(b div 10,1)+'.'+strz(b mod 10,1);
                else s:='?.?';
                end;
                supOSver:='OS/2 '+s
             end
       end
                      else supOSver:='Unknown OS';
    {$else}
    b:=hi(dver);
    supOSver:='DOS '+strz(lo(dver),1)+'.'+strz(b,2);
    case lo(dver) of
       5: supOSver:='Windows NT';
       20: begin
              case b of
                 0..11: s:='2.'+strz(b,1);
                 30..99: s:=strz(b div 10,1)+'.'+strz(b mod 10,1);
              else s:='?.?';
              end;
              supOSver:='OS/2 '+s
           end;
    else {Nothing};
    end
    {$endif}
end;

function AdjHist(var lg:file;hist:string;offset:long):boolean;
var f:file;
    i,k:word;
    t:long;
    hr:thist;
    dt:datetime;
    buf:array[1..14] of char;
begin
   adjhist:=false;
   if hist='' then exit;
   k:=filemode;
   filemode:=2;
   assign(f,hist);
   {$I-}
   reset(f,1);
   {$I+}
   if ioresult=0 then
      begin
         seek(f,filesize(f)-hrs);
         blockread(f,hr,hrs,i);
         if i=hrs then with hr do {Checking time}
            begin
               t:=0;
               {$I-}
               seek(lg,pos1);
               {$I+}
               if ioresult=0 then {May be ok}
                  begin
                     blockread(lg,buf,14,i);
                     if i=14 then with dt do
                        begin
                           GetDate(Year,Month,Day,i);
                           Day:=lval(buf[1]+buf[2]);
                           Month:=lval(buf[4]+buf[5]);
                           Hour:=lval(buf[7]+buf[8]);
                           Min:=lval(buf[10]+buf[11]);
                           Sec:=lval(buf[13]+buf[14])+2;
                           t:=dos2unix(dt);
                           adjhist:=(tim=t);
                           if tim=t then {T-Hist.$?? ok}
                              begin
                                 seek(f,2);
                                 while not eof(f) do
                                    begin
                                       blockread(f,hr,hrs,i);
                                       seek(f,filepos(f)-hrs);
                                       dec(pos1,offset);
                                       dec(pos2,offset);
                                       if pos1<0 then pos1:=0;
                                       if pos2<0 then pos2:=0;
                                       blockwrite(f,hr,hrs,i)
                                    end
                              end
                                    else {T-Hist.$?? damaged, reindex needed}
                              begin
                                 {Not applied yet}
                              end
                        end
                  end;
               {$I-}
               close(f);
               {$I+}
               if ioresult<>0 then writeln('[?] Can''t close ',hist)
            end
      end;
   filemode:=k
end;

procedure LogBack(name:string;var himark,lomark:long);
const mbf=128;
var f:file;
    k,i:word;
    j,l:byte;
    bf:array[1..mbf] of char;
    s,s0,s1:string;
begin
   k:=filemode;
   filemode:=$42;
   s:=strz(-himark,1);
   himark:=0;
   lomark:=0;
   assign(f,name);
   {$I-}
   reset(f,1);
   {$I+}
   if ioresult=0 then
      begin
         BackDay(s,'');
         wlog({$ifndef release}3{$else}4{$endif},'Looking for '+s);
         s:=s[4]+s[5]+s[1]+s[2];
         s0:='';
         repeat
            blockread(f,bf,mbf,i);
            if i>0 then
               begin
                  if (255-length(s0))<i then delete(s0,1,i);
                  for j:=1 to i do s0:=s0+bf[j];
                  repeat
                     j:=pos(#10,s0);
                     if j=0 then break;
                     delete(s0,1,j);
                     l:=length(s0);
                     if l<9 then break;
                     if (s0[2]=' ') and (s0[5]=' ') and (s0[9]=' ') then {Binkstyle log}
                        begin
                           bink_log:=true;
                           s1:=strz(nmonth(s0[6]+s0[7]+s0[8]),2)+s0[3]+s0[4]
                        end
                                                                    else
                        begin {T-Mail-style log}
                           bink_log:=false;
                           if s0[3]<>'/' then break;
                           s1:=s0[4]+s0[5]+s0[1]+s0[2]
                        end;
                     if ((copy(s1,1,2)='11') or (copy(s1,1,2)='12')) and ((copy(s,1,2)='01') or (copy(s,1,2)='02')) then
                        begin
                           s1:='98'+s1;
                           s:='99'+s
                        end;
                     if s1>=s then
                        begin
                           himark:=filepos(f)-l-2;
                           lomark:=filesize(f)-himark;
                           wlog({$ifndef release}3{$else}4{$endif},'Found at 0x'+hex(himark,8)+' - 0x'+hex(lomark,8));
                           i:=0
                        end
                  until (i=0)
               end
         until (i=0) or eof(f);
         close(f)
      end;
   filemode:=k
end;
function CutLog(name,hist:string;himark,lomark:long):boolean;
const maxlbuf=8192;
type tlbuf=array[1..maxlbuf] of byte;
var f,f1:file;
    lbuf:tlbuf;
    sr:searchrec;
    next:boolean;
    offs,fs0,fs1:long;
    i,j:word;
    b:byte;
    q:boolean;
begin
   cutlog:=false;
   wlog(3,'Processing '+name);
   q:=himark<=0;
   if q then LogBack(name,himark,lomark);
   if (himark>1) and (lomark>0) then
      begin
         if not q then {Kbytes}
            begin
               himark:=himark*1024;
               lomark:=lomark*1024
            end
      end
                                                    else exit;
   next:=false;
   if exist(name,sr,next) then
      begin
         if sr.size>=himark then
            begin
               assign(f,name);
               {$I-}
               reset(f,1);
               {$I+}
               if ioresult=0 then
                  begin
                     fs0:=filesize(f);
                     assign(f1,pdir(name)+'tmplog.tmp');
                     {$I-}
                     rewrite(f1,1);
                     {$I+}
                     if ioresult=0 then
                        begin
                           seek(f,filesize(f)-lomark);
                           while not eof(f) do {seek eol}
                              begin
                                 blockread(f,b,1,i);
                                 if b=10 then break
                              end;
                           offs:=filepos(f);
                           if not ({$ifdef gpm}log_gpm or {$endif}bink_log) then AdjHist(f,hist,offs);
                           seek(f,offs);
                           repeat
                              blockread(f,lbuf,maxlbuf,i);
                              if i>0 then blockwrite(f1,lbuf,i,j)
                                     else j:=0;
                              if i<>j then
                                 begin
                                    close(f1);
                                    close(f);
                                    {$I-}
                                    erase(f1);
                                    {$I+}
                                    if ioresult<>0 then {Nothing};
                                    exit
                                 end;
                           until (i<maxlbuf) or eof(f);
                           fs1:=filesize(f1);
                           close(f1)
                        end;
                     close(f);
                     {$I-}
                     erase(f);
                     {$I+}
                     if ioresult=0 then rename(f1,name);
                     wlog(3,'Ok: '+strz(fs0 div 1024,1)+'K -> '+strz(fs1 div 1024,1)+'K');
                     cutlog:=true
                  end
                             else wlog(3,'Can''t open')
            end
                            else wlog(3,'Too short to cut')
      end
                          else wlog(3,'Not found')
end;

function nmonth(s0:string):byte;
var i:byte;
begin
   for i:=1 to 12 do if s0=mnth[i] then break;
   nmonth:=i
end;
function bdt2tdt(s:string):string;
begin
   bdt2tdt:=copy(s,3,2)+'/'+strz(nmonth(copy(s,6,3)),2)+copy(s,9,10)
end;
{$ifdef gpm}
function gpm2tml(s:string):string;
var i,l:byte;
    s0,s1,s2,s3:string;
    c:char;
begin
   s1:='';
   sdone:=true;
   l:=length(s)+1;
   s2:=copy(s,24,l-24);
   s0:=bdt2tdt(s);
   if pos('Password protected session',s2)=1 then s1:=known^[26] else
   if pos('Sysop',s2)=1 then s1:=known^[42]+copy(s,30,l-30) else
   if pos('Incoming call: ',s2)=1 then s1:=known^[19]+copy(s,39,l-39) else
   if pos('Outgoing call: ',s2)=1 then s1:=known^[20]+copy(s,39,l-39) else
   if s[1]='>' then s1:='˛ '+s2 else
   if pos('Answering. Waiting for carrier.',s2)=1 then s1:=known^[19]+' CONNECT 1' else {Added at 0.31/Alpha-6}
   if (pos('RING detected',s2)=1) or (pos('Ring #',s2)=1) then s1:=known^[18]+' [RING]' else
   if pos('ReceiverSync: ExternMail',s2)=1 then s1:=known^[30] else
   if pos('Human caller',s2)=1 then s1:=known^[28] else
   if pos('Process finished',s2)=1 then s1:=known^[33]+copy(s,56,l-56) else
   if (pos('Password mismatch',s2)=1) or (pos('Password error',s2)=1) then s1:=known^[25] else
   if pos('Main address',s2)=1 then
      begin
         i:=12;
         s1:=known^[27]+readword(s2,i,spc+[',','@'])
      end
                               else
   if pos('Calling',s2)=1 then
      begin
         s1:=known^[17]+copy(s2,8,length(s2)-7);
         i:=pos(']:',s1);
         if i>0 then delete(s1,i+1,1)
                else
           begin
              i:=pos(': ',s1); delete(s1,i,1);
              insert(' [0]',s1,i);
           end;
         i:=pos(' [',s1); insert(',',s1,i)
      end
                          else
   if (pos('Call cancelled',s2)=1) or (pos('rings, no answer',s2)>0) then s1:=known^[37]+'NO CARRIER>' else
   if pos('Remote address',s2)=1 then
      begin
         radr:=copy(s,40,l-40)+', '+known^[41]+' ';
         sdone:=fts1<>'';
         if sdone then s1:=radr+fts1
      end
                                 else
   if pos('FTS-0001',s2)=1 then
      begin
         fts1:=s2;
         sdone:=false
      end
                           else
   if pos('Remote software',s2)=1 then s1:=radr+copy(s,41,l-41) else
   if s[1] in ['-','+'] then {File xfer}
      begin
         s3:='';
         c:='Z';
         if pos('DZA',s2)=1 then s3:=',Dir,8k' else
         if pos('ZAP',s2)=1 then s3:=',Zap,8k' else
         if pos('ZMO',s2)=1 then s3:=',1k' else
         if (pos('HYD',s2)=1) or (pos('JAN',s2)=1) then c:=s2[1];
         i:=12;
         s1:=c+s2[7]+'-'+copy(s2,4,2)+s3+' '+readword(s2,i,[','])+' ';
         inc(i);
         s3:=readword(s2,i,[',']); {Size}
         s1:=s1+s3+' ';
         inc(i);
         s1:=s1+copy(s2,i,length(s2)-i+1);
         i:=pos(' cancelled at ',s1);
         if i>0 then
            begin
               delete(s1,i,14);
               insert(known^[7],s1,i);
               i:=pos(':',s1);
               delete(s1,i,length(s1)-i+1)
            end;
         i:=pos(': 0:00,',s1);
         if i>0 then
            begin
               delete(s1,i,7);
               insert(': 0:01,',s1,i)
            end
      end
                        else
   if pos('Establishing',s2)=1 then
      begin
         i:=14;
         s1:=known^[24]+' EMSI, protocol: '+readword(s2,i,spc)+','
      end
                               else
   if (pos('Handshake failed',s2)=1) or (pos('Timeout. No carrier.',s2)=1) or
      (pos('Answer cancelled',s2)=1) then s1:=known^[22] else
   if pos('External mailer session completed',s2)=1 then s1:=known^[33] else
   if pos('External mailer session',s2)=1 then s1:=known^[40] else
   if (s[1]='=') and ((pos('NO ',s2)=1) or (pos('BUSY',s2)=1) or
      (pos('CARRIER',s2)>0) or (pos('CONNECT',s2)>0)) then s1:=known^[37]+s2+'>' else sdone:=false;
   if sdone then gpm2tml:=s0+s1 else gpm2tml:=''
end;
{$endif}
{$ifdef dlc}
procedure zcpos(zc:string;var x,l:byte);
var i,j:byte;
begin
   for i:=1 to length(zc) do if zc[i] in ['0'..'9'] then break;
   for j:=i to length(zc) do if not (zc[j] in ['0'..'9']) then break;
   x:=i;
   l:=j-i;
   if l=0 then x:=0
end;

procedure UpdateFilesBBS(fbbs,name,zc:string);
var io,x,l,i,j:byte;
    n:word;
    fb,ft,fba:text;
    s,s0,s1,s2:string;
    q:boolean;
begin
   assign(fb,fbbs);
   {$I-}
   reset(fb);
   {$I+}
   io:=ioresult;
   if io=0 then
      begin
         s:=copy(fbbs,1,length(fbbs)-3);
         assign(ft,s+'tmp');
         {$I-}
         rewrite(ft);
         {$I+}
         io:=ioresult;
         if io=0 then
            begin
               q:=false;
               while not eof(fb) do
                  begin
                     readln(fb,s0);
                     if pos(big(name),big(s0))=1 then
                        begin
                           q:=true;
                           i:=1;
                           s1:=readword(s0,i,spc);
                           skipchr(s0,i,spc);
                           if i>length(s0) then
                              begin
                                 if not (s0[i-1] in spc) then s0:=s0+' ';
                                 while length(s0)<13 do s0:=s0+' ';
                                 i:=length(s0)+1;
                                 s0:=s0+zc
                              end;
                           j:=i; {First pos. of counter}
                           repeat
                              s2:=readword(s0,i,spc);
                              zcpos(s2,x,l);
                              if x=0 then
                                 begin
                                    i:=j;
                                    insert(zc+' ',s0,i)
                                 end
                           until x<>0;
                           i:=i-j-1; {Counter length}
                           n:=lval(copy(s2,x,l))+1;
                           delete(s0,j+x-1,l);
                           insert(strz(n,l),s0,j+x-1)
                        end;
                     {$I-}
                     writeln(ft,s0);
                     {$I+}
                     io:=ioresult;
                     if io<>0 then
                        begin
                           writeln('[?] Can''t write Files.Tmp! Disk full?');
                           wlog(2,'Can''t write Files.Tmp! Disk full?');
                           break
                        end
                  end;
               close(ft);
               if io<>0 then
                  begin
                     {$I-}
                     erase(ft);
                     {$I+}
                     if ioresult<>0 then {Nothing};
                  end
            end;
         close(fb);
         if io=0 then
            begin
               assign(fba,s+'BAK');
               {$I-}
               erase(fba);
               {$I+}
               if ioresult<>0 then {Nothing};
               {$I-}
               rename(fb,s+'BAK');
               {$I+}
               io:=ioresult;
               if io=0 then
                  begin
                     {$I-}
                     rename(ft,fbbs);
                     {$I+}
                     io:=ioresult;
                     if io<>0 then wlog(3,'Can''t rename Files.Tmp -> Files.Bbs!')
                              else
                        if no_bak then
                           begin
                              {$I-}
                              erase(fba);
                              {$I+}
                              if ioresult<>0 then wlog(3,'Can''t erase Files.Bak')
                           end
                  end
                       else wlog(3,'Can''t rename Files.Bbs -> Files.Bak!');
            end
      end;
   if q then
      begin
         if io=0 then wlog(3,name+', '+fbbs+' updated.')
                 else wlog(3,name+', '+fbbs+' update failed.')
      end
        else wlog(3,name+', not found in '+fbbs)
end;

procedure MkDirList(dir:string;var dls:dirlist);
var sr:searchrec;
begin
   findfirst(dir+dlcmask,directory,sr);
   while doserror=0 do
      begin
         if (sr.attr and directory<>0) and (pos('.',sr.name)<>1) then
            begin
               new(dls^.p);
               dls:=dls^.p;
               dls^.s:=dir+sr.name+'\';
               dls^.p:=nil;
               wlog(4,'+FreqDir '+dls^.s);
               MkDirList(dls^.s,dls)
            end;
         findnext(sr)
      end
end;

procedure MakeDirList(dlst:string;var dls:dirlist);
var dlf:text;
    i:byte;
    s,p:string;
    q:boolean;
begin
   assign(dlf,dlst);
   {$I-}
   reset(dlf);
   {$I+}
   if ioresult=0 then
      begin
         while not eof(dlf) do
            begin
               readln(dlf,s);
               if s<>'' then
                  if s[1]<>';' then
                     begin
                        i:=1;
                        p:=readword(s,i,spc);
                        if pos('freq',lower(p))=1 then {G.P.Mail log}
                           begin
                              q:=pos('tree',lower(p))=5;
                              if not q and (pos('alias',lower(p))=5) then p:=pdir(readword(s,i,spc))
                                                                     else p:=readword(s,i,spc)
                           end
                                                  else q:=false;
                        if p<>'' then
                           begin
                              if p[length(p)]<>'\' then p:=p+'\';
                              if dls^.s<>'' then {New}
                                 begin
                                    new(dls^.p);
                                    dls:=dls^.p;
                                    dls^.p:=nil
                                 end;
                              dls^.s:=p;
                              wlog(4,'FreqDir '+p);
                              if q then MkDirList(p,dls)
                           end
                     end
            end;
         close(dlf)
      end
end;

procedure FreeDirList(dl:dirlist);
var dls:dirlist;
    q:boolean;
begin
   repeat
      dls:=dl;
      q:=dl^.p<>nil;
      if q then dl:=dl^.p;
      dispose(dls)
   until not q
end;

function ProcessFreqList(flst,dlst,zc:string):byte;
var dff:text;
    dl,dls:dirlist;
    sr:searchrec;
    io:byte;
    s,p,name:string;
    q:boolean;
begin
   io:=0;
   if dlst<>'' then
      begin
         writeln('[˚] '+lang^[Main_10]);
         wlog(2,lang^[Main_10]);
         new(dls);
         dl:=dls;
         dls^.s:='';
         dls^.p:=nil;
         MakeDirList(dlst,dls); {dl - store begin}
         assign(dff,flst);
         {$I-}
         reset(dff);
         {$I+}
         io:=ioresult;
         if io=0 then
            begin
               while not eof(dff) do
                  begin
                     readln(dff,s);
                     p:=pdir(s);
                     name:=shortname(s);
                     write(#13'[ ] '+left(name,12));
                     if p<>'' then {Full path, no search nesessary}
                        begin
                           write(#13'[˚');
                           UpdateFilesBBS(p+filesbbs,name,zc)
                        end
                              else
                        if dl^.s<>'' then {Dir.Frq list}
                           begin
                              dls:=dl;
                              repeat
                                 p:=dls^.s;
                                 findfirst(p+name,anyfile,sr);
                                 q:=doserror=0;
                                 if q then
                                    begin
                                       write(#13'[˚');
                                       UpdateFilesBBS(p+filesbbs,name,zc);
                                       break
                                    end;
                                 q:=dls^.p<>nil;
                                 if q then dls:=dls^.p
                              until not q;
                              if not q then
                                 begin
                                    wlog(3,'? '+name+' not found');
                                    write(' ?:'+left(name,12))
                                 end
                           end
                  end;
               close(dff);
               write(#13,'':32,#13)
            end;
         FreeDirList(dl);
         wlog(2,'Done')
      end;
   ProcessFreqList:=io
end;

procedure InitDLC(s:string;task:int);
var code:word;
begin
   if s<>'' then
      begin
         assign(lr,rdir+pname+'.Dlc');
         {$I-}
         reset(lr,1);
         {$I+}
         if ioresult=0 then
            begin
               seek(lr,task*4);
               blockread(lr,lc,4,code);
               close(lr);
               if code<>4 then lc:=0
            end
                       else lc:=0;
         if not fle then
            begin
               {$I-}
               append(fl);
               {$I+}
               fle:=ioresult=0;
               if not fle then
                  begin
                     {$I-}
                     rewrite(fl);
                     {$I+}
                     fle:=ioresult=0
                  end
            end
      end
end;
{$endif}
{$ifdef binkd}
procedure bnd2tml_init;
var i:int;
begin
   nbidx:=1; {Next idx}
   lbidx:=0; {Last idx}
   cbidx:=0; {Current output idx}
   for i:=1 to maxbnd do blist[i].id:=0
end;

procedure bnd2tml_done;
var i:int;
    p:tblist;
    c:char;
begin
   c:=#0;
   for i:=1 to lbidx do with blist[i] do
      if id<>0 then
         begin
            if c=#0 then wlog(3,#$c2' ('+strz(lbidx,1)+'/'+strz(nbidx,1)+') BinkD memory leaks');
            inc(c);
            pl:=pf;
            wlog(3,#$c3' ['+strz(id,1)+']');
            while pl<>nil do
               begin
                  p:=pl;
                  pl:=pl^.p;
                  if pl=nil then c:=#$c0 else c:=#$c3;
                  wlog(3,c+#$c4#$c4' '+p^.s);
                  dispose(p)
               end
         end
end;

function bnd2tml_get:string; {if cbidx<>0}
var s0:string;
    i:int;
    p:tblist;
begin
   s0:='';
   with blist[cbidx] do
      begin
         if id<>0 then {First iterration}
            begin
               id:=0;
               pl:=pf {lastread pointer}
            end;
         if pl=nil then cbidx:=0 {End of batch} else
            begin
               p:=pl;
               s0:=pl^.s;
               pl:=pl^.p;
               dispose(p)
            end
      end;
   bnd2tml_get:=s0
end;

procedure bnd2tml_put(s:string); {if cbidx=0, returns cbidx}
var s0,s1,s2:string;
    cuid:wrd;
    i,l:byte;
    j,k:int;
    q:boolean;
    cps,sz:long;
begin
   s2:='';
   i:=20;
   cuid:=lval(readword(s,i,[']'])); {TaskId}
   l:=length(s)-i;
   inc(i); {First pos of words (???)}
   q:=false;
   for j:=1 to lbidx do with blist[j] do
      begin
         if j=nbidx then continue;
         q:=cuid=id;
         if q then break
              else
            begin
               q:=(st and 1<>0) and (pos('session with',s)=i) and (pos(ml,s)<>0);
               if q then {Incoming call}
                  begin
                     s:=copy(s,1,i-1)+'connected';
                     id:=cuid;
                     ml:='';
                     break
                  end
            end
      end;
   if not q then j:=nbidx;
   s0:='';
   with blist[j] do
      begin
         {Terminators}
         if pos(': unknown host',s)>0 then
            begin
               s0:=known^[37]+'NO ANSWER>';
               cbidx:=j
            end
                                      else
         if (pos('session closed, quitting...',s)=i) or (pos('unable to connect',s)=i) or
            (pos('got signal #',s)=i) or (pos('BEGIN,',s)=i) then cbidx:=j else
            begin
               if pos('connected',s)=i then s0:=known^[20-st and 1]+' CONNECT binkp' else
               if (pos('VER',s)=i) then ml:=copy(s,i+4,l-4) else
               if (pos('addr:',s)=i) and (ml<>'') then
                  begin
                     s0:=copy(s,i+6,l-6)+', '+known^[41]+' '+ml;
                     ml:=''
                  end
                                                  else
               if pos('call to',s)=i then s0:=known^[17]+copy(s,i+7,l-7) else
               if pos('ZYZ',s)=i then s0:=known^[42]+convspc(copy(s,i+3,l-3)) else
               if pos('NDL',s)=i then s0:=known^[24]+' binkp, protocol: binkp,' else
               if pos('pwd protected session',s)=i then s0:=known^[26] else
               if (pos('unexpected password from the remote:',s)=i) or
                  (pos('Bad password',s)=i) or (pos('incorrect password',s)=i) then s0:=known^[25] else
               if (pos('sent:',s)=i) or (pos('rcvd:',s)=i) then
                  begin
                     s0:='j?-16 ';
                     s0[2]:=s[i];
                     inc(i,6);
                     s0:=s0+readword(s,i,spc)+' '; inc(i); {"(" bypass}
                     s1:=readword(s,i,[',']); {size}
                     sz:=lval(s1); if sz<0 then sz:=0;
                     s0:=s0+s1+' OK: ';
                     s1:=readword(s,i,['.']+spc); {cps}
                     cps:=lval(s1); if cps<=0 then cps:=1;
                     sz:=sz div cps;
                     s1:=strz(sz div 60,1)+':'+strz(sz mod 60,2)+', '+strz(cps,1)+' cps';
                     s0:=s0+s1
                  end
                                   else
               if pos('done (',s)=i then
                  begin
                     inc(i,6);
                     while s[i]<>' 'do inc(i);
                     inc(i);
                     s0:='˛ '+readword(s,i,['@',','])+', bytes ';
                     i:=pos('S/R: ',s)+5;
                     while s[i]<>'(' do inc(i);
                     inc(i);
                     s1:=readword(s,i,['/']);
                     s0:=s0+readword(s,i,spc)+'/'+s1+', time 0:00:01'
                  end
                                    else
               if pos('incoming from',s)=i then
                  begin
                     s0:=known^[18]+' [RING]';
                     inc(i,14);
                     s2:=readword(s,i,[#0])
                  end
            end;
         if s0<>'' then
            begin
               if q then
                  begin
                     new(pl^.p);
                     pl:=pl^.p
                  end
                        else {Create new item}
                  begin
                     id:=cuid;
                     ml:=s2;
                     st:=ord(s2<>'');
                     new(pf);
                     pl:=pf;
                     nbidx:=1;
                     while blist[nbidx].id<>0 do inc(nbidx);
                     if nbidx>lbidx then lbidx:=nbidx
                  end;
               pl^.p:=nil;
               pl^.s:=bdt2tdt(s)+s0
            end
      end
end;
{$endif}
function UnixNow:long;
var dt:datetime;
    w:word;
    l:long;
begin
   with dt do
      begin
         getdate(year,month,day,w);
         gettime(hour,min,sec,w);
         l:=dos2unix(dt) and $fff00000;
         unixnow:=l or (l shr 16) or $7000e
      end
end;

procedure CutLogs;
var i:wrd;
begin
   writeln('[˚] '+lang^[Main_11]+' '+strz(ilg,1));
   wlog(2,lang^[Main_11]+' '+strz(ilg,1));
   for i:=1 to ilg do with lilg[i]^ do
      begin
         cutlog(s,'',hilog,lolog);
         dispose(lilg[i])
      end
end;

procedure gl_final(var s,s1:string;parts:byte;shift:byte);
var i,j,z:byte;
begin
   s:='0% ≈';
   s1:=' ';
   shift:=24-shift div parts;
   for i:=0 to 23 do
      begin
         for j:=2 to parts do s:=s+'ƒ';
         s:=s+'¬';
         if i<shift then z:=25-shift+i else z:=i-shift+1;
         if z=24 then z:=0;
         for j:=2 to (parts-ord(z>9)) do s1:=s1+' ';
         if s1[length(s1)]=' ' then s1:=s1+strz(z,1) else s1:=s1+'  '
      end
end;

function ftnrnd:string;
var l:long;
begin
   {$ifdef os2}
   if GetStt(vbuf)=0 then l:=vbuf[3] div 10 else
   {$endif}
   l:=timer;
   inc(l,1708041075);
   inc(l,timeofs);
   ftnrnd:=lower(hex(l,8))
end;

function Wait(time:long):boolean;
var q:byte;
begin
   while time>0 do
      begin
         dec(time);
         {$ifdef ver70}
         asm
            mov ax,1680h
            int 2fh
            mov q,al
         end
         {$endif}
      end;
   Wait:={$ifdef ver70}q=0{$else}false{$endif}
end;
procedure TimeSlice;
begin
   {$ifdef ver70}
   if timer-_tslc>cslice then
      begin
         _tslc:=timer;
         wait(1)
      end
   {$endif}
end;
procedure WaitSec(sec:word);
var tmp:long;
begin
   tmp:=timer;
   while tmp+sec*18>timer do timeslice
end;
{$ifdef ver70}
procedure waitorkey(sec:word);
var z:longint;
    timer:longint absolute $40:$6c;
begin
   z:=timer+sec*18;
   write(lang^[WaitOrKey_1],#13);
   repeat
      asm
         mov ah,0Bh
         int 21h
         cmp al,0
         je @1
         mov ah,8
         int 21h
     @1: mov byte(kp),al
      end
   until (z<timer) or (kp<>#0)
end;
{$endif}
procedure Flag(src:string);
var i,l:byte;
    f:file;
    s,s0:string;
    q:boolean;
begin
   l:=length(src);
   q:=false;
   for i:=1 to rpt do q:=q or (p_[i]>0);
   if (l>0) and ok and q then
      begin
         i:=1;
         s0:='';
         while i<l do
            begin
               s:=readword(src,i,spc+[';']);
               if s0='' then s0:=pdir(s);
               if pdir(s)='' then s:=s0+s;
               wlog(2,'Creating flag '+s);
               assign(f,s);
               {$I-}
               rewrite(f,1);
               {$I+}
               if ioresult=0 then close(f)
                             else wlog(2,'Unable to create')
            end
      end
end;

function doye:string;
var d,m,y,dw:word;
    i:byte;
begin
   getdate(y,m,d,dw);
   dw:=0;
   writeln(d,' ',m,' ',y);
   for i:=1 to m-1 do inc(dw,days[m]);
   inc(dw,d);
   inc(dw,ord((y366(y)) and (m>2)));
   doye:='.'+strz(dw,3)
end;

function doyn:string;
var d,m,y,dw:word;
begin
   getdate(y,m,d,dw);
   doyn:=strz(d,2)+'-'+strz(m,2)+'-'+strz(y mod 100,2);
end;

procedure renlog(pathname:string;line:byte);
var dir:dirstr;
    name:namestr;
    ext:extstr;
    s:string;
    f:file;
begin
   fsplit(pathname,dir,name,ext);
   case log_ren of
      1: s:=dir+name+doye;
      2: s:=dir+doyn+'.L'+hex(line,2)
   end;
   assign(f,pathname);
   {$I-}
   rename(f,s);
   {$I+}
   if ioresult=0 then wlog(3,'renamed '+shortname(pathname)+' -> '+shortname(s))
                 else wlog(2,'Can''t rename '+shortname(pathname)+' -> '+shortname(s))
end;

procedure backuplog(var dir:string;name,backup:string);
var l:byte;
begin
   l:=length(backup);
   if l>0 then
      begin
         if backup[l]<>'\' then backup:=backup+'\';
         l:=coping(dir+name,backup+name,true);
         dir:=fexpand(backup);
         if l=0 then wlog(3,'moved '+name+' -> '+dir)
                else wlog(2,'Can''t move '+name+' -> '+dir)
      end
end;

procedure MacPut(macro:string;value:string);
var l:long;
    i:word;
    q:boolean;
begin
   l:=strcrc32(lower(macro));
   q:=false;
   if macros=0 then new(mtable);
   for i:=1 to macros do
      begin
         q:=mtable^[i].hash=l;
         if q then break
      end;
   if q then mtable^[i].value:=value
        else
      if macros<macmax then
         begin
            inc(macros);
            {$ifndef release}
            if loglevel>3 then writeln('[>] Storing "'+value+'" -> '+macro,' (',macros,')');
            {$endif}
            mtable^[macros].hash:=l;
            mtable^[macros].value:=value
         end
{$ifndef release}
                       else
         writeln('[?] Can''t store value of "'+macro+'"')
{$endif}
end;

function MacGet(macro:string;var value:string):boolean;
var l:long;
    i:word;
begin
   l:=strcrc32(lower(macro));
   value:='("'+macro+'" not found)';
   MacGet:=false;
   for i:=1 to macros do
      begin
         if mtable^[i].hash=l then
            begin
               value:=mtable^[i].value;
               MacGet:=true;
               break
            end
      end
end;

function tplmac(s:string;var p:byte):string;
const cmdw=4;
      cmds:array[1..cmdw] of string[8]=('left','right','centernr','center');
var i,j,k,m:byte;
    q:boolean;
    s0,s1:string;
begin
   j:=p+1;
   while (upcase(s[j]) in ['A'..'Z','0'..'9','.','_']) and (j<=length(s)) do inc(j);
   q:=false;
   s0:=copy(s,p+1,j-p-1); {cmd or macro}
   if s[j]='(' then
      begin
         for m:=1 to cmdw do {function select}
            begin
               q:=pos(cmds[m],lower(s0))=1;
               if q then break
            end;
         if q then
            begin
               inc(j);
               k:=j;
               while (s[k]<>')') and (k<length(s)) do inc(k);
               s0:=copy(s,j+1,k-j-1);
               i:=pos(',',s0);
               if i>2 then
                  begin
                     wid:=lval(copy(s0,i+1,length(s0)-i));
                     s0:=copy(s0,1,i-1);
                     if (wid<1) or (wid>160) then wid:=width
                  end
                      else wid:=width
            end
      end;
   if not q then
      begin
         inc(p,j-p-1);
         m:=0
      end
            else p:=k;
   {$ifndef release}
   if loglevel>3 then write('[>] Get macro: ',s0,' <- ');
   {$endif}
   if MacGet(s0,s1) then s0:=s1;
   case m of
      1: s0:=left(s0,wid);
      2: s0:=right(s0,wid);
      3: s0:=centernr(s0,wid);
      4: s0:=center(s0,wid);
   else {nothing};
   end;
   tplmac:=s0
end;

function tplmacro(s:string):string;
var s1:string;
    i:byte;
begin
   s1:='';
   for i:=1 to length(s) do
      if s[i]<>'@' then s1:=s1+s[i]
                   else s1:=s1+tplmac(s,i);
   tplmacro:=s1
end;

{ Returns: true if this type of record continues, false - if absent or finish }
function TplGet(var f:text;var s:string):boolean;
var i:byte;
    q:boolean;
    s0,s1:string;
begin
   s:='';
   q:=false;
   while not eof(f) do
      begin
         if q then
            begin
               s0:=s;
               q:=false
            end
              else s0:='';
         readln(f,s);
         s1:=lower(s);
         if (tplmod=_print) and (s='') then {insert empty lines}
            begin
               if s0<>'' then s:=s0+#13#10;
               break
            end;
         if (s<>'') and (s[1]<>';') then {not comment}
            begin
               if pos('%width ',s1)=1 then
                  begin
                     i:=8;
                     width:=lval(readword(s,i,spc));
                     if (width<1) or (width>160) then width:=78
                  end
                                      else
                  begin
                     while s[length(s)] in spc do delete(s,length(s),1); {skip right spaces}
                     q:=s[length(s)]='\'; {continue flag}
                     if q then delete(s,length(s),1);
                     if pos('%print',s1)   =1 then tplmod:=_print else
                     if pos('%body.div',s1)=1 then tplmod:=_body_div else
                     if pos('%body',s1)    =1 then tplmod:=_body else
                     if pos('%end',s1)     =1 then tplmod:=_end else
                     if not q and (s[1]='%') then {User defined variables}
                        begin
                           i:=2;
                           s1:=readword(s,i,spc);
                           if i<=length(s) then MacPut(s1,copy(s,i,length(s)-i+1))
                        end
                                 else
                        begin
                           s:=s0+s;
                           if not q and (tplmod<>_none) then break
                        end;
                     TplGet:=curtpl=tplmod
                  end
            end
      end;
   if eof(f) then
      begin
         tplmod:=_end;
         s:='';
         s0:='';
         TplGet:=false
      end;
   curtpl:=tplmod
end;

begin
   macros:=0;
   width:=78;
end.
