(*****************************************************************************
 * T-LAN - Universal Log Analyser
 *
 * $Id: t-lngcmp.pas,v 0.34.11 2000/11/19 00:08:00 riddle Exp $
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

uses ftn;

const ll=13;

var src,incl:text;
    f:file;
    s,s0,s1,s2,s3,s4,fn,fl:string;
    i,j,n,cnt:byte;
    lngsize,lin,lngwrds,lngver:word;
    code:integer;
    timer:longint absolute $0040:$006C;
    tmp,cks:longint;
    LngFile:array[1..255] of byte;

procedure help;
begin
   writeln('Usage: T-LNGCMP <VERSION> <T-LAN.LAN> [T-LAN.LNG]');
   halt(1)
end;
function strz(n:longint;p:byte):string;
var s:string;
begin
   str(n,s);
   while length(s)<p do s:='0'+s;
   strz:=s
end;
function Sum_(n:byte):word;
var i,j:byte;
begin
   i:=0;
   for j:=1 to n do inc(i,LngFile[j]);
   Sum_:=i;
end;
begin
   writeln('T-LAN language file compiler 0.23.0 (C) 22-May-98 Vitaly Lunyov');
   if (paramcount<2) or (paramcount>3) then help;
   val(paramstr(1),lngver,code);
   if code<>0 then help;
   fn:=paramstr(2);
   assign(src,fn);
   {$I-}
   reset(src);
   {$I+}
   if ioresult<>0 then help;
   if paramcount=3 then fl:=paramstr(3) else fl:='T-LAN.LNG';
   assign(f,fl);
   assign(incl,'T-LNG.INC');
   rewrite(incl);
   rewrite(f,1);
   s4:='{Nothing}';
   cnt:=0;
   n:=0;
   lin:=0;
   cks:=crc32init;
   lngwrds:=0;
   tmp:=timer;
{   i:=$18;
   blockwrite(f,i,1);}
   blockwrite(f,lngver,2);
   while not eof(src) do
      begin
         readln(src,s);
         inc(lin);
         if lin mod ll=1 then write(#13,fn,'(',lin,')');
         if (s<>'') and (s[1]<>';') then
            begin
               i:=1;
               while not (s[i] in [#9,' ']) do inc(i);
               s0:=copy(s,1,i-1); {Field ID with num}
               j:=i;
               while s[j]<>'_' do dec(j);
               s2:=copy(s,j+1,i-j-1); {Field num}
               s3:=copy(s,1,j); {Field ID}
               while s[i] in [#9,' '] do inc(i);
               s1:=copy(s,i,length(s)-i+1); {Variable contents}
               inc(cnt);
               if s1='.' then s1:='';
               j:=length(s1);
               for i:=1 to j do cks:=crc32(ord(s1[i]),cks);
               dec(j);
               if j<>255 then blockwrite(f,s1,j+2) else blockwrite(f,j,1);
               if s4<>s3 then
                  begin
                     if (cnt>0) and (n>0) then LngFile[n]:=cnt;
                     inc(lngwrds);
                     s4:=s3;
                     writeln(incl,'function ',s4,'(n:byte):string;');
                     writeln(incl,'begin');
                     writeln(incl,'   ',s4,':=Lang^[',Sum_(n),'+n]');
                     writeln(incl,'end;');
                     writeln(incl);
                     cnt:=0;
                     inc(n)
                  end
            end
      end;
   close(src);
   writeln(incl,'Const LngWrds=',lngwrds,';');
   close(incl);
   i:=0;
   blockwrite(f,i,1);
   blockwrite(f,cks,4);
   writeln(#13,fn,'(',lin,')');
   writeln(lin,' lines,',((timer-tmp)/18):4:1,' seconds, ',filesize(f),' bytes data.');
   close(f)
end.
