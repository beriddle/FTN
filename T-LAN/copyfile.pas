(*****************************************************************************
 * T-LAN - Universal Log Analyser
 *
 * $Id: copyfile.pas,v 0.34.11 2000/11/19 00:08:00 riddle Exp $
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

unit copyfile;

interface

uses dos{$ifndef ver70},use32,strings{$endif}{$ifdef os2},os2base,os2def{$endif};

function Coping(finame,foname:string;kill:boolean):word;

implementation

function Coping(finame,foname:string;kill:boolean):word;
{$ifndef os2}
const n=8192;
type tbuf=array[1..n] of byte;
var fi,fo:file;
    t:longint;
    i,j:word;
    io:byte;
    q:boolean;
    buf:^tbuf;
{$else}
var ps0,ps1:pchar;
    rc:longint;
{$endif}
begin
   {$ifndef os2}
   assign(fi,finame);
   assign(fo,foname);
   {$I-}
   reset(fi,1);
   {$I+}
   io:=ioresult;
   if io=0 then
      begin
         {$I-}
         rewrite(fo,1);
         {$I+}
         io:=ioresult;
         if io=0 then
            begin
               getftime(fi,t);
               close(fo);
               setfattr(fo,hidden);
               reset(fo,1);
               new(buf);
               repeat
                  blockread(fi,buf^,n,i);
                  if i>0 then
                     begin
                        blockwrite(fo,buf^,i,j);
                        q:=(i=j)
                     end
                         else q:=true
               until (i<n) or not q;
               dispose(buf);
               close(fo);
               reset(fo,1); {HPFS bug workaround}
               setftime(fo,t);
               close(fo);
               setfattr(fo,archive)
            end;
         close(fi)
      end;
   if (io=0) and not q then
      begin
         {$I-}
         erase(fo);
         {$I+}
         if ioresult<>0 then {Nothing};
         Coping:=1
      end
                       else
      begin
         if (io=0) and kill then
            begin
               {$I-}
               erase(fi);
               {$I+}
               io:=ioresult
            end;
         Coping:=io
      end;
   {$else}
   finame:=fexpand(finame);
   foname:=fexpand(foname);
   getmem(ps0,length(finame)+1); strpcopy(ps0,finame);
   getmem(ps1,length(foname)+1); strpcopy(ps1,foname);
   if kill and (finame[1]=foname[1]) then
      begin
         rc:=DosDelete(ps1);
         rc:=DosMove(ps0,ps1)
      end
                                     else
      begin
         rc:=DosCopy(ps0,ps1,1);
         if (rc=NO_ERROR) and kill then rc:=DosDelete(ps0)
      end;
   freemem(ps0,length(finame)+1);
   freemem(ps1,length(foname)+1);
   Coping:=rc
   {$endif}
end;

end.
