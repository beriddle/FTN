(*****************************************************************************
 * T-LAN - Universal Log Analyser
 *
 * $Id: os2sup.pas,v 0.34.11 2000/11/19 00:08:00 riddle Exp $
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

unit os2sup;

interface

uses os2base,os2def;

var network:boolean;

function GetStt(var buf:array of longint):word;
function DrvStat(drv:char):word;

implementation

function DrvStat(drv:char):word;
var ps:pchar;
    act,rc,f:longint;
    s:string;
    p:array[0..2] of char;
    q:pchar;
begin
   p[0]:=drv; p[1]:=':'; p[2]:=#0;
   q:=p;
   rc:=DosOpen(q,f,act,0,0,1,$0000A040,nil);
   if rc=0 then DosClose(f);
   DrvStat:=rc
end;

function GetStt(var buf:array of longint):word;
begin
   GetStt:=DosQuerySysInfo(11,14,buf,4*4)
end;

end.
