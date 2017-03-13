(*****************************************************************************
 * T-LAN - Universal Log Analyser
 *
 * $Id: lng.pas,v 0.34.11 2000/11/19 00:08:00 riddle Exp $
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

unit lng;

interface

Const LngVer=3102;

      Code_Addr_1=1;
      Code_Addr_2=2;
      Code_Addr_3=3;
      Code_Addr_4=4;

      Imp_File_1=5;
      Imp_File_2=6;

      Poster_1=7;
      Poster_2=8;

      WaitOrKey_1=9;

      Macro_1=10;

      Fill_Known_1=11;
      Fill_Known_2=12;

      Count_Stat_1=13;

      Total_1=14;
      Total_2=15;
      Total_3=16;
      Total_4=17;
      Total_5=18;
      Total_6=19;
      Total_7=20;
      Total_8=21;
      Total_9=22;
      Total_10=23;
      Total_11=24;
      Total_12=25;
      Total_13=26;
      Total_14=27;
      Total_15=28;
      Total_16=29;
      Total_17=30;
      Total_18=31;
      Total_19=32;
      Total_20=33;
      Total_21=34;
      Total_22=35;
      Total_23=36;
      Total_24=37;
      Total_25=38;
      Total_26=39;
      Total_27=40;
      Total_28=41;
      Total_29=42;
      Total_30=43;
      Total_31=44;

      Overall_1=45;
      Overall_2=46;
      Overall_3=47;
      Overall_4=48;
      Overall_5=49;
      Overall_6=50;
      Overall_7=51;
      Overall_8=52;
      Overall_9=53;
      Overall_10=54;
      Overall_11=55;
      Overall_12=56;
      Overall_13=57;
      Overall_14=58;
      Overall_15=59;
      Overall_16=60;
      Overall_17=61;
      Overall_18=62;
      Overall_19=63;
      Overall_20=64;
      Overall_21=65;
      Overall_22=66;
      Overall_23=67;

      Filelist_1=68;
      Filelist_2=69;
      Filelist_3=70;
      Filelist_4=71;
      Filelist_5=72;
      Filelist_6=73;
      Filelist_7=74;
      Filelist_8=75;
      Filelist_9=76;
      Filelist_10=77;
      Filelist_11=78;
      Filelist_12=79;
      Filelist_13=80;

      GraphLog_1=81;
      GraphLog_2=82;
      GraphLog_3=83;
      GraphLog_4=84;
      GraphLog_5=85;
      GraphLog_6=86;
      GraphLog_7=87;
      GraphLog_8=88;
      GraphLog_9=89;
      GraphLog_10=90;

      CPSLog_1=91;
      CPSLog_2=92;
      CPSLog_3=93;
      CPSLog_4=94;
      CPSLog_5=95;
      CPSLog_6=96;
      CPSLog_7=97;

      CPSWide_1=98;
      CPSWide_2=99;
      CPSWide_3=100;
      CPSWide_4=101;
      CPSWide_5=102;
      CPSWide_6=103;

      Disk_1=104;
      Disk_2=105;
      Disk_3=106;
      Disk_4=107;
      Disk_5=108;
      Disk_6=109;

      Info_1=110;
      Info_2=111;
      Info_3=112;
      Info_4=113;
      Info_5=114;
      Info_6=115;
      Info_7=116;

      Help_1=117;
      Help_2=118;

      Start_1=119;
      Start_2=120;
      Start_3=121;
      Start_4=122;
      Start_5=123;
      Start_6=124;
      Start_7=125;
      Start_8=126;
      Start_9=127;
      Start_10=128;
      Start_11=129;
      Start_12=130;
      Start_13=131;
      Start_14=132;
      Start_15=133;
      Start_16=134;
      Start_17=135;
      Start_18=136;
      Start_19=137;

      ResetLF_1=138;
      ResetLF_2=139;
      ResetLF_3=140;

      Main_1=141;
      Main_2=142;
      Main_3=143;
      Main_4=144;
      Main_5=145;
      Main_6=146;
      Main_7=147;
      Main_8=148;
      Main_9=149;
      Main_10=150;
      Main_11=151;

      Log_1=152;
      Log_2=153;

      ReadCtl_1=154;
      ReadCtl_2=155;
      ReadCtl_3=156;
      ReadCtl_4=157;
      ReadCtl_5=158;
      ReadCtl_6=159;
      ReadCtl_7=160;

implementation

end.
