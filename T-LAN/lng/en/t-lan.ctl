;*********************************************************************
;***         T-Mail log analyser 0.34 sample control file          ***
;*********************************************************************
;
;RegisterName    The SysOp
; Register string (value by default - Unregistered).
; Defines  a  string which will be shown after 'Registered to:' words
; during  program execution and will be inserted into '^aPID:' kludge
; while posting. It MUST be the first keyword in T-LAN.CTL.
;
;======================= Log analyser section ========================
;
Address         2:0/0
; Defines the main address of system, wich must be exactly the same as
; main address from T-Mail.Ctl (value by default - 0:0/0.0).
; In  T-Mail versions after 2603 the format of displaying addresses in
; log  has  changed  and  now  it  became  possible to define aliases,
; therefore  this  variable is necessary: it is used for processing of
; abbreviated record of addresses in log and in list of aliases.
;
;Aliases         C:\T-MAIL\Aliases.Ctl ; 4D
; File  of  T-Mail address aliases (value by default - no).
; Is  intended  for  correct  work with T-Mail 2603+ where aliases are
; used.  This  variable also replaces real address in reports by their
; aliases.  It  may  be cancelled by indicating parameter 4d after the
; name of aliases file. Up to 512 aliases are supported now.
;
Language        C:\T-MAIL\T-MAIL.LNG
; Defines  the  filename of language support file T-Mail-LNG (value by
; default - English for T-Mail version 2604).
; If  you  use  another  language  and T-Mail version after 2599 it is
; necessary to give here the path to your language file.
; ATTENTION:  It  is  possible to define only one language version for
; all analysed logs.
;
Log             C:\T-MAIL\T-MAIL.LOG ; Kill ; Cut 1000 500
; Defines the name of analysed log. (value by default - no).
; For  multiline  systems  or  for gathering statistics in one log but
; with different values of other variables this is possible:
;[1] Log C:\T-MAIL\T-MAIL1.LOG
;[2] Log C:\T-MAIL\T-MAIL2.LOG
; Available values:
; Cut             - if log size overdue the first defined number of Kb
;                   it will be cut to second defined number of Kb;
;                 - if the first number is negative it means the number
;                   of days to save a log for;
; RenLog          - rename logfile name to a current date in "DD-MM-YY.Lnn"
;                   format after processing, where nn is line number;
; RenExt          - rename logfile extention  to a current day if year;
; Backup          - move processed logs to BackupDir directory;
; Kill            - erase log after processing.
;
;BackupDir       C:\T-MAIL\BACKUP
; Defines  directory  name to place processed logs (value by default -
; no).
;
Templates       TEMPLATE\
; Defines  directory  with  templates for reports  (value by default -
; executable directory).
;
;T-Hist          C:\T-MAIL\T-HIST.$00
; Defines  T-Hist.$??  filename  for  appropriate  log file  (value by
; default - no).
; Correcting  T-Mail  history  file  after  log  cutting  for T-Mail's
; built-in session viewer <Alt-I> to work properly.
;
;CutLog          Squish.Log   1000 500
; Defines filename to be truncated after complete mailer logs analysis
; (value by default - no). Maximum 'CutLog' keywords count is 256.
; Available values:
; 1. If log size overdue the first defined number of Kb it will be cut
; to second defined number of Kb.
; 2. If  the  first  number is negative it means the number of days to
; save  a log for. It will work fine only with T-Mail style or Binkley
; style logs.
;
;Output          C:\T-MAIL
; Directory to hold temporary and report files.  By default it will be
; an appropriate mailer log directory.
;
;Nodes           2:*/*.* 16:*/*.* !123:*/*.*
; Defining the group of addresses (value by default - *:*/*.*).
; Group  of  addresses,  for  creating  statistics. Supports agreement
; about T-Mail addresses. Addresses, that do not enter this group, not
; will be mentioned in statistics.
;
;Period          01/01-31/12,00:00:00-23:59:59
; Defines  the  date and time of beginning and completion of gathering
; statistics (value by default - 01/01-31/12,00:00:00-23:59:59).
; The variable consists of two fields (of date and of time), separated
; by  comma  and  represent  two intervals divided by '-' symbol, made
; according to the following rules:
; 1. The time of interval is by default 00:00:00-23:59:59
; 2. If  the  first field contains symbols '/' it should be understood
; as the date of beginning and end of the analysed interval.
; 3. If  the  first  field  doesn't  contain  symbols '/' it should be
; understood   as  "...days  before  this  (according  to  the  system
; calendar)",  and  the  next after '-' - as "duration" (in days) i.e.
; 'Period 1-1' wich means necessarity of gathering statistics for past
; 24 hours.
;
Total           HideDetails,FileCPS
; Common statistics (value by default - no).
; The main part of statistics generator. Available values:
;   HideDetails   - hide information about unsuccesfull calls;
;   HideExternals - hide information about started process;
;   HideFailures  - hide information about failures of EMSI;
;   FileCPS       - count  CPS only on the basis of transmitting,
;                   by default counts from the moment of
;                   picking up the phone receiver;
;   Protected     - think about all sessions as protected.
;
Summary         HideFailures,FileCPS
; Summary statistics (value by default - no).
; Available values:
;   HideExternals - hide information about started process;
;   HideFailures  - hide information about failures of EMSI;
;   FileCPS       - count  CPS only on the basis of transmitting,
;                   by default counts from the moment of
;                   picking up the phone receiver;
;   Protected     - think about all sessions as protected.
;
;Graphic         Wide
; Building loading diagram (value by default - no).
; Available values:
;   Wide          - extended busy diagram (72 rows),
;                   by default - 48;
;   Fake          - to construct a loading diagram from "Nodes" value
;                   (by default - display all information in it);
;   Skip          - do not add information abount appropriate line to
;                   a diagram (Multiline mode only);
;   Space         - use space on empty place instead of 'ú'.
;
;Charset         ±²Û°@ðþþ
; Characters,  with  the  help  of  wich  the  loading diagram will be
; constructed  (value  by  default  is  brought  from  T-LAN.LNG), 7th
; character  using  for building CPS diagram (value by default - 'þ'),
; 8th  character  using  for  building  disk  usage  diagram (value by
; default - 'þ').
;
FileList        *.* SizePKT,SizeARC,SizeTIC
; List of files (value by default - *.*).
; Wildcard:
;   [!]Wildcard   - for files that do not correspond defined wildcard,
;                   only size will be counted.
; Available values:
;   SizePKT       - calculate the size of transmitted Netmail;
;   SizeARC       - calculate the size of transmitted Arcmail;
;   SizeTIC       - calculate the size of transmitted *.tic files.
;   SizeFiles     - calculate the size of transmitted *.tic files, not
;                   matched with wildcard;
;   HidePKT       - hide transmitted Netmail;
;   HideARC       - hide transmitted Arcmail;
;   HideTIC       - hide transmitted *.tic files;
;   HideFiles     - hide transmitted files, not matched with wildcard;
;   HideSkipped   - hide skipped files.
;
;CPS             Max,Avg,Min,Addr,Reverse
; CPS report (value by default - Avg).
; Available values:
;   Max           - sort by maximum CPS;
;   Avg           - sort by average CPS;
;   Min           - sort by minimum CPS;
;   Addr          - sort by system address;
;   Reverse       - reverse sorting order;
;   Top           - make 'Top 10 CPS' instead of diagram.
;
;Disk            CDEF ; Used
; Disk space diargam (value by default - no).
; Available values:
;   C,D,..,Z or * - drive letters (* mean C-Z);
;   Used          - make used space diagram (by default);
;   Free          - make free space diagram.
;
TwitInfo         ,-1 /NC+5 /HUB+5 /B-Team+5 /C10+5 /C20+5 /C50+5 /C255+5 /Unregistered /Noncommercial+5 /Noncommercial
; Delete substrings from 'Info' lines (value by default - no).
; Control characters are '*', '+', '-', '^' and '=':
; /C10 - delete substring '/C10';
; /C10* - delete all characters after '/C10' substring;
; /C10+10 - delete all characters after 10th character after '/C10'
; /C10-10 - delete all characters after 10th character before  end  of
; '/C10';
; /C10^5  - delete 5 characters after '/C10' substring;
; /Noncommercial=/NC - change substring '/Noncommercial' to '/NC'.
; For example:
; TwitInfo /C10+5
; Original line: 'T-Mail 2604.OS2/C10/1234/12345678/1234'
; After TwitInfo: 'T-Mail 2604.OS2/C10/1234'
;
Statistics      Total,Summary,Graphic,FileList,CPS,Disk,SysOp,Mailer ; ,Multiline
; The list of reports (value by default - Total).
; List of files, that will be generated. Reports  are  created  in the
; output directory with corresponding log file name, if not specified:
;           Multiline - create one report for all mentioned logs. In
;                       this case reports will be named 'Station'
; with extension for:
;           Total     - .stt (always created)
;           Summary   - .sta
;           Graphic   - .stg
;           Filelist  - .stf
;           CPS       - .stc
;           Disk      - .std
;           SysOp     - .sts
;           Mailer    - .stm
;
;Kill            Total,Summary,Graphic,Filelist,CPS,Disk,SysOp,Mailer
; To erase reports after finishing work (value by default - no).
; Available values:
;   Total         - erase *.stt
;   Summary       - erase *.sta
;   Graphic       - erase *.stg
;   Filelist      - erase *.stf
;   CPS           - erase *.stc
;   Disk          - erase *.std
;   SysOp         - erase *.sts
;   Mailer        - erase *.stm
;
SelfLog         T-LAN.LOG Normal
; Defines the name of T-Lan log (value by default - no).
; After  the file name goes the parameter with a level of detailing of
; the log:
; Debug  - is  a  debug  log.  It  is recommended to turn on only when
; writing a bug report, because in this case every "sneeze" is written
; there :)
; Normal - normal detailing;
; Tiny   - minimal information;
; None   - prohibition of logging.
;
;============================= Poster section ========================
;
; Creating *.PKT type 2+
;Area            Netmail Pvt,K/s,Trs
; Areatag and flags (value by default - no, i.e. Poster is turned off)
;
;AreaPath        C:\T-MAIL\FILES
; Echotosser inbound directory (value by default - current).
;
;FromPKT         2:5020/999
; Address from wich a packet is created (value by default - no).
;
;FromMsgId       2:5020/999
; MSGID of created message (value by default - FromPKT).
;
;ToPKT           2:5020/999 [password]
; Address for wich a packet must be created (value by default - no).
; For  systems  with  Full Security there is a possibility to define a
; password to this packet after the address.
;---------------------------------------------------------------------
;
;From           T-LAN
; Defines  the  field  'From'  of  created message (value by default -
; T-LAN).
;
;To             SysOp
; Defines  the  field  'To'  of  created  message  (value by default -
; 'SysOp' /in Netmail/ or 'All' /in Echomail/).
;
;Subj           Statistics (@Date)
; Defines  the  field  'Subj'  of  current  message  (value by default
; depends on T-LAN.LNG).
;
;Tearline       @PID
; Defines tearline (value by default - no).
;
;Origin         -=( Automatically posted message )=-
; Defines origin in echomail (value by default depends on T-LAN.LNG).
;
;PostFiles     12     Graphic+Summary
; Defines  the  size  of  each message (in Kb) and the list of reports
; wich  must be in this packet. If the size of report exeeds the given
; value (by default - 12) then it will be cut a part.
; Message size might be up to 32K (DOS) and up to 255K (OS/2).
; The  list  shouldn't  be  larger  then in 'Statistics' because it is
; difficult  to  send  the  report,  which  is  not  created (value by
; default  - Graphic+Summary). Options separated by '+' character will
; be  posted  to  a  sigle  message,  separated  by  ',' - to separate
; messages.
;
;Flag          C:\T-MAIL\FLAGS\Arcmail.t-m Repack.t-m
; Defines flags made after creating packet (value by default - no).
; Name separator is a space character.
; Next flags path may not be defined. In this case it will be the same
; of the first flag's.
;
;===================== Download counter section ======================
;
;DirList       C:\T-MAIL\DIR.FRQ ; NoBackup
; Directory list in T-Mail or G.P.Mail format for searching tranferred
; files (value by default - no).
; Available values:
; NoBackup - erase FILES.BAK after successful FILES.BBS update.
;
;ZeroCounter   [00]
; Default download counter (value by default - [00]).
;
IgnoreFiles   *.pk? *.su? *.mo? *.tu? *.we? *.th? *.fr? *.sa? *.tic *.?ut *.req *.xma *.?rq
; Matching files should not be added to list needed to be counted.
;
;=====================================================================
