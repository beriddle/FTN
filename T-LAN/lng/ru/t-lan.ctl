;*********************************************************************
;***         T-Mail log analyser 0.34 sample control file          ***
;*********************************************************************
;
;RegisterName    The SysOp
; C�p��� p�����p�樨 (���祭�� ��-y���砭�� - Unregistered).
; ������ ��p��y, ���p�� �y��� �뢮������ ��᫥ ᫮�� '���짮��⥫�:'
; �� �p��� p����� �p��p���� � ��⠢������ � ��y�� ^aPID: �p� ���⨭��.
; ������ ���� ��p��� ��p���� 䠩�� ���䨣yp�樨.
;
;======================= Log analyser section ========================
;
Address         2:0/0
; ������  �᭮����  ��p�� ��⥬�, ���p� ������ ᮢ������ � �᭮���
; ��p�ᮬ �� T-Mail.Ctl (���祭�� ��-y���砭�� - 0:0/0.0).
; � T-Mail ��pᨩ ��p� 2603 ��������� �p��� ������ ��p�ᮢ � ���� �
; ������   �����������   �������   ����ᮢ,   ���⮬y   �  ��������
; ����室������  �  �⮩  ��p�������:  ���  �ᯮ��y���� ��� ��p���⪨
; ᮪p�饭��� ����� ��p�ᮢ � ���� � � ᯨ᪥ ����ᮢ.
;
;Aliases         C:\T-MAIL\Aliases.Ctl ; 4D
; ���� ��p���� ����ᮢ T-Mail (���祭�� ��-y���砭�� - ���).
; �p�������祭  ���  ��pp��⭮� p����� � T-Mail 2603+ c �ᯮ�짮������
; ����ᮢ.  ���y���⮬  p�����  �⮩ ��p������� ���� ⠪�� ������
; �  ������  p������ ��p�ᮢ �⠭権 �� �� ������, ���py�, ��p�祬,
; ����� �⬥���� y�������� ��p����� 4D ��᫥ ����� 䠩�� ����ᮢ.
; �����p�������� �� 500 ����ᮢ.
;
;Language        C:\T-MAIL\T-MAIL.LNG
; ������  ��� 䠩�� �몮��� �����p��� T-MAIL.LNG (���祭�� ��-y����-
; ��� - ������᪨� ��� T-Mail ��pᨨ 2604).
; �p�  �ᯮ�짮�����  �몠,  �⫨筮��  ��  ���祭��  ��-y���砭��, �
; T-Mail   ��p�   2599   ����室���  y������  �����  �y��  �  ��襬y
; �몮���y 䠩�y.
; �H���H��!  ����� ��p������� ⮫쪮 ���y ��p�����y� Language ��� ���
; �������py���� �����.
;
Log             C:\T-MAIL\T-MAIL.LOG ; Kill ; Cut 1000 500
; ������ ��� �������py����� ���� (���祭�� ��-y���砭�� - ���).
; ���  ������������� ��⥬, ���� ��� ᡮp� ����⨪� �� �����y ���y,
; �� � p���묨 ���祭�ﬨ �py��� ��p������� ��������� ⠪�� ᫥�y�饥:
;[1] Log C:\T-MAIL\T-MAIL1.LOG
;[2] Log C:\T-MAIL\T-MAIL2.LOG
; ���y�⨬� ��p����p�:
; Cut             - �᫨ p����p ���� �p���ᨫ ��p��� ���祭�� ��p����-
;                   p� (� Kb), � �� �y��� y��� �� p����p� ��p���;
;                 - �᫨ ��p�� ��p����p ��p��⥫��,  � ��  ������
;                   �᫮ ����, �� ���p� ��p���� ���;
; RenLog          - ��p���������� ��� ��᫥ ��p���⪨  �  ⥪y�y� ���y
;                   �p��� "DD-MM-YY.Lnn", ��� nn - ����p �����;
; RenExt          - ��p���������� p���p���� ���� � ⥪y騩 ���� ����;
; Backup          - ��p������� � ��⠫�� BackupDir ��᫥ ��p���⪨;
; Kill            - y���⮦��� ��� ��᫥ ��p���⪨.
;
;BackupDir       C:\T-MAIL\BACKUP
; ������  ���  ��⠫���,  �  ���p�  ��p������  ���  ��᫥ ��p���⪨
; (���祭�� ��-y���砭�� - ���).
;
Templates       TEMPLATE\
; ������  ���  ��⠫���,  � ���p�� �࠭���� 蠡���� ����⮢ (���祭��
; ��-y���砭�� - ��⠫�� �ᯮ��塞��� 䠩��).
;
;T-Hist          C:\T-MAIL\T-HIST.$00
; ������  ���  䠩��  T-Hist.$??, ᮮ⢥���y�饣� �������py����y ���y
; (���祭�� ��-y���砭�� - ���).
; �p��������  ��pp����  䠩��  ���p�� T-Mail �p� y�祭�� ���� ⠪��
; ��p����, �⮡� p���⠫ ���p����� �p�ᬮ�p騪 T-Mail <Alt-I>.
;
;CutLog          Squish.Log   1000 500
; ������ ��� ����,  ���p�  ᫥�y�� y��� ��᫥ ������� ����� �����p�
; (���祭�� ��-y���砭�� - ���). ���ᨬ��쭮� �᫮ ��p��⨢ - 256.
; ���y�⨬� ��p����p�:
; 1. �᫨ p����p ���� �p���ᨫ ��p��� ���祭�� ��p����p� (� Kb), � ��
; �y��� y��� �� p����p� ��p���.
; 2. �᫨ ��p�� ��p����p ��p��⥫��,  � �� ������ �᫮ ����,  ��
; ���p� ��p���� ���. ����⠥� ⮫쪮 �� T-Mail-style � Binkley-style
; �����.  �H���H��:  �����  �� ����p ����� �� �� �����, CutLog �y���
; �믮���� �����p���⢥��� ��p�� ����p襭��� p����� T-LAN.
;
;Output          C:\T-MAIL
; ��⠫��,  �  ���p�� �y�y� �p������� �p������ 䠩�� � 䠩�� ����⮢
; (���祭�� ��-y���砭�� - � ��⠫��� ᮮ⢥���y��� ����� �����p�).
;
;Nodes           2:*/*.* 16:*/*.* !123:*/*.*
; ������� �py��� ��p�ᮢ (���祭�� ��-y���砭�� - *:*/*.*).
; ��p��, �� �����訥 � ��y �py��y, �� �y�y� �⮡p����� � ����⨪�.
; �����p�������� ᮣ��襭�� �� ��p��� T-Mail.
;
;Period          01/01-31/12,00:00:00-23:59:59
; ������  ���y  �  �p��� ��砫� � ����砭�� ᡮp� ����⨪� (���祭��
; ��-y���砭�� - 01/01-31/12,00:00:00-23:59:59).
; ��p�������  ��⮨�  ��  ��y�  �����,  p��������  ����⮩:  ���� �
; �p�����,  ���p� �p���⠢���� ᮡ�� ���p����, p������� ᨬ�����
; '-', ��⠢������ �� ᫥�y�騬 �p������:
; 1. �p��� ���p���� ��-y���砭�� - 00:00:00-23:59:59
; 2. �᫨ ��p��� ���� ᮤ�p��� ᨬ���� '/',  � ��� ���p��������� ���
; ��� ��砫� � ����砭�� �������py����� ���p����.
; 3. �᫨  ��p���  ����  ��  ᮤ�p���  ᨬ�����  '/',   �  ���  �y���
; ���p���������  ���  "����  ⮬y  �����,  �⭮�⥫쭮  ⥪y饣� (��
; ��⥬���y �������p�)", � ᫥�y�饥 ��᫥ '-' ��� "�p������⥫쭮���
; (�  ����)", � ���� 'Period 1-1' y���뢠�� �� ����室������ �������
; ����⨪� �� �p�襤訥 �y⪨.
;
Total           HideDetails,FileCPS
; ���� ����⨪� (���祭�� ��-y���砭�� - ���).
; �᭮���� ���� ����p��p� ����⨪�. ���y�⨬� ���祭��:
;   HideDetails   - �p뢠�� ���p���� � ��yᯥ��� �������;
;   HideExternals - �p뢠�� ���p���� � ���y᪥ �p���ᮢ;
;   HideFailures  - �p뢠�� ���p���� �� ��p뢠� EMSI;
;   FileCPS       - ������ CPS � ��砫� ��p���� 䠩��� (��-y���砭��
;                   ��⠥��� � ������ ���� �py���);
;   Protected     - ������ ���, �� �� ��ᨨ �뫨 ����p�����.
;
Summary         HideFailures,FileCPS
; C������ ����⨪� (���祭�� ��-y���砭�� - ���).
; ���y�⨬� ���祭��:
;   HideExternals - �p뢠�� ���p���� � ���y᪥ �p���ᮢ;
;   HideFailures  - �p뢠�� ���p���� �� ��p뢠� EMSI;
;   FileCPS       - ������ CPS � ��砫� ��p���� 䠩��� (��-y���砭��
;                   ��⠥��� � ������ ���� �py���);
;   Protected     - ������ ���, �� �� ��ᨨ �뫨 ����p�����.
;
;Graphic         Wide
; ����p����� �p�䨪� ���py��� (���祭�� ��-y���砭�� - ���).
; ���y�⨬� ���祭��:
;   Wide          - y����祭�� �p�䨪 ���py��� - 72 �⮫�� (��-y���-
;                   砭�� - 48 �⮫�殢);
;   Fake          - ��p���� �p�䨪 ���py��� ⮫쪮 y�����  ��  'Nodes'
;                   (��-y���砭�� - ������� � �p�䨪 ��� ���p����);
;   Skip          - �� ��������� � �p�䨪 ���p���� � ����� (⮫쪮 �
;                   p����� Multiline);
;   Space         - �p���� �� �y�⮬ ���� �p�䨪� ����� '�';
;
;Charset         ��۰@���
; C������, � ������� ���p�� �y��� ��p������ �p�䨪 ���py��� (���祭��
; ��-y���砭��  -  ��p����  �� T-LAN.LNG), 7-� ᨬ��� �ᯮ��y���� ���
; ����p�����  �p�䨪�  CPS  (���祭��  ��-y���砭�� - '�'), 8-� ᨬ���
; �ᯮ��y����  ���  ����p����� ���⮣p���� ᢮������� �p���p���⢠ ��
; ��᪥.
;
FileList        *.* SizePKT,SizeARC,SizeTIC
; C��᮪ 䠩��� (���祭�� ��-y���砭�� - *.*).
; ��᪠:
;   [!]��᪠      - ��� 䠩���,  �� ᮮ⢥���y��� ��᪥,  �y��� ���-
;                   ���뢠���� ⮫쪮 p����p.
; ���y�⨬� ���祭��:
;   SizePKT       - ������� p����p� ��p�������� Netmail;
;   SizeARC       - ������� p����p� ��p�������� Arcmail;
;   SizeTIC       - ������� p����p� ��p������� *.tic 䠩���;
;   SizeFiles     - ������� p����p� ��p������� 䠩���, �� ������� ���
;                   ���y;
;   HidePKT       - �p��� ��p������ Netmail;
;   HideARC       - �p��� ��p������ Arcmail;
;   HideTIC       - �p��� ��p������ *.tic 䠩��;
;   HideFiles     - �p��� ��p������ 䠩��, �� �����訥 ��� ���y;
;   HideSkipped   - �p��� �p��y饭�� 䠩��.
;
;CPS             Max,Avg,Min,Addr,Reverse
; ���⮣p���� CPS (���祭�� ��-y���砭�� - Avg).
; ���y�⨬� ���祭��:
;   Max           - �p�p���� �� ���ᨬ��쭮�y CPS;
;   Avg           - �p�p���� �� �p�����y CPS;
;   Min           - �p�p���� �� �������쭮�y CPS;
;   Addr          - �p�p���� �� ��p��y;
;   Reverse       - ��p��� ��p冷� �p�p����;
;   Top           - ��p���� 'Top 10 CPS' ����� ���⮣p����.
;
;Disk            CDEF ; Used
; ���⮣p���� ᢮������� �p���p���⢠ (���祭�� ��-y���砭�� - ���).
; ���y�⨬� ���祭��:
;   C,..,Z ��� *  - ��᪨ (* ����砥� C-Z);
;   Used          - �⮡p����� �� �p�䨪� �ᯮ��y���� �p���p���⢮
;                   (��-y���砭��);
;   Free          - �⮡p����� �� �p�䨪� ᢮������ �p���p���⢮.
;
TwitInfo        ,-1 /NC+5 /HUB+5 /B-Team+5 /C10+5 /C20+5 /C50+5 /C255+5 /Unregistered /Noncommercial+5 /Noncommercial
; �������  �����p���  ��  ��p��  ���  'SysOp' � 'Mailer' (���祭�� ��-
; y���砭�� - ',-1').
; ���y�⨬� �ᯮ�짮����� ᯥ�ᨬ����� '*', '+', '-', '^' � '=':
; /C10 - y������ �����p��y '/C10';
; /C10* - y������ �� ᨬ����, ����� � ��p���� �� �����p���� '/C10';
; /C10+10 - y������ �� ᨬ����, ����� � ����⮣� �� '/C10';
; /C10-10 - y������ �� ᨬ����, ����� � ����⮣� ��p�� ���殬 ���-
; ��p��� '/C10';
; /C10^5 - 㤠���� 5 ᨬ�����, ��稭�� � ��ࢮ�� �� �����ப�� '/C10';
; /Noncommercial=/NC - ������� �����p��y '/Noncommercial' �� '/NC'.
; �p���p:
; TwitInfo /C10+5
; �p������쭠� ��p���: 'T-Mail 2604.OS2/C10/1234/12345678/1234'
; ���y���� p����� TwitInfo: 'T-Mail 2604.OS2/C10/1234'
;
;SysOp           Wide
; ���p���� � �������� �ᮯ�� (���祭�� ��-y���砭�� - ���).
; ���y�⨬� ���祭��:
; Wide            - �ᯮ�짮���� 24 ᨬ���� � ���� SysOp ����� 20.
;
Statistics      Total,Summary,Graphic,FileList,CPS,Disk,SysOp,Mailer ; ,Multiline
; C��᮪ ����⮢ (���祭�� ��-y���砭�� - Total).
; �����  ᮧ������  �  ��⠫���,  �������� � Output � ᮮ⢥���y�騬
; ���y ������, �᫨ �� y������:
;        Multiline - ᮧ������ ����  �����  ��  �᭮����� ������� ���
;                    y�������� �����. � �⮬ �y砥 ������ �y�y� ����-
;                    ������ 'Station'
; c p���p����� ���:
;        Total     - .stt (ᮧ������ �ᥣ��)
;        Summary   - .sta
;        Graphic   - .stg
;        Filelist  - .stf
;        CPS       - .stc
;        Disk      - .std
;        SysOp     - .sts
;        Mailer    - .stm
;
;Kill            Total,Summary,Graphic,Filelist,CPS,Disk,SysOp,Mailer
; ����⮦��� ������ �� ����砭�� p����� (���祭�� ��-y���砭�� - ���).
; ���y�⨬� ���祭��:
;   Total         - y���⮦��� *.stt
;   Summary       - y���⮦��� *.sta
;   Graphic       - y���⮦��� *.stg
;   Filelist      - y���⮦��� *.stf
;   CPS           - y���⮦��� *.stc
;   Disk          - y���⮦��� *.std
;   SysOp         - y���⮦��� *.sts
;   Mailer        - y���⮦��� *.stm
;
SelfLog         T-LAN.LOG Normal
; ������ ��� ᮡ�⢥����� ���� (���祭�� ��-y���砭�� - ���).
; �� ������ 䠩�� ᫥�y�� ��p����p � yp������ ��⠫���樨 ����:
; Debug  - �⫠���� ���.  ��� p�������y���� ������� ⮫쪮 � �y砥
;          �p���⮢����� ����� �� �訡���, ��᪮��y �p�  �⮬  � ���
;          ������ ����� "��" :)
; Normal - ��p���쭠� ��⠫�����;
; Tiny   - �������쭠� ���p����;
; None   - ���p�饭�� ������� ����.
;
;============================= Poster section ========================
;
; C������� *.PKT type 2+
;Area            Netmail Pvt,K/s,Trs
; Areatag � 䫠��� (���祭�� ��-y���砭�� - ���, �.�. Poster �⪫�祭)
;
;AreaPath        C:\T-MAIL\FILES
; �室��� ��⠫�� �����p� (���祭�� ��-y���砭�� - ⥪y騩).
;
;FromPKT         2:5020/999            ; Full 4D address
; ��p��, � ���p��� �p��py���� ����� (���祭�� ��-y���砭�� - ���).
;
;FromMsgId       2:5020/999            ; Full 4D address
; MSGID ��p��p�������� ᮮ�饭�� (���祭�� ��-y���砭�� - FromPKT).
;
;ToPKT           2:5020/999 [password] ; Full 4D address, [��p���]
; ��p��, ��� ���p��� �p��py���� ����� (���祭�� ��-y���砭�� - ���).
; ���  ��⥬  �  Full  Security  �p��yᬮ�p��� ����������� �� ��p�ᮬ
; ������ ��p��� �⮣� �����.
;---------------------------------------------------------------------
;
;From           @PID
; ������  ����  'From' ᮧ��������� ᮮ�饭�� (���祭�� ��-y���砭�� -
; T-LAN).
;
;To             SysOp
; ������  ����  'To'  ᮧ���������  ᮮ�饭�� (���祭�� ��-y���砭�� -
; 'SysOp' /��� Netmail/ � 'All' /��� Echomail/).
;
;Subj           Statistics (@Date)
; ������ ���� 'Subj' ᮧ��������� ᮮ�饭�� (���祭�� ��-y���砭�� - �
; ����ᨬ��� �� T-LAN.LNG)
;
;Tearline       @PID
; ������ Tearline (���祭�� ��-y���砭�� - ���).
;
;Origin         -=( Automatically posted message )=-
; ������  Origin  � Echomail (���祭�� ��-y���砭�� - � ����ᨬ��� ��
; T-LAN.LNG).
;
;PostFiles     12     Graphic+Summary
; ������  p����p �⤥�쭮�� ᮮ�饭�� (� Kb) � ᯨ᮪ ����⮢, ���p�
; ����室��� ������� � ᮧ������� �����. �᫨ p����p ����� �p�����
; �������  p����p  (��-y���砭��  -  12),  �  �� ��p������ �� ���.
; ��p���祭��: p����p ����� ���� �� 1 �� 32K (DOS) ��� �� 255K (OS/2).
; C��᮪ �� ������ ���� �����, 祬 � 'Statistics' - ᫮��� ��p������
; �� ᮧ����� ����� (��-y���砭�� - Graphic+Summary).
; ������,  p���������  ������  '+'  �y�y�  ����饭� � ���� ᮮ�饭��,
; p��������� ',' - � p����.
;
;Flag          C:\T-MAIL\FLAGS\Arcmail.t-m Repack.t-m
; ������  �����  䫠����,  ���������  ��᫥  ᮧ����� ����� (���祭��
; ��-y���砭�� - ���). �������⥫� - �p����.
; �y�� ��᫥�y��� 䫠���� ����� �� y���뢠��: �� �y��� ���������� ⥬
; ��, �� � ��p�� y�������.
;
;===================== Download counter section ======================
;
;DirList       C:\T-MAIL\DIR.FRQ ; NoBackup
; C��᮪ ��⠫����, � ���p�� �y��� �᪠�� ��p������ 䠩��  (���祭��
; ��-y���砭�� - ���).
; ���y�⨬� ���祭�� ��p����p��:
; NoBackup - y������ FILES.BAK ��᫥ yᯥ譮�� ������ FILES.BBS.
;
;ZeroCounter   [00]
; ��� ���稪� (���祭�� ��-y���砭�� - [00]).
;
IgnoreFiles   *.pk? *.su? *.mo? *.tu? *.we? *.th? *.fr? *.sa? *.tic *.?ut *.req *.xma *.?rq
; ��� 䠩���, ᮮ⢥���y��� ��p��᫥��� ��᪠�, ����稪 ��뢠����
; �� �y���.
;
;=====================================================================
