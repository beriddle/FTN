; Functions:
; @Left(string[,width])
; @Right(string[,width])
; @Center(string[,width])
; @CenterNR(string[,width])
%WIDTH 78
%PRINT
%Head  Summary link statistics 
@CenterNR(@Head)
@CenterNR(@Date)

 �������������� Password: '*' - Present, ' ' - Absent, '?' - Error
 �    ��������� Outgoing calls
 �    �     ��� Sessions
 �    �     � � Last Session Result: '�' - Success, '' - Aborted
����������������������������������������������������������������������������ͻ
�P    O     S�L    Address     � Days/Time �  Bytes    Bytes  �     CPS      �
�            �                 �  Online   � received   sent  �Min.�Max.�Avg.�
����������������������������������������������������������������������������͹
%BODY
�@IsProtected@Right(@OutCalls,5)@Right(@Sessions,6)�@IsSuccess@Left(@Address,16)\
�@Right(@Online,11)�@Right(@Received,9)@Right(@Sent,9)�@MinCPS�@MaxCPS�@AvgCPS�
%PRINT
����������������������������������������������������������������������������͹
�@Right(@TOutCalls,6)@Right(@TSessions,6)� Stations:@Right(@TStations,6) �\
@Right(@TOnLine,11)�@Right(@TReceived,9)@Right(@TSent,9)�@TMinCPS�@TMaxCPS�@TAvgCPS�
����������������������������������������������������������������������������ͼ
@Right(@Version)
%END
