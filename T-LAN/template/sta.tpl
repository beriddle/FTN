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

 旼컴컴컴컴컴컴 Password: '*' - Present, ' ' - Absent, '?' - Error
 �    旼컴컴컴� Outgoing calls
 �    �     旼� Sessions
 �    �     � � Last Session Result: '�' - Success, '' - Aborted
�袴袴袴袴袴袴佶袴袴袴袴袴袴袴袴佶袴袴袴袴袴佶袴袴袴袴袴袴袴袴錮袴袴袴袴袴袴袴�
튡    O     S쿗    Address     � Days/Time �  Bytes    Bytes  �     CPS      �
�            �                 �  Online   � received   sent  쿘in.쿘ax.쿌vg.�
勁袴袴袴袴袴曲袴袴袴袴袴袴袴袴曲袴袴袴袴袴曲袴袴袴袴袴袴袴袴袴妄袴曲袴袴妄袴攷
%BODY
�@IsProtected@Right(@OutCalls,5)@Right(@Sessions,6)�@IsSuccess@Left(@Address,16)\
�@Right(@Online,11)�@Right(@Received,9)@Right(@Sent,9)�@MinCPS�@MaxCPS�@AvgCPS�
%PRINT
勁袴袴袴袴袴曲袴袴袴袴袴袴袴袴曲袴袴袴袴袴曲袴袴袴袴袴袴袴袴袴妄袴曲袴袴妄袴攷
�@Right(@TOutCalls,6)@Right(@TSessions,6)� Stations:@Right(@TStations,6) �\
@Right(@TOnLine,11)�@Right(@TReceived,9)@Right(@TSent,9)�@TMinCPS�@TMaxCPS�@TAvgCPS�
훤袴袴袴袴袴賈袴袴袴袴袴袴袴袴賈袴袴袴袴袴賈袴袴袴袴袴袴袴袴袴鳩袴賈袴袴鳩袴暠
@Right(@Version)
%END
