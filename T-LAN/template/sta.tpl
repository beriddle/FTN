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

 ฺฤฤฤฤฤฤฤฤฤฤฤฤฤ Password: '*' - Present, ' ' - Absent, '?' - Error
 ณ    ฺฤฤฤฤฤฤฤฤ Outgoing calls
 ณ    ณ     ฺฤฤ Sessions
 ณ    ณ     ณ ฺ Last Session Result: '๚' - Success, '' - Aborted
ษออออออออออออัอออออออออออออออออัอออออออออออัออออออออออออออออออัออออออออออออออป
บP    O     SณL    Address     ณ Days/Time ณ  Bytes    Bytes  ณ     CPS      บ
บ            ณ                 ณ  Online   ณ received   sent  ณMin.ณMax.ณAvg.บ
ฬออออออออออออุอออออออออออออออออุอออออออออออุออออออออออออออออออุออออุออออุออออน
%BODY
บ@IsProtected@Right(@OutCalls,5)@Right(@Sessions,6)ณ@IsSuccess@Left(@Address,16)\
ณ@Right(@Online,11)ณ@Right(@Received,9)@Right(@Sent,9)ณ@MinCPSณ@MaxCPSณ@AvgCPSบ
%PRINT
ฬออออออออออออุอออออออออออออออออุอออออออออออุออออออออออออออออออุออออุออออุออออน
บ@Right(@TOutCalls,6)@Right(@TSessions,6)ณ Stations:@Right(@TStations,6) ณ\
@Right(@TOnLine,11)ณ@Right(@TReceived,9)@Right(@TSent,9)ณ@TMinCPSณ@TMaxCPSณ@TAvgCPSบ
ศออออออออออออฯอออออออออออออออออฯอออออออออออฯออออออออออออออออออฯออออฯออออฯออออผ
@Right(@Version)
%END
