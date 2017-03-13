%WIDTH 78
%PRINT
%Head  Total statistics 
@CenterNR(@Head)

               ฺฤฤฤฤฤ Remote  : ' ' - Listed,       'U' - Unlisted
               ณฺฤฤฤฤ Password: '*' - Present,      ' ' - Absent, '?' - Error
               ณณฺฤฤฤ Call    : 'i' - Incoming,     'o' - Outgoing
               ณณณฺฤฤ Protocol: 'z'Modem, 'Z'edZap, 'D'irZap, 'J'anus, 'H'ydra
               ณณณณ             'X'Modem, 'B'inkP,  'h'ydra/hdx
               ณณณณฺฤ Ext.Freq: 'f' - Present,      ' ' - Absent
               ณณณณณฺ Session : '๚' - Success,      '' - Aborted
ษอออออออออออออัอออออออออออออออออออออออัออออออออัออออออออออออออออออัออออัอออออป
บ   Session   ณRPCPES     Address     ณ  Time  ณ  Bytes    Bytes  ณCPS ณSpeedบ
บ Begin  End  ณ                       ณ Online ณ received   sent  ณ    ณ     บ
%BODY.DIV
ฬอออ @Left(@Date,5) อออุอออออออออออออออออออออออุออออออออุออออออออออออออออออุออออุอออออน
%BODY
บ @Left(@BTime,5)-@Left(@ETime,5) ณ@IsListed@IsProtected@Direction@Protocol\
@IsExtFreq@IsSuccess @Left(@Address,16)ณ@Onlineณ@Right(@Received,9)@Right(@Sent,9)ณ\
@CPSณ@Right(@Speed,5)บ
%PRINT
ศอออออออออออออฯอออออออออออออออออออออออฯออออออออฯออออออออออออออออออฯออออฯอออออผ
@Right(@Version)
%END
