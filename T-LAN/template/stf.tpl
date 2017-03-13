%WIDTH 74
%PRINT
%Head  Transfered files list 
@CenterNR(@Head)
@CenterNR(@Date)

ษออออออออออออออออออัอออออออออออัออออออออัออออออออออออออัออออออออออัออออออป
บ     Address      ณ  Session  ณ  Time  ณ     Name     ณ   Size   ณ CPS  บ
%BODY.DIV
ฬออออออออออออออออออุออ @Left(@Date,5) ออุออออออออุออออออออออออออุออออออออออุออออออน
%BODY
บ @Left(@OneAddress,16) ณ@Left(@BTime,5)@Dash@Left(@ETime,5)ณ@Onlineณ\
@Direction @Left(@Name,12)ณ@Right(@Size,9) ณ @CPS บ
%PRINT
ศออออออออออออออออออฯอออออออออออฯออออออออฯออออออออออออออฯออออออออออฯออออออผ
@Right(@Version)
%END
