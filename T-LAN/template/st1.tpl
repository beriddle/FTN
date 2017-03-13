%WIDTH 68
%PRINT
%Head  Top 10 CPS 
%Head0  Absolute maximum 
%Head1  Average maximum 
%Head2  Absolute minimum 
%Head3  Average minimum 
@CenterNR(@Head)
@Center(@Head0,31)      @CenterNR(@Head1,31)
ษอออออออออออออออออออออัอออออออป      ษอออออออออออออออออออออัอออออออป
บ       Address       ณ  CPS  บ      บ       Address       ณ  CPS  บ
ฬอออออออออออออออออออออุอออออออน      ฬอออออออออออออออออออออุอออออออน
%BODY.DIV
@MaxNum@AMaxNum
%BODY
บ@Right(@MaxNum,3) @Left(@MaxAddress,16) ณ@Right(@MaxCPS,6) บ      \
บ@Right(@AMaxNum,3) @Left(@AMaxAddress,16) ณ@Right(@AMaxCPS,6) บ
%PRINT
ศอออออออออออออออออออออฯอออออออผ      ศอออออออออออออออออออออฯอออออออผ

@Center(@Head2,31)      @CenterNR(@Head3,31)
ษอออออออออออออออออออออัอออออออป      ษอออออออออออออออออออออัอออออออป
บ       Address       ณ  CPS  บ      บ       Address       ณ  CPS  บ
ฬอออออออออออออออออออออุอออออออน      ฬอออออออออออออออออออออุอออออออน
%BODY.DIV
@MinNum@AMinNum
%BODY
บ@Right(@MinNum,3) @Left(@MinAddress,16) ณ@Right(@MinCPS,6) บ      \
บ@Right(@AMinNum,3) @Left(@AMinAddress,16) ณ@Right(@AMinCPS,6) บ
%PRINT
ศอออออออออออออออออออออฯอออออออผ      ศอออออออออออออออออออออฯอออออออผ
@Right(@Version)
%END
