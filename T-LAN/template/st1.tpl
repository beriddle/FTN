%WIDTH 68
%PRINT
%Head  Top 10 CPS 
%Head0  Absolute maximum 
%Head1  Average maximum 
%Head2  Absolute minimum 
%Head3  Average minimum 
@CenterNR(@Head)
@Center(@Head0,31)      @CenterNR(@Head1,31)
浜様様様様様様様様様様冤様様様�      浜様様様様様様様様様様冤様様様�
�       Address       �  CPS  �      �       Address       �  CPS  �
麺様様様様様様様様様様慷様様様�      麺様様様様様様様様様様慷様様様�
%BODY.DIV
@MaxNum@AMaxNum
%BODY
�@Right(@MaxNum,3) @Left(@MaxAddress,16) �@Right(@MaxCPS,6) �      \
�@Right(@AMaxNum,3) @Left(@AMaxAddress,16) �@Right(@AMaxCPS,6) �
%PRINT
藩様様様様様様様様様様詫様様様�      藩様様様様様様様様様様詫様様様�

@Center(@Head2,31)      @CenterNR(@Head3,31)
浜様様様様様様様様様様冤様様様�      浜様様様様様様様様様様冤様様様�
�       Address       �  CPS  �      �       Address       �  CPS  �
麺様様様様様様様様様様慷様様様�      麺様様様様様様様様様様慷様様様�
%BODY.DIV
@MinNum@AMinNum
%BODY
�@Right(@MinNum,3) @Left(@MinAddress,16) �@Right(@MinCPS,6) �      \
�@Right(@AMinNum,3) @Left(@AMinAddress,16) �@Right(@AMinCPS,6) �
%PRINT
藩様様様様様様様様様様詫様様様�      藩様様様様様様様様様様詫様様様�
@Right(@Version)
%END
