%WIDTH 78
%PRINT
%Head  CPS Graphic 
@CenterNR(@Head)
@CenterNR(@Date)

����������������������������������������������������������������������������ͻ
�      Address       �@Center(@CPSMode,40)�     CPS      �
�                    �@Right(@Scale,40)�Min.�Max.�Avg.�
����������������������������������������������������������������������������͹
%BODY
�@Right(@Num,3) @Left(@Address,16)�@Left(@Bar,40)�@MinCPS�@MaxCPS�@AvgCPS�
%PRINT
����������������������������������������������������������������������������ͼ
@Right(@Version)
%END
