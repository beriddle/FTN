%WIDTH 74
%PRINT
%Head  Transfered files list 
@CenterNR(@Head)
@CenterNR(@Date)

������������������������������������������������������������������������ͻ
�     Address      �  Session  �  Time  �     Name     �   Size   � CPS  �
%BODY.DIV
���������������������� @Left(@Date,5) �������������������������������������������͹
%BODY
� @Left(@OneAddress,16) �@Left(@BTime,5)@Dash@Left(@ETime,5)�@Online�\
@Direction @Left(@Name,12)�@Right(@Size,9) � @CPS �
%PRINT
������������������������������������������������������������������������ͼ
@Right(@Version)
%END
