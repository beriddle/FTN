%WIDTH 78
%PRINT
%Head  Total statistics 
@CenterNR(@Head)

               ������ Remote  : ' ' - Listed,       'U' - Unlisted
               ������ Password: '*' - Present,      ' ' - Absent, '?' - Error
               ������ Call    : 'i' - Incoming,     'o' - Outgoing
               ������ Protocol: 'z'Modem, 'Z'edZap, 'D'irZap, 'J'anus, 'H'ydra
               ����             'X'Modem, 'B'inkP,  'h'ydra/hdx
               ������ Ext.Freq: 'f' - Present,      ' ' - Absent
               ������ Session : '�' - Success,      '' - Aborted
����������������������������������������������������������������������������ͻ
�   Session   �RPCPES     Address     �  Time  �  Bytes    Bytes  �CPS �Speed�
� Begin  End  �                       � Online � received   sent  �    �     �
%BODY.DIV
���� @Left(@Date,5) �����������������������������������������������������������������͹
%BODY
� @Left(@BTime,5)-@Left(@ETime,5) �@IsListed@IsProtected@Direction@Protocol\
@IsExtFreq@IsSuccess @Left(@Address,16)�@Online�@Right(@Received,9)@Right(@Sent,9)�\
@CPS�@Right(@Speed,5)�
%PRINT
����������������������������������������������������������������������������ͼ
@Right(@Version)
%END
