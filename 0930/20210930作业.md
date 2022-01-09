# many-time-pad

*1、某密文与其他密文异或，多次出现字母则代表此位置很可能为空格，用空格与此位置的密文（加密后的空格）异或得到密钥此位置的值。*

*2、得到粗略密钥后对所有密文进行解密，根据最容易理解的明文进行搜索，将完整且准确的明文与对应密文异或即可得到准确密钥 和 所有明文*

![image-20210929223517652](/home/rean/.config/Typora/typora-user-images/image-20210929223517652.png)

![image-20210929223547601](/home/rean/.config/Typora/typora-user-images/image-20210929223547601.png)

![image-20210929223835941](/home/rean/.config/Typora/typora-user-images/image-20210929223835941.png)

# crack-vigenere

![image-20210929225146499](/home/rean/.config/Typora/typora-user-images/image-20210929225146499.png)

![image-20210929225211192](/home/rean/.config/Typora/typora-user-images/image-20210929225211192.png)

![image-20210929225229952](/home/rean/.config/Typora/typora-user-images/image-20210929225229952.png)

![temp](/home/rean/Pictures/temp.jpg)

# break repeating-key xor

*1.先求key的长度: 从2-42进行遍历，将密文(bytes形式)进行顺序分组，计算根据Hamming distance(利用不同位异或结果为1)*

*2.按照同一个密钥字符进行分组,每组就转化成了 single_key_XOR: 根据字母出现的频率得到分数最高的, 得到key*

3.密文和key进行循环异或*

![image-20210929224345241](/home/rean/.config/Typora/typora-user-images/image-20210929224345241.png)

![image-20210929224410007](/home/rean/.config/Typora/typora-user-images/image-20210929224410007.png)

![image-20210929224456444](/home/rean/.config/Typora/typora-user-images/image-20210929224456444.png)

![image-20210929224545962](/home/rean/.config/Typora/typora-user-images/image-20210929224545962.png)

# crack sha-1-hashed passwords

![image-20210929224725993](/home/rean/.config/Typora/typora-user-images/image-20210929224725993.png)
