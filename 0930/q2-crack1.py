def findindexkey(subarr):#该函数可以找出将密文subarr解密成可见字符的所有可能值
    visiable_chars=[]#可见字符
    for x in range(32,126):
        visiable_chars.append(chr(x))
    #print(vi)
    test_keys=[]#用于测试密钥
    ans_keys=[]#用于结果的返回
    for x in range(0x00,0xFF):# 枚举密钥里所有的值
        test_keys.append(x)
        ans_keys.append(x)
    for i in test_keys:#对于0x00~0xFF里的每一个数i和subarr里的每个值s异或
        for s in subarr:
            if chr(s^i) not in visiable_chars:#用i解密s，如果解密后明文不是可见字符，说明i不是密钥
                ans_keys.remove(i)#去掉ans_keys里测试失败的密钥
                break
    #print(ans_keys)
    return ans_keys
 
strmi='F96DE8C227A259C87EE1DA2AED57C93FE5DA36ED4EC87EF2C63AAE5B9A7EFFD673BE4ACF7BE8923C\
AB1ECE7AF2DA3DA44FCF7AE29235A24C963FF0DF3CA3599A70E5DA36BF1ECE77F8DC34BE129A6CF4D126BF\
5B9A7CFEDF3EB850D37CF0C63AA2509A76FF9227A55B9A6FE3D720A850D97AB1DD35ED5FCE6BF0D138A84C\
C931B1F121B44ECE70F6C032BD56C33FF9D320ED5CDF7AFF9226BE5BDE3FF7DD21ED56CF71F5C036A94D96\
3FF8D473A351CE3FE5DA3CB84DDB71F5C17FED51DC3FE8D732BF4D963FF3C727ED4AC87EF5DB27A451D47E\
FD9230BF47CA6BFEC12ABE4ADF72E29224A84CDF3FF5D720A459D47AF59232A35A9A7AE7D33FB85FCE7AF5\
923AA31EDB3FF7D33ABF52C33FF0D673A551D93FFCD33DA35BC831B1F43CBF1EDF67F0DF23A15B963FE5DA\
36ED68D378F4DC36BF5B9A7AFFD121B44ECE76FEDC73BE5DD27AFCD773BA5FC93FE5DA3CB859D26BB1C63C\
ED5CDF3FE2D730B84CDF3FF7DD21ED5ADF7CF0D636BE1EDB79E5D721ED57CE3FE6D320ED57D469F4DC27A8\
5A963FF3C727ED49DF3FFFDD24ED55D470E69E73AC50DE3FE5DA3ABE1EDF67F4C030A44DDF3FF5D73EA250\
C96BE3D327A84D963FE5DA32B91ED36BB1D132A31ED87AB1D021A255DF71B1C436BF479A7AF0C13AA14794'
arr=[]#密文，每个元素为字符的ascii码
for x in range(0,len(strmi),2):
    arr.append(int(strmi[x:2+x],16))
 
 
for keylen in range(1,14):#枚举密钥的长度1~14
    for index in range(0,keylen):#对密钥里的第index个进行测试
        subarr=arr[index::keylen]#每隔keylen长度提取密文的内容，提取出来的内容都被密文的第index个加密
        ans_keys=findindexkey(subarr)#找出密钥中第index个的可能的值
        print('keylen=',keylen,'index=',index,'keys=',ans_keys)
        if ans_keys:#如果密钥第index个有可能存在，尝试用密钥的index个去解密文
            ch=[]
            for x in ans_keys:
                ch.append(chr(x^subarr[0]))
            print(ch)
#运行到这里，观察输出可以发现，密钥长度为7时有解
print('###############')
import string
def findindexkey2(subarr):#再造一个函数筛选密钥
    test_chars=string.ascii_letters+string.digits+','+'.'+' '#将检查的字符改为英文+数字+逗号+句号+空格
    #print(test_chars)
    test_keys=[]#用于测试密钥
    ans_keys=[]#用于结果的返回
    for x in range(0x00,0xFF):# 枚举密钥里所有的值
        test_keys.append(x)
        ans_keys.append(x)
    for i in test_keys:#对于0x00~0xFF里的每一个数i和substr里的每个值s异或
        for s in subarr:
            if chr(s^i) not in test_chars:#用i解密s，如果解密后不是英文、数字、逗号、句号、空格，说明i不是密钥
                ans_keys.remove(i)#去掉ans_keys里测试失败的密钥
                break
    #print(ans_keys)
    return ans_keys
 
vigenerekeys=[]#维基尼尔密码的密钥
for index in range(0,7):#已经知道密钥长度是7
    subarr=arr[index::7]
    vigenerekeys.append(findindexkey2(subarr))
print(vigenerekeys)#输出的是[[186], [31], [145], [178], [83], [205], [62]].
 
 
print("#########")
ming=''
for i in range(0,len(arr)):
    ming=ming+chr(arr[i]^vigenerekeys[i%7][0])
print(ming)