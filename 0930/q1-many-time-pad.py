import binascii
'''
1、某密文与其他密文异或，多次出现字母则代表此位置很可能为空格，用空格与此位置的密文（加密后的空格）异或得到密钥此位置的值。
2、得到粗略密钥后对所有密文进行解密，根据最容易理解的明文进行搜索，将完整且准确的明文与对应密文异或即可得到准确密钥 和 所有明文
'''
ciphertexts = [
     "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e",
     "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f",
     "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",
     "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa",
     "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070",
     "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4",
     "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce",
     "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3",
     "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027",
     "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83",
     "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904",
 ]
ciphertexts = [binascii.unhexlify(x) for x in ciphertexts]

def strXor(a, b):
     return "".join([chr(x ^ y) for x, y in zip(a, b)])

def keyXor(m,k):
    return bytes([m[i]^k[i%len(k)] for i in range(len(m))])

key = [0] * 1000    #存放密钥
max_space_count=[0]*1000    #全局性值，对应最大计数，若某密钥在某位取得最大计数则此为最可能为空格，对应利用此位最可能得出密钥
whitespace = ord(' ')   #空格

#开始做异或,有c1⊕c2=m1⊕k⊕m2⊕k=m1⊕m2
for ciphertext_a in ciphertexts:
    space_suspect_counts = [0] * len(ciphertext_a)
    for ciphertext_b in ciphertexts:
        #如果遇到自己，跳过，不和自己做异或
        if ciphertext_a == ciphertext_b:
            continue
        #开始两两异或
        a_xor_b = strXor(ciphertext_a, ciphertext_b)
        for char_idx, xor_resulting_char in enumerate(a_xor_b):
            #一个大写字母与空格异或，结果为其对应的小写字母；一个小写字母与空格异或，结果为其对应的大写字母。
            #isaplha()函数：判断字符串中是否是字母
            if xor_resulting_char.isalpha() or xor_resulting_char == 0:
                #获得可能的空格位置，统计这个位置和其他字符串异或出现字母的次数
                space_suspect_counts[char_idx] += 1
    #开始假设空格位置来自于ciphertext_a，如果统计的某个位置上满足要求的次数大于等于我所期望的次数，
    #那么我们假设这个位置上就是空格且来自与ciphertext_a中对应的位置
    #space_tolerance_threshold = 0.8
    for char_idx, suspect_count in enumerate(space_suspect_counts):
        #判断出现的次数是否满足要求
        if suspect_count >= max_space_count[char_idx]:
            #通过判断得知密文这个位置上大概率是space，所以，此时 m=space，所以 c⊕space=m⊕k⊕space=k，从而可以求的key值
            suspect_key = ciphertext_a[char_idx] ^ whitespace
            #增加判断，将 key再与其他密文对应位置异或
            #等于说又判断了一次？？？
            for ciphertext_b in ciphertexts:
                if char_idx<len(ciphertext_b):
                    if(ord('A')<=ciphertext_b[char_idx]^suspect_key<=ord('z')):
                        max_space_count[char_idx] = suspect_count
                        key[char_idx]=suspect_key
i=0
target_plaintext=[0]*11
print("====First try:====")
for ciphertext_c in ciphertexts:
    target_plaintext[i]= strXor(ciphertext_c,key)
    print(f"PT_{i}:{target_plaintext[i]}")
    i+=1

print("\n====Second try====")
# 我们发现第10句密文被得到的结果最准确，同过搜索得到对应准确明文，以此来求Key
m10=b'The secret message is: When using a stream cipher, never use the key more than once'
keyMoreLike = keyXor(m10,ciphertexts[10])
print("More precise key:",binascii.b2a_qp(keyMoreLike))
print("PT_8 using more precise key: {}".format(strXor(ciphertexts[7],keyMoreLike)))
