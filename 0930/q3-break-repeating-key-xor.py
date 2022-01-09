import base64
'''
1.先求key的长度: 从2-42进行遍历，将密文(bytes形式)进行顺序分组，计算根据Hamming distance(利用不同位异或结果为1)
2.按照同一个密钥字符进行分组,每组就转化成了 single_key_XOR: 根据字母出现的频率得到分数最高的, 得到key
3.密文和key进行循环异或
'''
def hamm (s1, s2):
    # 利用不同位异或结果为1来计算两相同长度字符串的不同位数
    assert len(s1)==len(s2)
    dist = 0
    for a,b in zip(s1,s2):
        dist += (bin(a^b).count('1'))
    return dist

def find_key_len(c):
    aver_hamm=[] #列表的每项为 密钥长度和对应的标准化汉明码均值
    for keylen in range(2,41):
        #将密文分组
        tmp_aver_hamm=[]
        test1 = c
        # 为方便编程，此处对所有密文进行如下计算（而非只求6组）：
        while len(test1) >= (2 * keylen):
            x = test1[:keylen]
            y = test1[keylen:(2 * keylen)]
            score = hamm(x, y) / keylen
            test1 = test1[(2 * keylen):]
            tmp_aver_hamm.append(score)
        res={
                'keylength': keylen,
                'avg distance': sum(tmp_aver_hamm)/len(tmp_aver_hamm)
            }
        aver_hamm.append(res)
    # 根据最小汉明码距离确定最有可能的密钥长度，这里只返回最有可能的一项，若结果不正确再多返回已排序的几项
    possible_key_length = sorted(aver_hamm, key=lambda x: x['avg distance'])[0]
    return  possible_key_length['keylength']

def get_english_score(input_bytes):
    """Compares each input byte to a character frequency chart and returns the score of a message based on the
    relative frequency the characters occur in the English language
    """
    # From https://en.wikipedia.org/wiki/Letter_frequency
    # with the exception of ' ', which I estimated.
    character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }
    return sum([character_frequencies.get(chr(byte), 0) for byte in input_bytes.lower()])

def keyXor(m,k):
    return bytes([m[i]^k[i%len(k)] for i in range(len(m))])

def single_char_xor(m, k):
    return bytes([k^i for i in m])

def bruteforce_single_char_xor(ciphertext):
    potential_messages = []
    for key_value in range(256):
        message = single_char_xor(ciphertext, key_value)
        score = get_english_score(message)
        data = {
            'message': message,
            'score': score,
            'key': key_value
        }
        potential_messages.append(data)
    return sorted(potential_messages, key=lambda x: x['score'], reverse=True)[0]['key']

cipher=open("w2-break-repeating-key-xor.txt").read().replace('\n','')
# convert to bytes
cipher=base64.b64decode(cipher)
keylen=find_key_len(cipher)
print(keylen)
#分组
key=[]
for index in range(keylen):
    sub_cipher=cipher[index::keylen]
    ## single_key_XOR:
    key.append(bruteforce_single_char_xor(sub_cipher))
print(''.join(chr(i) for i in key))
print(keyXor(cipher,bytes(''.join(chr(i) for i in key),encoding='utf8')))