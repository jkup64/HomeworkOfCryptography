import binascii
from hashlib import sha1
from Crypto.Cipher import AES

def odd_even(x):
    res_bin = ""
    x_bin = bin(int(x,16))[2:]
    for i in range(0, len(x_bin), 8):
        if x_bin[i:i+7].count("1") % 2 == 0:
            res_bin += x_bin[i:i+7] + '1'
        else:
            res_bin += x_bin[i:i+7] + '0'
    res_hex = hex(int(res_bin,2))
    return res_hex[2:]

# blurred_visa = "12345678<8<<<1110182<111116?<<<<<<<<<<<<<<<4"
# print(blurred_visa[21:27])
# a = [1,1,1,1,1,6]
# b = [7,3,1]
# res = 0
# for i in range(len(a)):
#     res += a[i] * b[i%3]
# print(res%10)
clear_visa = "12345678<8<<<1110182<1111167<<<<<<<<<<<<<<<4"
read_info = clear_visa[0:10] + clear_visa[13:20] +clear_visa[21:28]
# print(read_info)
K_seed = sha1(read_info.encode()).hexdigest()[:32]
c = "00000001"
D = K_seed + c
H = sha1(binascii.a2b_hex(D)).hexdigest()
K_a = H[:16]
K_b = H[16:32]
key = odd_even(K_a) + odd_even(K_b)
key = binascii.a2b_hex(key)
ct = binascii.a2b_base64("9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI")
iv = bytes([0] * AES.block_size)
cipher = AES.new(key, AES.MODE_CBC, iv)
print("Key =",key)
print("Pt =",cipher.decrypt(ct))
