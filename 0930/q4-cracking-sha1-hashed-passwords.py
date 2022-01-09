import hashlib
from itertools import permutations
import multiprocessing
import time
flag = False
def signalCrackProcess(pwd_list, target):
    for i in pwd_list:
        pwd = "".join(ch for ch in i)
        hash = hashlib.sha1(pwd.encode()).hexdigest()
        if hash == target:
            print("done! password:", pwd)
            flag = True
            return True
    return False
    
target = "67ae1a64661ac8b4494666f58c4822408dd0a3e4"

alpha_list = "QqWw%58(=0Ii*+nN"
time_start = time.time()
for i in range(8, 9):
    cnt = 0
    pwd_list = [[] for k in range(8)]
    for j in permutations(alpha_list, i):
        pwd_list[cnt % 8].append(j)
        cnt += 1
        if cnt == 8192:
            pool = []
            for k in range(8):
                pool.append(multiprocessing.Process(target=signalCrackProcess, args=(pwd_list[k], target)))
            for k in pool:
                k.start()
                k.join()
            for k in pool:
                del(k)
            pwd_list = [[] for k in range(8)]
            cnt = 0
        if flag:
            exit()
time_end = time.time()
print("Spend time: ",time_end-time_start)