#AES加密算法    作者：林下の夕      版本：v0.0.1    日期：2022年3月15日
message = b'hello, tomorrow.'
key = b'GOODBYE, TODAY..'
def AES(MessageOrCipher,key,mode):
    '''mode:
            encrypt
    
            decrypt

    '''

    def getjuzhen(m):
        '''排列成字节矩阵'''
        juzheng = []
        M=[]
        for i in range(len(m)):
            if (i+1)%4==0:
                M.append(m[i])
                juzheng.append(M)
                M = []
            else:
                M.append(m[i]) 

        return juzheng
        
    def addroundkey(m,k):
        '''轮密钥加'''
        mm = []
        kk = []
        r = []
        for i in range(4):
            rr = []
            for j in range(4):
                rr.append(m[i][j]^k[i][j])
            r.append(rr)
        return r

    def ext_gcd(a, b):    
        if b == 0:          
            return 1, 0, a     
        else:         
            x, y, gcd = ext_gcd(b, a % b) #递归直至余数等于0(需多递归一层用来判断)        
            x, y = y, (x - (a // b) * y) #辗转相除法反向推导每层a、b的因子使得gcd(a,b)=ax+by成立         
            return x, y, gcd

    def xtime(binnumber1):
        '''GF域内的乘法算法之一'''
        flag = 1
        m = 0b100011011
        m1 = 0b00011011
        # ll2 = list(bin(binnumber2)[2:])
        ll1 = list(bin(binnumber1)[2:].zfill(8))
        p = len(ll1)
        if ll1[0]=='0':
            return binnumber1<<1
        else:
            return (binnumber1<<1)^m

    def times(b1,b2):
        '''GF域内的乘法'''
        ll2 = list(bin(b2)[2:].zfill(8))
        L = []
        vv = b1
        loc = len(ll2)-ll2.index('1')
        # print(loc)
        for i in range(loc):
            L.append(vv)
            vv = xtime(vv)
        r = 0
        j = 0
        lm = ll2[-1::-1]
        for i in range(len(lm)):
            if lm[i]=='1':
                r^=L[i]

        return r

    def liancheng(l):
        '''GF内3的幂'''
        if l ==0:
            return 1
        r = 3
        for i in range(l-1):
            r = times(r, 3)
        return r

    def getre1():
        '''生成元查表求逆'''
        re1={}
        re1[0]=1
        for i in range(1,255):
            re1[i]=liancheng(i)
        re1[255]=1
        return re1
    re1 = getre1()

    def getre2():
        '''生成逆表'''
        re2={}
        re2[1]=0
        for i in range(1,255):
            re2[liancheng(i)]=i
        return re2
    re2 = getre2()

    def findinvert(b,re1,re2):
        if b == 0:
            return 0
        lll = re2[b]
        re = re1[255-lll]
        return re

    def getsbox(b):
        pl = bin(findinvert(b, re1, re2))[2:].zfill(8)
        pppl = []
        for i in pl:
            pppl.append(int(i))
        ppl = pppl[-1::-1]
        m = []
        c1 = (1*ppl[0]) ^ (0*ppl[1]) ^ (0*ppl[2]) ^ (0*ppl[3]) ^ (1*ppl[4]) ^ (1*ppl[5]) ^ (1*ppl[6]) ^ (1*ppl[7]) ^ 1 
        c2 = (1*ppl[0]) ^ (1*ppl[1]) ^ (0*ppl[2]) ^ (0*ppl[3]) ^ (0*ppl[4]) ^ (1*ppl[5]) ^ (1*ppl[6]) ^ (1*ppl[7]) ^ 1 
        c3 = (1*ppl[0]) ^ (1*ppl[1]) ^ (1*ppl[2]) ^ (0*ppl[3]) ^ (0*ppl[4]) ^ (0*ppl[5]) ^ (1*ppl[6]) ^ (1*ppl[7]) ^ 0 
        c4 = (1*ppl[0]) ^ (1*ppl[1]) ^ (1*ppl[2]) ^ (1*ppl[3]) ^ (0*ppl[4]) ^ (0*ppl[5]) ^ (0*ppl[6]) ^ (1*ppl[7]) ^ 0 
        c5 = (1*ppl[0]) ^ (1*ppl[1]) ^ (1*ppl[2]) ^ (1*ppl[3]) ^ (1*ppl[4]) ^ (0*ppl[5]) ^ (0*ppl[6]) ^ (0*ppl[7]) ^ 0 
        c6 = (0*ppl[0]) ^ (1*ppl[1]) ^ (1*ppl[2]) ^ (1*ppl[3]) ^ (1*ppl[4]) ^ (1*ppl[5]) ^ (0*ppl[6]) ^ (0*ppl[7]) ^ 1 
        c7 = (0*ppl[0]) ^ (0*ppl[1]) ^ (1*ppl[2]) ^ (1*ppl[3]) ^ (1*ppl[4]) ^ (1*ppl[5]) ^ (1*ppl[6]) ^ (0*ppl[7]) ^ 1 
        c8 = (0*ppl[0]) ^ (0*ppl[1]) ^ (0*ppl[2]) ^ (1*ppl[3]) ^ (1*ppl[4]) ^ (1*ppl[5]) ^ (1*ppl[6]) ^ (1*ppl[7]) ^ 0 
        m.append(c1)
        m.append(c2)
        m.append(c3)
        m.append(c4)
        m.append(c5)
        m.append(c6)
        m.append(c7)
        m.append(c8)
        bbb = ''.join(str(i) for i in m[-1::-1])
        # return hex(int(bbb,2))
        return int(bbb,2)

    def sbox():
        sbox = {}
        for i in range(256):
            sbox[i]=getsbox(i)
        return sbox

    def ByteSubstitution(byte):
        return sbox()[byte]


    jz1 = [[2, 1,1,3], [3,2,1,1], [1,3,2,1], [1,1,3,2]]
    jz2 = [[0xD4,0xBF,0x5D,0x30], [0x25,0x25,0x25,0x25], [0x25,0x25,0x25,0x25], [0x25,0x25,0x25,0x25]]
    def jztimes(jz1,jz2):
        '''GF域下的矩阵乘法'''
        r = []
        for j in range(4):
            rr = []
            for i in range(4):
                rr.append((times(jz1[0][i], jz2[j][0]) ^ times(jz1[1][i], jz2[j][1]) ^ times(jz1[2][i], jz2[j][2]) ^ times(jz1[3][i],jz2[j][3])))
            r.append(rr)

        return r
        
    def MC(jz):
        '''列混合'''
        jz1 = [[2, 1,1,3], [3,2,1,1], [1,3,2,1], [1,1,3,2]]
        return jztimes(jz1, jz)

    def BS(jz):
        '''字节代换层'''
        r=[]
        for i in range(4):
            rr = []
            for j in range(4):
                rr.append(ByteSubstitution(jz[i][j]))
            r.append(rr)
        return    r

    def wy(jz,j):
        '''行间位移'''
        nn = jz[:]
        rr = []
        for i in range(4):
                x = jz[(i+j)%4][:]
                y = nn[i%4][:]
                y[j]=x[j]
                
                rr.append(y)
        return rr

    def SR(jz):
        '''行位移'''
        r = jz
        for i in range(1,4):
            r = wy(r, i)
            
        return r   

    def danci(jz,k):
        '''一轮加密'''
        n1 = BS(jz)
        n2 = SR(n1)
        n3 = MC(n2)
        r = addroundkey(n3, k)
        return r
        
    def G(k,time):
        '''G函数处理密钥'''
        nn = k[:]
        for i in range(4):
            x = k[(i+1)%4]
            nn[i%4]=x
        rr = nn[:]
        for i in range(4):
            rr[i]=sbox()[nn[i]]
        Rcon = [ 0X00,0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
        rr[0]=rr[0]^Rcon[time]

        return rr

    def oncekeywhitening(key,time):
        '''一次密钥漂白'''
        r = []
        for i in range(4):
            rr = []
            for j in range(4):
                if i==0:
                    rr.append(key[i][j]^G(key[3], time)[j])
                else:
                    rr.append(key[i][j]^r[i-1][j])
            r.append(rr)
        return r

    def KW(key):
        '''生成密钥列表'''
        keys = [key]
        
        for i in range(1,11):
            keys.append(oncekeywhitening(keys[i-1], i))
        return keys

    def encryptAES(m,k):
        keys = KW(k)
        c = addroundkey(m, keys[0])
        # print(BS(c))
        for i in range(1,10):
            c=danci(c, keys[i])
        c = BS(c)
        c=SR(c)
        c = addroundkey(c, keys[10])
        return c


    def inv_sbox():
        return {i:j for j,i in sbox().items()}

    def inv_BS(jz):
        r=[]
        for i in range(4):
            rr = []
            for j in range(4):
                rr.append(inv_ByteSubstitution(jz[i][j]))
            r.append(rr)
        return    r

    def inv_ByteSubstitution(byte):
        return inv_sbox()[byte]

    def inv_addroundkey(m, k):
        return addroundkey(m, k)

    def inv_SR(jz):
        for i in range(3):
            jz = SR(jz)
        return jz

    def inv_MC(jz):
        jz2 = [[14, 9, 13, 11], [11, 14, 9, 13], [13, 11, 14, 9], [9, 13, 11, 14]]
        return jztimes(jz2, jz)

    def decryptAES(c,k):
        state = getjuzhen(c)
        keys = KW(getjuzhen(k))
        state = inv_addroundkey(state, keys[-1])
        state = inv_SR(state)
        state = inv_BS(state)
        
        for i in range(1,10):
            state = inv_addroundkey(state, keys[10-i])
            state = inv_MC(state)
            state = inv_SR(state)
            state = inv_BS(state)
        state = inv_addroundkey(state, keys[0])
        return state

    def bytes2matrix(text):
        """ Converts a 16-byte array into a 4x4 matrix.  """
        return [list(text[i:i+4]) for i in range(0, len(text), 4)]

    def matrix2bytes(matrix):
        
        """ Converts a 4x4 matrix into a 16-byte array.  """
        r = b''
        for i in matrix:
            r+=bytes(i)

        return r

    if len(MessageOrCipher)!=16 or type(MessageOrCipher)!=bytes:
        print('MessageOrCipher is not a 16-bytes-long Bytes()!')
        return None
    
    if len(key)!=16 or type(MessageOrCipher)!=bytes:
        print('Key is not a 16-bytes-long Bytes()!')
        return None

    if mode == 'encrypt':
        return matrix2bytes(encryptAES(getjuzhen(MessageOrCipher), getjuzhen(key)))

    elif mode == 'decrypt':
        return matrix2bytes(decryptAES(MessageOrCipher, key))

    else:
        print('please enter the right mode (decrypt or encrypt)!!!')
        return None

# print(AES(message, key, 'encrypt'))
c = b'\n\xbc\xc2sJ\xc7\xc1\xd3YZf\xd8\x96g\x8c\xe1'
print(AES(c, key, 'decrypt'))

# 相当于
# from Crypto.Cipher.AES import *
# a = new(b'GOODBYE, TODAY..', MODE_ECB)
# c= a.encrypt(b'hello, tomorrow.')
