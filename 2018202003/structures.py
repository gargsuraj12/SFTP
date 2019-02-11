import hashlib
import random

global prime
prime = 1000000007

global alpha
alpha = 2

global MAX_CONNECTIONS
MAX_CONNECTIONS = 20

global MAX_SIZE
MAX_SIZE = 80

global MAX_LEN
MAX_LEN = 2048

global MAX_BUFF_SIZE
MAX_BUFF_SIZE = 1024

global UNSUCCESSFUL
UNSUCCESSFUL = 0

global SUCCESSFUL
SUCCESSFUL = 1

global PROCESSING
PROCESSING = 2

global EOF_MARKER
EOF_MARKER = 1

# Protocol Messages
global LOGINCREAT
LOGINCREAT = 10
global LOGINREPLY
LOGINREPLY = 20
global AUTHREQUEST
AUTHREQUEST = 30
global AUTHREPLY
AUTHREPLY = 40
global SERVICEREQUEST
SERVICEREQUEST = 50
global SERVICEERROR
SERVICEERROR = 51
global SERVICEDONE
SERVICEDONE = 60
global KEYESTAB
KEYESTAB = 70
global KEYESTABDONE
KEYESTABDONE = 80
global EXIT
EXIT = 90


class Header:
    def __init__(self, opcode, sourceAddr, destAddr):
        self.opcode = opcode
        self.sourceAddr = sourceAddr
        self.destAddr = destAddr

class Message:
    def __init__(self):
        self.header = None
        self.buffer = None
        self.id = None
        self.q = None
        self.password = None
        self.status = None
        self.file = None
        self.dummy = None        

encryptDict = {' ' : 0	, 'A' : 1, 'B' : 2, 'C' : 3, 'D' : 4, 'E' : 5, 'F' : 6, 'G' : 7, 'H' : 8, 'I' : 9, 'J' : 10, 'K' : 11, 'L' : 12, 'M' : 13, 'N' : 14, 'O' : 15, 'P' : 16, 'Q' : 17, 'R' : 18, 'S' : 19, 'T' : 20, 'U' : 21, 'V' : 22, 'W' : 23, 'X' : 24, 'Y' : 25, 'Z' : 26, ',' : 27, '.' : 28, '?' : 29, '0' : 30, '1' : 31, '2' : 32, '3' : 33, '4' : 34, '5' : 35, '6' : 36, '7' : 37, '8' : 38, '9' : 39, 'a' : 40, 'b' : 41, 'c' : 42, 'd' : 43, 'e' : 44, 'f' : 45, 'g' : 46, 'h' : 47, 'i' : 48, 'j' : 49, 'k' : 50, 'l' : 51, 'm' : 52, 'n' : 53, 'o' : 54, 'p' : 55, 'q' : 56, 'r' : 57, 's' : 58, 't' : 59, 'u' : 60, 'v' : 61, 'w' : 62, 'x' : 63, 'y' : 64, 'z' : 65, '!' : 66}

decryptDict = {0 : ' ', 1 : 'A', 2 : 'B', 3 : 'C', 4 : 'D', 5 : 'E', 6 : 'F', 7 : 'G', 8 : 'H', 9 : 'I', 10 : 'J', 11 : 'K', 12 : 'L', 13 : 'M', 14 : 'N', 15 : 'O', 16 : 'P', 17 : 'Q', 18 : 'R', 19 : 'S', 20 : 'T', 21 : 'U', 22 : 'V', 23 : 'W', 24 : 'X', 25 : 'Y', 26 : 'Z', 27 : ',', 28 : '.', 29 : '?', 30 : '0', 31 : '1', 32 : '2', 33 : '3', 34 : '4', 35 : '5', 36 : '6', 37 : '7', 38 : '8', 39 : '9', 40 : 'a', 41 : 'b', 42 : 'c', 43 : 'd', 44 : 'e', 45 : 'f', 46 : 'g', 47 : 'h', 48 : 'i', 49 : 'j', 50 : 'k', 51 : 'l', 52 : 'm', 53 : 'n', 54 : 'o', 55 : 'p', 56 : 'q', 57 : 'r', 58 : 's', 59 : 't', 60 : 'u', 61 : 'v', 62 : 'w', 63 : 'x', 64 : 'y', 65 : 'z', 66 : '!'}

delimeter = '-'
MODVAL = 67

def calcHash(password):
    result = hashlib.sha1(password.encode())
    result = result.hexdigest()
    return result

def encryptString(key, data:str):
    # print("inside encryptString() with key: ", key)
    key = key % MODVAL
    # print("key is: ", key)
    # print("Data is: ", data)
    encryptedData = ''
    for ch in data:
        # print("ch is: ", ch)
        eChar = (encryptDict[ch] + key) % MODVAL
        # print("for ", ch, " encrypted is: ", eChar)
        
        # encryptedData += str(eChar)+delimeter
        encryptedData += decryptDict[eChar]
    # encryptedData = encryptedData[:-1]    
    return encryptedData 

def encryptMessageObj(key, message : Message):
    # print("Key in encryptMessageObj() is: ", key)
    if message.buffer != None:
        message.buffer = encryptString(key, message.buffer)
    
    if message.id != None:
        message.id = encryptString(key, message.id)
    
    if message.q != None:
        message.q = encryptString(key, str(message.q))
    
    if message.password != None:
        message.password = encryptString(key, message.password)
        
    if message.status != None:
        message.status = encryptString(key, str(message.status))

    if message.file != None:
        message.file = encryptString(key, message.file)

    if message.dummy != None:
        message.dummy = encryptString(key, str(message.dummy))

    return message            

def decryptString(key, data:str):
    key = key % MODVAL
    print("key is: ", key)
    decryptedData = ''  
    for s in data:
        # print("s is: ", s)
        # num = int(s)
        num = int(encryptDict[s])
        num = num - key
        if num < 0:
            num = num + MODVAL
        else:
            num = num % MODVAL

        # num = ((num % MODVAL) + (-key % MODVAL) - 1) % MODVAL
        # print("Num is: ", num)
        decryptedData += decryptDict[num]
    # print("decrypted data is: ", decryptedData)    
    return decryptedData

def decryptMessageObj(key, message : Message):
    if message.buffer != None:
        message.buffer = decryptString(key, message.buffer)
    
    if message.id != None:
        message.id = decryptString(key, message.id)
    
    if message.q != None:
        message.q = int(decryptString(key, str(message.q)))
    
    if message.password != None:
        message.password = decryptString(key, message.password)
    
    if message.status != None:
        message.status = int(decryptString(key, str(message.status)))

    if message.file != None:
        message.file = decryptString(key, message.file)

    if message.dummy != None:
        message.dummy = int(decryptString(key, str(message.dummy)))

    return message

def printMessage(message):
    if message.buffer != None:
        print("buffer is: ", message.buffer)
    
    if message.id != None:
        print("id is: ", message.id)
    
    if message.q != None:
        print("q is: ", message.q)
    
    if message.password != None:
        print("password is: ", message.password)
    
    if message.status != None:
        print("status is: ", message.status)

    if message.file != None:
        print("file is: ", message.file)

    if message.dummy != None:
        print("dummy is: ", message.dummy)


def rabinMiller(num):
    s = num - 1
    t = 0
    while s % 2 == 0:
        s = s // 2
        t += 1
    for trials in range(5): # try to falsify num's primality 5 times
        a = random.randrange(2, num - 1)
        v = pow(a, s, num)
        if v != 1: # this test does not apply if v is 1.
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % num
    return True


# if __name__ == '__main__':
#     key = 141668497
#     msg = Message()
#     msg.id = "c1"
#     msg.q = 1000000007
#     msg.password = "c1"
#     msg = encryptMessageObj(key, msg)
#     print("After encryption:")
#     printMessage(msg)
#     msg = decryptMessageObj(key, msg)
#     # num = decryptString(key, msg.q)
#     print("After decryption:")
#     printMessage(msg)
#     # print(num)