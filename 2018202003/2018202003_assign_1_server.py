import sys, traceback
import structures as st
import random
import socket
import pickle
import os
import threading as th

X_B = None
# Stores the symmetric-key as value with tuple(ip,port) as the dictionary key
keyDict = {}

class User:
    def __init__(self, salt, password, prime):
        self.salt = salt
        self.password = password
        self.prime = prime

# Contains various user objects
userDict = {}

def loginCreate(rcvdMsgObj):
    try:
        id = rcvdMsgObj.id
        # Checking if this userId already present in the dictionary
        if id in userDict.keys():
            print("User with id: ", id, " is already present..")
            return False

        password = rcvdMsgObj.password
        print("Password received is: ", password)
        prime = rcvdMsgObj.q
        salt = random.randint(2,100000000)
        password = password + str(salt) + str(prime)
        print("Password to store is: ", password)
        # Now password needs to be hashed
        password = st.calcHash(password)

        userObj = User(salt, password, prime)
        print("User object created..")
        userDict[id] = userObj
        print("User obj stored in dictionary..")

        # pickle.dump(userDict, open("PasswordFile.pkl",'w'))
        
        return True
    except:
        print("Exception occurred while loginCreate()..")
        print("Exception is: ", sys.exc_info()[0])
        return False

def authenticateClient(id, password):
    try:
        if id in userDict.keys() == False:
            print("User not present in userDict{}..")
            return False
        print("User present in userDict{}..")    
        user = userDict[id]
        password = password + str(user.salt) + str(user.prime)
        password = st.calcHash(password)
        if password == user.password:
            print("Passwords matched..")
            return True
        else:
            print("Passwords did not match..")
            return False    
    except:
        print("Exception occurred while authenticateClient()..")
        print("Exception is: ", sys.exc_info())
        return False


def uploadFile(conn, fileName, myIP, clientIP, key):
    filePath = fileName
    header = None
    replyMsgObj = None
    replyMsg = None
    
    try:
        filePtr = open(filePath, "r")
    except IOError:
        print("Unable to open file: ", fileName)
        header = st.Header(st.SERVICEERROR, myIP, clientIP)
        replyMsgObj = st.Message()
        replyMsgObj.header = header
        replyMsg = pickle.dumps(replyMsgObj)
        conn.send(replyMsg)
        return False
    
    flag = False
    try:
        i = 1
        fileStat = os.stat(filePath)
        fileSize = fileStat.st_size
        conn.send(str(fileSize).encode('ascii'))
        while True:
            data = filePtr.read(st.MAX_BUFF_SIZE)

            # Encrypt the data
            data = st.encryptString(key, data)

            replyMsg = data
            
            if data == b'' or len(data) < st.MAX_BUFF_SIZE:
                flag = True
            conn.send(replyMsg.encode('ascii')) 
            print("sending chunk:" ,i)
            print("chunk data after encryption is:\n", data)
            
            i += 1
            if flag:
                print("This is the last chunk to be sent from server..")
                break

        if flag:
            print("File sent to the client successfully..")
        return flag
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        print("Error occurred while sending the file to the client..")
        print("*** print_exception:")
        traceback.print_exception(exc_type, exc_value, exc_traceback,limit=2, file=sys.stdout)
        print("*** print_tb:")
        traceback.print_tb(exc_traceback, limit=1, file=sys.stdout)

        filePtr.close()
        header = st.Header(st.SERVICEERROR, myIP, clientIP)
        replyMsgObj = st.Message()
        replyMsgObj.header = header
        replyMsg = pickle.dumps(replyMsgObj)
        conn.send(replyMsg)
        return False


def processClient(conn, clientAddr, myIP):
    replyMsg = "You are now connected with " + myIP + "\n"
    conn.send(replyMsg.encode('ascii'))
    clientIP = clientAddr[0]
    while True:
        # 
        rcvdMsg = conn.recv(st.MAX_LEN)
        # print("From client: ",rcvdMsg)
        rcvdMsgObj = pickle.loads(rcvdMsg)  
        print("Received obj before decryption is: ")
        st.printMessage(rcvdMsgObj)
        # First Decrypt the received message
        # It is assumed that header is not encrypted
        
        opcode = rcvdMsgObj.header.opcode
        if opcode == st.EXIT:
            print("inside EXIT")
            conn.close()
            break
        
        elif opcode == st.KEYESTAB:
            print("Inside KEYESTAB")
            Y_A = rcvdMsgObj.dummy
            key = pow(Y_A, X_B, st.prime)
            keyDict[clientAddr] = key
            print("Session Key for client: ",clientAddr, " is: ",key)
            Y_B = pow(st.alpha, X_B, st.prime)
            header = st.Header(st.KEYESTABDONE, myIP, clientIP)
            replyMsgObj = st.Message()
            replyMsgObj.header = header
            replyMsgObj.dummy = Y_B
            replyMsgObj.status = st.SUCCESSFUL
            replyMsg = pickle.dumps(replyMsgObj)
            conn.send(replyMsg)

        elif opcode == st.LOGINCREAT:
            print("Inside LOGINCREAT")
            
            key = keyDict[clientAddr]
            print("key is: ", key)
            rcvdMsgObj = st.decryptMessageObj(key, rcvdMsgObj)
            print("Message after decryption is: ")
            st.printMessage(rcvdMsgObj)

            rv = loginCreate(rcvdMsgObj)
            header = st.Header(st.LOGINREPLY, myIP, clientIP)
            replyMsgObj = st.Message()
            replyMsgObj.header = header
            if rv:
                replyMsgObj.status = st.SUCCESSFUL
            else:
                replyMsgObj.status = st.UNSUCCESSFUL
            
            # Encrypt the reply message object
            replyMsgObj = st.encryptMessageObj(key, replyMsgObj)

            replyMsg = pickle.dumps(replyMsgObj)
            conn.send(replyMsg) 

        elif opcode == st.AUTHREQUEST:
            print("Inside AUTHREQUEST")
            
            key = keyDict[clientAddr]
            rcvdMsgObj = st.decryptMessageObj(key, rcvdMsgObj)

            rv = authenticateClient(rcvdMsgObj.id, rcvdMsgObj.password)
            header = st.Header(st.AUTHREPLY, myIP, clientIP)
            replyMsgObj = st.Message()
            replyMsgObj.header = header
            if rv:
                replyMsgObj.status = st.SUCCESSFUL
            else:
                replyMsgObj.status = st.UNSUCCESSFUL

            # Encrypt the reply message object
            replyMsgObj = st.encryptMessageObj(key, replyMsgObj)

            replyMsg = pickle.dumps(replyMsgObj)
            conn.send(replyMsg)

        elif opcode == st.SERVICEREQUEST:
            print("Inside SERVICEREQUEST")

            key = keyDict[clientAddr]
            rcvdMsgObj = st.decryptMessageObj(key, rcvdMsgObj)

            uploadFile(conn, rcvdMsgObj.file, myIP, clientIP, key)
        else:
            print("Inside else")
            pass            


if __name__ == '__main__':
    # checks whether sufficient arguments have been provided 
    if len(sys.argv) != 3: 
        print ("Insufficent arguements!! Correct usage: script, IP address, port number")
        exit()

    # dbfile = open('PasswordFile.pkl')      
    # userDict = pickle.load(dbfile)

    myIP = str(sys.argv[1])
    myPort = int(sys.argv[2])

    X_B = random.randint(2, st.prime)
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
    print("Socket successfully created")
    
    server.bind((myIP, myPort)) 
    print("successfully binded..")

    server.listen(st.MAX_CONNECTIONS) 
    print("Server is listening..")

    while True:
        # inp = input()
        conn, clientAddr = server.accept() 
        print("Connection accepted for client: ", clientAddr)
        th.Thread(target=processClient, args=(conn, clientAddr, myIP)).start()
        # processClient(conn, clientAddr, myIP)


    server.close()
        