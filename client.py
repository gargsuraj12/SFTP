import structures as st
import random
import sys, traceback
import socket
import pickle
import os

X_A = None
SESSION_KEY = None

def closeConnection(conn):
    header = st.Header(st.EXIT, myIP, serverIP)
    reqMsgObj = st.Message()
    reqMsgObj.header = header
    reqMsg = pickle.dumps(reqMsgObj)
    conn.send(reqMsg)
    conn.close()

def establiishKey(conn, myIP, serverIP):
    global SESSION_KEY
    Y_A = pow(st.alpha, X_A, st.prime)
    
    header = st.Header(st.KEYESTAB, myIP, serverIP)
    reqMsgObj = st.Message()
    reqMsgObj.header = header
    reqMsgObj.dummy = Y_A
    
    # Serializing object into ByteString
    reqMsg = pickle.dumps(reqMsgObj)
    conn.send(reqMsg)
    
    # Deserializing received string into object
    replyMsg= conn.recv(st.MAX_LEN)
    replyMsgObj = pickle.loads(replyMsg)

    if replyMsgObj.status == st.SUCCESSFUL:
        Y_B = replyMsgObj.dummy
        SESSION_KEY = pow(Y_B, X_A, st.prime)
        print("Session key sucessfully established and is: ", SESSION_KEY)
        return True
    else:
        print("Unable to setup session key as Y_B not supplied by server..")
        # Needs to close the connection at the server
        # conn.close()
        closeConnection(conn)
        quit()
    return False


def loginCreate(conn, myIP, serverIP):
    # Later all the valid fields of Message object needs to be encrypted using the already established key between this client and server -- ToDo
    id = input("Enter the client's ID: ")
    password = input("Enter the client's password: ")
    
    header = st.Header(st.LOGINCREAT, myIP, serverIP)
    reqMsgObj = st.Message()
    reqMsgObj.header = header
    reqMsgObj.id = id
    reqMsgObj.password = password
    reqMsgObj.q = st.prime
    
    # First Message needs to be encrypted -- ToDo
    # do not encrypt header
    reqMsg = pickle.dumps(reqMsgObj)
    conn.send(reqMsg)

    replyMsg = conn.recv(st.MAX_LEN)
    replyMsgObj = pickle.loads(replyMsg)
    # Now the reply Meaasge and header needs to be decrypted -- ToDo
    if replyMsgObj.status == st.SUCCESSFUL:
        print("Client successfully registered at server..")
        return True
    else:
        print("Error occurred while registering client at server..")
        # Needs to close the connection at the server
        # conn.close()
        closeConnection(conn)
        quit()
    return False


def authenticate(conn, myIP, serverIP):
    id = input("Enter the this client's ID: ")
    password = input("Enter the client's password: ")
    
    header = st.Header(st.AUTHREQUEST, myIP, serverIP)
    reqMsgObj = st.Message()
    reqMsgObj.header = header
    reqMsgObj.id = id
    reqMsgObj.password = password
    reqMsgObj.q = st.prime

    # First Message needs to be encrypted -- ToDo
    # do not encrypt header
    reqMsg = pickle.dumps(reqMsgObj)
    conn.send(reqMsg)

    replyMsg = conn.recv(st.MAX_LEN)
    replyMsgObj = pickle.loads(replyMsg)
    # Now the reply Meaasge and header needs to be decrypted -- ToDo
    if replyMsgObj.status == st.SUCCESSFUL:
        print("Client successfully authenticated at server..")
        return True
    else:
        print("Error occurred while authenticating client at server..")
        # Needs to close the connection at the server
        # conn.close()
        closeConnection(conn)
        quit()
    return False


def downloadFile(conn, myIP, serverIP):

    fileName = input("Enter the file name to be downloaded: ")
    header = st.Header(st.SERVICEREQUEST, myIP, serverIP)
    reqMsgObj = st.Message()
    reqMsgObj.header = header
    reqMsgObj.file = fileName
    reqMsg = pickle.dumps(reqMsgObj)
    conn.send(reqMsg)

    try:
        filePath = "downloads/" + fileName
        filePtr = open(filePath, "wb")
    except IOError:
        print("Unable to open file: ", fileName)
        closeConnection(conn)
    try:
        i = 1
        while True:
            replyMsg = conn.recv(st.MAX_LEN)
            print("Chunk number is: ", i)
            print("Len of reply message is: ", len(replyMsg))
            print("Reply message is: ", replyMsg)
            replyMsgObj = pickle.loads(replyMsg)
            # Decrypt the Message() -- ToDo
            if replyMsgObj.header.opcode == st.SERVICEERROR:
                print("Error occurred while downloading the file from server")
                filePtr.close()
                if os.path.exists(filePath):
                    os.remove(filePath)
                closeConnection(conn)
                quit()
            
            # else
            data = replyMsgObj.buffer
            # print("chunk:",i," is:\n", data)
            i += 1    
            filePtr.write(data)
            # checking whether the current chunk is the last one
            if replyMsgObj.status == st.SUCCESSFUL:
                print("File has been downloaded successfully..")
                filePtr.close()
                break
    except:
        print("Exception occured while downloading the file from server..")
        exc_type, exc_value, exc_traceback = sys.exc_info()
        print("*** print_exception:")
        traceback.print_exception(exc_type, exc_value, exc_traceback,limit=2, file=sys.stdout)
        print("*** print_tb:")
        traceback.print_tb(exc_traceback, limit=1, file=sys.stdout)
        filePtr.close()
        closeConnection(conn)
        quit()            
    # finally:
    #     filePtr.close()

if __name__ == '__main__':
    if len(sys.argv) != 5: 
        print ("Insufficent arguements!! Correct usage: script, client IP address, client port number, server IP address, server port number")
        exit() 

    myIP = str(sys.argv[1]) 
    myPort = int(sys.argv[2])
    serverIP = str(sys.argv[3])
    serverPort = int(sys.argv[4])
    
    # Setting private X_A
    X_A = random.randint(2, st.prime)
    
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("Socket successfully created..")
        conn.bind((myIP, myPort))
        print("Socket successfully binded..")
        conn.connect((serverIP, serverPort))
    except:
        print("Creating a client connection is unsuccessful..")
        quit()
    rcvdMsg = conn.recv(st.MAX_LEN)
    if rcvdMsg:
        rcvdMsg = rcvdMsg.decode('ascii')
        print("From Server: ", rcvdMsg)
    else:
        print("No initial reply received from server..")
        quit()
    # Establishing the key between this client and server
    
    SESSION_KEY = establiishKey(conn, myIP, serverIP)
    
    loginCreate(conn, myIP, serverIP)

    authenticate(conn, myIP, serverIP)
    
    downloadFile(conn, myIP, myPort)
    # while True:
    #     fileName = input("Enter the name of the file to be downloaded: ")
    closeConnection(conn)
    conn.close()
    