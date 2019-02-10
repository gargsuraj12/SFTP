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