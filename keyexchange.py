# key establishment protocol uses public key cryptography to establish a symmetric session key
import sys

class key_sender:
    sender = ''

    def __init__(self, sender):
        self.sender = sender

    # generate and send key
    def generate(self):
        from Crypto.Random import get_random_bytes

        # generate symmetric key
        symkey = get_random_bytes(16)
        return symkey

    def send(self, key, receiver):
        # imports
        from Crypto.Cipher import PKCS1_OAEP
        from Crypto.PublicKey import RSA
        import datetime

        # encrypt the symmetric key using reciever's public key
        publickeyfile = open(receiver + '-pubkey.pem')
        publickeystr = publickeyfile.read()
        publickeyfile.close()
        pubkey = RSA.import_key(publickeystr)
        RSAcipher = PKCS1_OAEP.new(pubkey)
        esymkey = RSAcipher.encrypt(key)
        #hexesymkey = (RSAcipher.encrypt(key)).hex() # symkey in hex

        # timestamp
        timestamp = str(datetime.datetime.utcnow()).encode('utf-8')

        # header
        header = (self.sender + receiver).encode('utf-8')

        # signature
        signature = self.sign(header + timestamp + esymkey)

        return header + timestamp + esymkey + signature

    def sign(self, msg_to_be_signed):

        from Crypto.Signature import PKCS1_PSS
        from Crypto.Hash import SHA256
        from Crypto.PublicKey import RSA

        h = SHA256.new()
        h.update(msg_to_be_signed)
        kfile = open(self.sender + '-key.pem', 'r')
        keystr = kfile.read()
        kfile.close()
        key = RSA.import_key(keystr)
        signer = PKCS1_PSS.new(key)
        signature = signer.sign(h)
        return signature


class key_receiver:
    sender = ''
    receiver = ''

    def __init__(self, receiver):
        self.receiver = receiver
        self.sender = None

    def process(self, msg):
        # imports
        from datetime import datetime
        from datetime import timedelta
        from Crypto.Cipher import PKCS1_OAEP
        from Crypto.PublicKey import RSA

        # parse
        header_sender = (msg[0:1]).decode('ascii')
        self.sender = header_sender
        header_receiver = (msg[1:2]).decode('ascii')
        timestamp = msg[2:28].decode('ascii')

        esymkey = msg[28:540]
        signature = msg[540:]

        # make sure the receiver is correct
        if (header_receiver != self.receiver):
            print("Receiver of message is incorrect")
            sys.exit(1)

        # make sure time difference is under one hour, flexible
        send_datetime = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f')
        receive_datetime = datetime.utcnow()
        timediff = (receive_datetime - send_datetime)/timedelta(minutes=1)
        #FOR TESTING PURPOSES TIMESTAMP WILL NOT GET EXPIRED

        ''''
        if (timediff> 60):
            print("Time of send message has expired")
            return False
        '''

        #verify the signature

        byteh = (header_sender+header_receiver+timestamp).encode('utf-8')

        if not(self.verify_signature(byteh+esymkey,signature)):
            print("Signature could not be verified")
            sys.exit(1)

        #decrypt the symmetric key and return it
        privatekeyfile = open(self.receiver + '-key.pem', 'r')
        privkeystr = privatekeyfile.read()
        privatekeyfile.close()
        privkey = RSA.import_key(privkeystr)
        RSAcipher = PKCS1_OAEP.new(privkey)
        symkey = RSAcipher.decrypt(esymkey)
        return self.sender, symkey

    def verify_signature(self, msg_signed, signature):

        from Crypto.Signature import PKCS1_PSS
        from Crypto.Hash import SHA256
        from Crypto.PublicKey import RSA

        h = SHA256.new()
        h.update(msg_signed)
        kfile = open(self.sender + '-pubkey.pem', 'r')
        pubkeystr = kfile.read()
        kfile.close()
        pubkey = RSA.import_key(pubkeystr)
        verifier = PKCS1_PSS.new(pubkey)
        if verifier.verify(h, signature):
            return True
        return False

