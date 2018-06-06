class state:

    def reset(participant, key):

        state = "enckey: " + key.hex() + '\n'
        state = state + "received: " + str(0) + '\n'
        addr_space = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        for a in addr_space:
            state = state + a + "-sequence: " + str(0) + '\n'
        statefile = participant + '-statefile.txt'
        ofile = open(statefile, 'wt')
        ofile.write(state)
        ofile.close()

class msg_sender:

    sender = ''
    receiver = ''

    def __init__(self, sender, receiver):

        self.sender = sender
        self.receiver = receiver

    def generate(self, msg):

        from Crypto.Cipher import AES

        statefile = self.sender + '-statefile.txt'

        sequences = {}

        # read the content of the state file
        ifile = open(statefile, 'rt')
        line = ifile.readline()
        enckey = line[len("enckey: "):len("enckey: ")+32]
        enckey = bytes.fromhex(enckey)
        line = ifile.readline()
        received = line[len("received "):]
        received = int(received, base=10)
        line = ifile.readline()
        while line != '':
            participant = line[:1]
            sequence = line[len(participant + "-sequence: "):]
            sequences[participant] = int(sequence, base=10)
            line = ifile.readline()
        ifile.close()

        payload_length = len(msg)
        padding_length = AES.block_size - (payload_length)%AES.block_size

        signature_length = 512 # RSA-PSS

        # compute message length...
        # header: 9 bytes
        #    version: 2 bytes
        #    sender:  1 btye
        #    length:  2 btyes
        #    sqn:     4 bytes
        # iv: AES.block_size
        # payload: payload_length
        # padding: padding_length
        # signature: signature_length
        msg_length = 9 + AES.block_size + payload_length + padding_length + signature_length

        # create header
        header_version = b'\x01\x01'  # protocol version 1.6
        header_sender = self.sender.encode('utf-8')  # sender
        header_length = msg_length.to_bytes(2, byteorder='big')  # message length (encoded on 2 bytes)
        header_sqn = (sequences[self.sender] + 1).to_bytes(4, byteorder='big')    # next message sequence number (encoded on 4 bytes)
        header = header_version + header_sender + header_length + header_sqn

        # encrypt what needs to be encrypted 
        encrypted = self.encrypt(msg, enckey)

        signature = self.sign(header + encrypted)

        # save state
        state = "enckey: " + enckey.hex() + '\n'
        state = state + "received: " + str(received + 1) + '\n'
        sequences[self.sender] = sequences[self.sender] + 1
        for participant in sequences:
            state = state + participant + "-sequence: " + str(sequences[participant]) + '\n'
        ofile = open(statefile, 'wt')
        ofile.write(state)
        ofile.close()
        return header + encrypted + signature

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

    def encrypt(self, msg, keystring):

        ''' AES-CBC '''

        import sys, getopt
        from Crypto.Cipher import AES
        from Crypto.Util import Padding
        from Crypto import Random

        plaintext = msg

        plaintext = Padding.pad(plaintext, AES.block_size)
        iv = Random.get_random_bytes(AES.block_size)
        cipher = AES.new(keystring, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(plaintext)
        
        return (iv + ciphertext)

class msg_receiver:

    sender = ''
    receiver = ''

    def __init__(self, receiver):

        self.receiver = receiver

    def process(self, msg):

        from Crypto.Cipher import AES
        import sys, getopt

        # parse the message
        header = msg[0:9]                   # header is 9 bytes long
        iv = msg[9:9 + AES.block_size]      # iv is AES.block_size bytes long
        encrypted = msg[9 + AES.block_size:]# the rest of the message is the encrypted part
        header_version = header[0:2]        # version is encoded on 2 bytes 
        header_sender = header[2:3]         # sender is encoded on 1 byte
        self.sender = chr(int.from_bytes(header_sender, byteorder='big'))
        header_length = header[3:5]         # msg length is encoded on 2 bytes 
        header_sqn = header[5:9]            # msg sqn is encoded on 4 bytes 

        # print("Message header:")
        # print("   - protocol version: " + header_version.hex() + " (" + str(header_version[0]) + "." + str(header_version[1]) + ")")
        # print("   - message sender: " + header_sender.hex() + " (" + str(int.from_bytes(header_sender, byteorder='big')) + ")")
        # print("   - message length: " + header_length.hex() + " (" + str(int.from_bytes(header_length, byteorder='big')) + ")")
        # print("   - message sequence number: " + header_sqn.hex() + " (" + str(int.from_bytes(header_sqn, byteorder='big')) + ")")

        # check the msg length
        if len(msg) != int.from_bytes(header_length, byteorder='big'):
            print("Warning: Message length value in header is wrong!")
            print("Processing is continued nevertheless...")

        statefile = self.receiver + '-statefile.txt'

        sequences = {}

        # read the content of the state file
        ifile = open(statefile, 'rt')
        line = ifile.readline()
        enckey = line[len("enckey: "):len("enckey: ")+32]
        enckey = bytes.fromhex(enckey)
        line = ifile.readline()
        received = line[len("received "):]
        received = int(received, base=10)
        line = ifile.readline() 
        while line != '':
            participant = line[:1]
            sequence = line[len(participant + "-sequence: "):]
            sequences[participant] = int(sequence, base=10)
            line = ifile.readline()
        ifile.close()

        # check the sequence number
        # print("Expecting sequence number " + str(sequences[self.receiver] + 1) + " or larger...")
        sndsqn = int.from_bytes(header_sqn, byteorder='big')
        if (sndsqn <= sequences[self.sender]):
            print("Error: Message sequence number is too old!")
            print("Processing completed.")
            sys.exit(1)    
        # print("Sequence number verification is successful.")

        # parse decrypted into payload and signature
        signature_length = 512        # RSA-PSS
        payload = encrypted[:-signature_length]
        signature = encrypted[-signature_length:]

        # verify the signature
        # print("Signature verification is being performed...")
        comp_signature = self.verify_signature(header + iv + payload, signature)

        if not comp_signature:
            print("Error: Signature verification failed!")
            print("Processing completed.")
            sys.exit(1)
        # print("Signature verified correctly.")

        # decrypt the encrypted part
        # print("Decryption is attempted...")
        decrypted = self.decrypt(iv + payload, enckey)

        # save state
        state = "enckey: " + enckey.hex() + '\n'
        state = state + "received: " + str(received + 1) + '\n'
        sequences[self.sender] = sndsqn
        for participant in sequences:
            state = state + participant + "-sequence: " + str(sequences[participant]) + '\n'
        ofile = open(statefile, 'wt')
        ofile.write(state)
        ofile.close()
        # print("Receiving state is saved.")
        # print("Processing completed.")

        return decrypted

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

    def decrypt(self, msg, keystring):

        ''' AES-CBC '''

        import sys, getopt
        from Crypto.Cipher import AES
        from Crypto.Util import Padding
        from Crypto import Random

        ciphertext = msg
        iv = ciphertext[:AES.block_size]
        ciphertext = ciphertext[AES.block_size:]

        cipher = AES.new(keystring, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        plaintext = Padding.unpad(plaintext, AES.block_size)
        
        return plaintext.decode('utf-8')


