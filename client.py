import socket
import sys
import select
import traceback
from time import sleep
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import random
from Crypto import Random
from threading import Thread, Event

chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890'

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print('Started chat-client')
try:
    ip = sys.argv[1]
    port = int(sys.argv[2])
    name = sys.argv[3]
except:
    try:
        ip = input('IP > ')
        port = int(input('PORT > '))
        name = input('NAME > ')
    except:
        sys.exit()
try:
    server.connect((ip,port))
except:
    print('connection refused')
    sys.exit()


class client:
    def __init__(self):
        self.event = Event()
        self.event2 = Event()
        self.aes_key = ''
        self.sockets_list = [sys.stdin, server]
        self.user_keys = []

    def create_user_key(self,temp_key,server_key):
        server = [chars.find(x) for x in list(server_key)]
        user = [chars.find(x) for x in list(temp_key)]
        rev_user = user[::-1]
        key1 = []
        key2 = []
        final_key = ''
        for i in range(len(server)):
            x = abs(server[i] - user[i])
            y = int((server[i] + user[i]) / 2)
            key1.append(x)
            key2.append(y)
        for i in range(len(key1)):
            z = abs(key1[i] - key2[i])
            if i % 2 == 0:
                char = chars[z]
            else:
                char = chars[-z]
            final_key = final_key+char
        return final_key[::-1]

    def AES_encrypt_message(self,message):
        if not isinstance(message,str):
            message = message.decode('utf-8')
        if len(bytes(message, encoding='utf-8')) % 16 != 0:
            message = message + '|'
            while len(bytes(message, encoding='utf-8')) % 16 != 0:
                message = message + random.choice(chars)
        message = bytes(message,'utf-8')
        iv = Random.new().read(16)
        obj = AES.new(self.aes_key,AES.MODE_CBC,iv)
        return iv + obj.encrypt(message)

    def AES_decrypt_message(self,message):
        iv = message[:16]
        message = message[16:]
        obj = AES.new(self.aes_key,AES.MODE_CBC,iv)
        message = obj.decrypt(message).decode('utf-8')
        if '|' in message:
            message = message[:message.find('|')]
        return message

    def RSA_encrypt_message(self,message,key):
        key = RSA.import_key(key)
        try:
            message = bytes(message,'utf-8')
        except:
            pass
        obj = PKCS1_OAEP.new(key)
        return obj.encrypt(message)

    def RSA_decrypt_message(self,message):
        return self.obj.decrypt(message)

    def generate_RSA_keys(self):
        RSA_keys = RSA.generate(2048)
        self.public_key = self.AES_encrypt_message(RSA_keys.publickey().exportKey())
        self.private_key = self.AES_encrypt_message(RSA_keys.exportKey())
        self.obj = PKCS1_OAEP.new(RSA_keys)

    def establish_handshake(self):
        temp = ''.join(random.choice(list(chars)) for i in range(32))
        print('Establishing handshake')
        sys.stdout.write("\033[F")
        server.send(bytes(temp,'utf-8'))
        print(f'Sent key ({temp})')
        key = server.recv(2048).decode('utf-8')
        if key == '':
            print('Failed to receive server key.')
            sys.exit()
        sys.stdout.write("\033[F")
        print(f'Recieved server key ({key})')
        sys.stdout.write("\033[F")
        self.aes_key = bytes(self.create_user_key(temp,key),'utf-8')
        server.send(self.AES_encrypt_message(name))

        self.generate_RSA_keys()

        server.send(self.public_key)
        self.event.set()
        self.event2.set()
        print('Successfully connected to server!                                           ')

    def listen(self):
        while self.event.is_set():
            try:
                self.sockets_list = [sys.stdin, server]
                self.read_sockets, self.write_socket, error_socket = select.select(self.sockets_list,[],[])
                for socks in self.read_sockets:
                    if socks == server:
                        message = socks.recv(2048)
                        if message == b'':
                            raise Exception('lost connection')
                        try:
                            message = self.AES_decrypt_message(message)
                            if 'RSA' in message:
                                self.user_keys = list(filter(None,message[4:].split('~~~')))
                            else:
                                print(message)
                        except Exception as e:
                            message = self.RSA_decrypt_message(message)
                            print(message.decode('utf-8'))
            except Exception as e:
                self.event.clear()
                server.close()
                break

    def send(self):
        while self.event.is_set():
            try:
                message = sys.stdin.readline().replace('\n','')
                if message == '':
                    continue
                message = name+' > '+message
                data = b''
                for key in self.user_keys:
                    data = data + b'~~~'+ self.AES_encrypt_message(key) + b'&&&' + self.RSA_encrypt_message(message,key)
                sys.stdout.write("\033[F")
                server.send(data)
            except Exception as e:
                print('Lost connection to server')
                break

    def run(self):
        c.establish_handshake()
        thread = Thread(target=self.listen)
        thread.setDaemon(True)
        thread.start()
        self.send()

c = client()
c.run()
