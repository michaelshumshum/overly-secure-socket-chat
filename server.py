import socket
import sys
import traceback
from json import load
from datetime import datetime
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import random
from Crypto import Random
from requests import get
from time import sleep
from queue import Queue
from threading import Thread, Event

with open('settings.json','r') as s:
    settings = load(s)
port = settings['port']
max_connections = settings['max-connections']
logging = settings['logging'] == 'True'
activity = settings['activity-timeout']
print('Current settings:')
for setting in settings:
    print('...',setting,':',settings[setting])

ansi = [
'[30m',
'[31m',
'[32m',
'[33m',
'[34m',
'[35m',
'[36m',
'[37m',
'[0m']

chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890'

class server:
    def __init__(self):
        self.ip = get('https://ipapi.co/ip/').text
        self.event = Event()
        self.start_time = datetime.now()
        self.clients = {}
        self.threads = []
        self.blacklist = []
        self.broadcast_queue = Queue()
        self.handshake_queue = Queue()
        self.distribution_queue = Queue()
        self.max_connections = max_connections
        self.logging = logging
        self.activity = activity
        if self.logging:
            self.log = open('logs/'+(str(self.start_time)[:19]).replace(' ','-')+'.txt','w+')

    def output(self,string):
        if isinstance(string,str):
            print(string)
            for i in ansi:
                string = string.replace(i,'')
            if self.logging:
                self.log.write(f'[{str(datetime.now())[11:19]}] {string}\n')
        else:
            for x in string:
                print(x)
                for i in ansi:
                    x = x.replace(i,'')
                if self.logging:
                    self.log.write(f'[{str(datetime.now())[11:19]}] {x}\n')

    def start_server(self):
        self.event.set()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((socket.gethostname(),port))
        self.output(f'Binded to {self.ip} on {port}')
        self.output(f'Start time : {self.start_time}')
        self.server.listen(self.max_connections)
        services = [
        self.broadcast_thread,
        self.accept_connections_thread,
        self.guarddog_thread,
        self.message_distribution_thread,
        self.handshake_thread,
        self.handshake_thread]
        for service in services:
            thread = Thread(target=service,name=str(service))
            thread.setDaemon(True)
            self.threads.append(thread)
            thread.start()
        self.server_command()

    def create_user_key(self,temp_key,user_key):
        if len(user_key) != 32:
            return False
        else:
            server = [chars.find(x) for x in list(temp_key)]
            user = [chars.find(x) for x in list(user_key)]
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
            return bytes(final_key[::-1],'utf-8')

    def AES_encrypt_message(self,message,key):
        if not isinstance(message,str):
            message = message.decode('utf-8')
        if len(bytes(message, encoding='utf-8')) % 16 != 0:
            message = message + '|'
            while len(bytes(message, encoding='utf-8')) % 16 != 0:
                message = message + random.choice(chars)
        message = bytes(message,'utf-8')
        iv = Random.new().read(16)
        obj = AES.new(key,AES.MODE_CBC,iv)
        return iv + obj.encrypt(message)

    def AES_decrypt_message(self,message,key):
        iv = message[:16]
        message = message[16:]
        obj = AES.new(key,AES.MODE_CBC,iv)
        # if for some reason, the key is incorrect, we bruteforce the key by searching all the keys in the clients dictionary.
        # if that still fails, that means the client's key was invalid.
        try:
            message = obj.decrypt(message).decode('utf-8')
        except:
            for client in self.clients:
                k = self.clients[client]['aes_key']
                obj = AES.new(k,AES.MODE_CBC,iv)
                try:
                    message = obj.decrypt(message).decode('utf-8')
                    break
                except:
                    continue
        if '|' in message:
            message = message[:message.find('|')]
        return message

    def RSA_encrypt_message(self,message,key):
        key = RSA.import_key(key)
        message = bytes(message,'utf-8')
        obj = PKCS1_OAEP.new(key)
        return obj.encrypt(message)

    def RSA_decrypt_message(self,message,key):
        key = RSA.import_key(key)
        obj = PKCS1_OAEP.new(key)
        return obj.decrypt(message)

    def remove_from_handshake_queue(self,ip):
        while not self.handshake_queue.empty():
            get = self.handshake_queue.get()
            if get[1][0] != ip:
                self.handshake_queue.put(get)

    def server_command(self):
        while True:
            command = sys.stdin.readline().replace('\n','')
            for thread in self.threads:
                if 'stopped daemon' in str(thread):
                    self.threads.remove(thread)
            sys.stdout.write("\033[F")
            try:
                if 'info' in command:
                    self.output('\u001b[35m                               ')
                    self.output(f'IP : {self.ip}')
                    self.output(f'PORT : {port}')
                    self.output(f'USERS CONNECTED : {len(self.clients)}')
                    self.output(f'UPTIME : {str(datetime.now() - self.start_time)[:7]}')
                    self.output('\u001b[0m')
                elif 'threads' in command:
                    self.output('\u001b[35m                               ')
                    self.output(f'\u001b[35mActive Threads ({len(self.threads)}):')
                    for thread in self.threads:
                        self.output(str(thread))
                    self.output('\u001b[0m')
                elif 'handshake queue' in command:
                    if len(self.handshake_queue.queue) > 0:
                        self.output('                            ')
                        self.output(f'\u001b[35mAddresses in the handshake queue: ({len(self.handshake_queue.queue)}):')
                        self.output([f"{addr} ({[i[1][0] for i in self.handshake_queue.queue].count(addr)})" for addr in set([i[1][0] for i in self.handshake_queue.queue])])
                        self.output('\u001b[0m')
                    else:
                        self.output('\u001b[31mHandshake queue is empty.\u001b[0m')
                elif 'users' in command:
                    if len(self.clients) > 0:
                        self.output('                            ')
                        self.output(f'\u001b[35mConnected Users ({len(self.clients)}):')
                        for client in self.clients:
                            self.output(f'{self.clients[client]["name"]} : {self.clients[client]["ip"]} : {self.clients[client]["aes_key"].decode("utf-8")}')
                        self.output('\u001b[0m')
                    else:
                        self.output('\u001b[31mNo users connected.\u001b[0m')
                elif 'kick' in command:
                    for client in self.clients:
                        if command[5:] in self.clients[client]["name"]:
                            self.output('\u001b[35mKicked '+self.clients[client]["ip"]+'\u001b[0m')
                            client.send(self.AES_encrypt_message('\u001b[31mYou have been kicked!\u001b[0m',self.clients[client]['aes_key']))
                            self.remove_conn(client)
                            break
                    else:
                        self.output(f'\u001b[31mNo user named "{command[5:]}" was found\u001b[0m')
                elif 'blacklist' == command:
                    self.output('                            ')
                    if len(self.blacklist) > 0:
                        self.output('\u001b[35mIP Blacklist:')
                        self.output(self.blacklist)
                        self.output('\u001b[0m')
                    else:
                        self.output('\u001b[31mIP Blacklist is empty.\u001b[0m')
                elif 'unban' in command:
                    if 'all' in command:
                        self.blacklist = []
                        self.output('\u001b[35mCleared IP blacklist\u001b[0m')
                    else:
                        try:
                            self.blacklist.remove(command[6:])
                        except:
                            self.output(f'\u001b[31m{command[6:]} is not on IP blacklist\u001b[0m')
                elif 'ban' in command:
                    if command[4:].count('.') == 3:
                        mode = 'ip'
                        self.remove_from_handshake_queue(command[4:])
                    else:
                        mode = 'name'
                    for client in self.clients:
                        if command[4:] in self.clients[client][mode]:
                            self.output('\u001b[35mBanned '+self.clients[client]["ip"]+'\u001b[0m')
                            client.send(self.AES_encrypt_message('\u001b[31mYou have been banned!\u001b[0m',self.clients[client]['aes_key']))
                            self.blacklist.append(self.clients[client]["ip"])
                            self.remove_conn(client)
                            break
                    else:
                        if mode == 'ip':
                            self.blacklist.append(command[4:])
                            self.output('\u001b[35mBlacklisted IP '+command[4:]+'\u001b[0m')
                        else:
                            self.output('\u001b[31mPlease input a valid name or IP address\u001b[0m')
                elif 'announce' in command:
                    self.broadcast_queue.put('\u001b[32mANNOUNCEMENT:')
                    self.broadcast_queue.put(command[9:]+'\u001b[0m')

                elif 'close' in command:
                    self.event.clear()
                    try:
                        self.broadcast_queue.put('\u001b[33mServer is shutting down...\u001b[0m')
                        sleep(0.1)
                        self.close_all_conn()
                    except:
                        pass
                    if self.logging:
                        self.log.close()
                    break
                else:
                    raise Exception('not command')
            except Exception as e:
                continue

    def close_all_conn(self):
        for client in self.clients:
            client.close()

    def remove_conn(self,client):
        try:
            client.close()
        except:
            pass
        removed = self.clients.pop(client)
        removed['event'].clear()
        self.broadcast_queue.put(f'\u001b[33m{removed["name"]} disconnected.\u001b[0m')
        self.output(f'Lost connection from {removed["ip"]}')

    def share_keys(self):
        keys = b'RSA '
        for client in self.clients:
            keys =  keys + b'~~~' +self.clients[client]['rsa_key']
        for client in self.clients:
            client.send(self.AES_encrypt_message(keys,self.clients[client]['aes_key']))

    # thread functions

    def guarddog_thread(self):
        while self.event.is_set():
            try:
                handshake_queue = [([i[1][0] for i in self.handshake_queue.queue].count(addr),addr) for addr in set([i[1][0] for i in self.handshake_queue.queue])]
                for item in handshake_queue:
                    if (item[0] > 10) and (item[1] not in self.blacklist):
                        self.blacklist.append(item[1])
                        self.output(f'\u001b[31m{item[1]} was banned due to handshake flooding.\u001b[0m')
                        self.remove_from_handshake_queue(item[1])
            except:
                pass
            try:
                for client in self.clients:
                    if self.clients[client]['spam_rating'] > 3:
                        self.output(f'\u001b[31m{self.clients[client]["ip"]} was kicked due to spam ({self.clients[client]["spam_rating"]} messages within 1 second).\u001b[0m')
                        client.send(self.AES_encrypt_message('\u001b[31mYou have been kicked for spamming!\u001b[0m',self.clients[client]['aes_key']))
                        self.remove_conn(client)
                    elif self.clients[client]['activity'] == 0:
                        self.output(f'\u001b[31m{self.clients[client]["ip"]} was kicked due to inactivity ({self.activity} seconds of inactivity).\u001b[0m')
                        client.send(self.AES_encrypt_message('\u001b[31mYou have been kicked for inactivity!\u001b[0m',self.clients[client]['aes_key']))
                        self.remove_conn(client)
            except Exception as e:
                pass
            sleep(1)

    def handshake_thread(self):
        class InvalidKey(Exception):
            pass
        class Blacklisted(Exception):
            pass
        while self.event.is_set():
            conn,addr = self.handshake_queue.get()
            conn.settimeout(5)
            try:
                if addr[0] in self.blacklist:
                    raise Blacklisted
                self.output(f"{addr[0]} attempting to join.")
                key = conn.recv(2048).decode('utf-8')
                if len(key) != 32:
                    raise InvalidKey
                temp = ''.join(random.choice(list(chars)) for i in range(32))
                conn.send(bytes(temp,'utf-8'))
                their_key = self.create_user_key(temp,key)
                try:
                    name = self.AES_decrypt_message(conn.recv(2048),their_key)
                except:
                    raise InvalidKey
                self.output(f"{addr[0]} verified client with key {their_key.decode('utf-8')}.                                      ")
                conn.settimeout(None)
                rsa_key = bytes(self.AES_decrypt_message(conn.recv(2048),their_key),'utf-8')
                thread = Thread(target=self.user_thread,args=(conn,addr,name,their_key,rsa_key),name=name+'_'+str(addr[0]))
                self.threads.append(thread)
                thread.start()
            except Blacklisted:
                conn.close()
            except InvalidKey:
                self.output(f"\u001b[31m{addr[0]} failed to send correct keys.\u001b[0m")
                conn.close()
            except socket.timeout:
                if addr[0] not in self.blacklist:
                    self.output(f"{addr[0]} timed out.")
                conn.close()
            except:
                self.output(f"\u001b[31m{addr[0]} failed client verification.\u001b[0m")
                conn.close()

    def accept_connections_thread(self):
        while self.event.is_set():
            try:
                conn,addr = self.server.accept()
                if addr[0] in self.blacklist:
                    conn.close()
                    continue
                self.handshake_queue.put((conn,addr))
            except Exception as e:
                self.output(str(e))
                continue

    def broadcast_thread(self):
        while self.event.is_set():
            message = self.broadcast_queue.get()
            clients = []
            for x in self.clients.items():
                clients.append(x[0])
            start = 0
            while True:
                try:
                    for client in clients[start:]:
                        client.send(self.AES_encrypt_message(message,self.clients[client]['aes_key']))
                    break
                except:
                    start = clients.index(client)
                    sleep(0.1)
                    continue

    def message_distribution_thread(self):
        while self.event.is_set():
            messages = self.distribution_queue.get()
            for message in messages:
                clients = []
                for x in self.clients.items():
                    clients.append(x[0])
                    start = 0
                for client in clients[start:]:
                    if self.clients[client]['rsa_key'] == message[0]:
                        client.send(message[1])

    def user_thread(self,conn,addr,name,aes_key,rsa_key):
        self.clients[conn] = {"name" : name , "ip" : addr[0] , "aes_key" : aes_key , "rsa_key" : rsa_key  , "spam_rating" : 0 , "activity" : self.activity}
        conn.send(self.AES_encrypt_message(f"\u001b[35mWelcome to {self.ip} : {port}, {name}!\u001b[0m",aes_key))
        sleep(0.1)
        self.broadcast_queue.put(f'\u001b[36m{name} connected.\u001b[0m')
        self.share_keys()
        conn.settimeout(0)
        while self.event.is_set():
            try:
                t = datetime.now()
                s = 0
                while int(str(datetime.now() - t)[5:7]) < 1:
                    try:
                        message = conn.recv(2048)
                    except Exception as e:
                        continue
                    s += 1
                    if message:
                        data = list(filter(None,message.split(b'~~~')))
                        for i in range(len(data)):
                            d = data[i].split(b'&&&')
                            data[i] = (bytes(self.AES_decrypt_message(d[0],aes_key),'utf-8'),d[1])
                        self.distribution_queue.put(data)
                    else:
                        raise Exception('leave')
                self.clients[conn]['spam_rating'] = s
                if s == 0:
                    self.clients[conn]['activity'] -= 1
                else:
                    self.clients[conn]['activity'] = self.activity
            except Exception as e:
                try:
                    self.remove_conn(conn)
                    break
                except:
                    break

s = server()
s.start_server()
