import socket
import time
import multiprocessing
import psutil
import ecdsa
import hashlib
import time

def generate_user_keys():
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)  # 使用 SECP256k1 椭圆曲线
    public_key = private_key.get_verifying_key()
    return private_key, public_key


def sign_transaction(private_key, transaction_data):
    
    transaction_hash = hashlib.sha256(transaction_data.encode()).digest()
    
    signature = private_key.sign(transaction_hash)
    return transaction_hash, signature


def verify_transaction(public_key, transaction_hash, signature):
    try:
        
        valid = public_key.verify(signature, transaction_hash)
        return valid
    except ecdsa.BadSignatureError:
        return False


HOST = '192.168.3.9'  
PORT = 7777          


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server_socket.bind((HOST, PORT))

server_socket.listen(500)
print(f"Server started on {HOST}:{PORT}, waiting for connections...")


i = 100
s = []
def serve(stop_event):
    i = 1000000
    s = []
    while i and not stop_event.is_set():
        
        client_socket, client_address = server_socket.accept()
        user_private_key, user_public_key = generate_user_keys()
        transaction_data = "UserA sends 1 BTC to UserB"
        transaction_hash, signature = sign_transaction(user_private_key, transaction_data)     
        is_valid = verify_transaction(user_public_key, transaction_hash, signature)
        if i % 100 == 0:
            print(i)
            print(is_valid)

        i -= 1
        s.append([time.time(), i])
     
        client_socket.send(b"Welcome to the server!")
    print(s[-1][0] - s[0][0])

def monitor_cpu_usage(threshold = 80):
    S = []
    while True:
        cpu_usage = psutil.cpu_percent(interval=0.1)
        S.append(cpu_usage)
        if cpu_usage > 80:
            stop_event.set()
            break
        if len(S) == 400:
            print(S, sum(S[10:200])/190)
        

if __name__ == '__main__':
    stop_event = multiprocessing.Event()
    s = multiprocessing.Process(target=serve, args=(stop_event,)) 
    s.start()
    m = multiprocessing.Process(target=monitor_cpu_usage, args=(stop_event,))
    m.start()

