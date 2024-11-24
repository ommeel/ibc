import socket
import time
# 设置监听的 IP 和端口
HOST = '127.0.0.1'  
PORT = 7777          


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


server_socket.bind((HOST, PORT))


server_socket.listen(100)



i = 100
s = []
if __name__ == '__main__':
    while i:
        
        client_socket, client_address = server_socket.accept()
     
        i -= 1
        s.append([time.time(), i])
        
        client_socket.send(b"Welcome to the server!")
    print(s[-1][0] - s[0][0])
    
    
