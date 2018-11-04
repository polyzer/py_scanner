import logging, queue
from datetime import datetime
from time import strftime
from .scanner_thread import ScannerThread
from scapy.os import *
class PyScanner:
    def __init__(self, params_names={"-threads":5, "-ip": "127.0.0.1"}):
        # print("ok")
        # print(dir(queue))
        params_names["-threads"]=int(params_names["-threads"])
        threads_count = params_names["-threads"]
        num_of_ports = 65535 # count of ports, that we will check 
        self.checkhost(params_names["-ip"]) #checking of our hosts
        
        self.work_queue = queue.Queue(1)

        start_clock = datetime.now()
        self.threads = []
        for i in range(params_names["-threads"]):
            thread = ScannerThread(num=i)
            self.threads.append(thread)
        for th in self.threads:
            th.start()
        for th in self.threads:
            th.join()

    def checkhost(self, ip="127.0.0.1"):
       # conf.verb = 0
        print(dir(scapy))
        try:
            print(ip)
            ping = sr1(IP(dst = ip)/ICMP())
            print("\n[*] Target is up, Beginning scanning...")
        except Exception:
            print("\nCouldn't resolve Target: %s((", ip)
            print(Exception)