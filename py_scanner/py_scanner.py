import logging, queue
from datetime import datetime
from time import strftime
from .scanner_thread import ScannerThread
from scapy.all import *

class PyScanner:
    def __init__(self, params_names={"-threads":5, "-ip": "127.0.0.1"}):
        # print("ok")
        # print(dir(queue))
        params_names["-threads"]=int(params_names["-threads"])
        threads_count = params_names["-threads"]
        num_of_ports = 65535 # count of ports, that we will check 
        self.checkhost(params_names["-ip"]) #checking of our hosts
        
        #now we will calculate 
        self.lock = threading.Lock()
        self.queue = queue.Queue()
        self.calcTasks(threads_num=threads_count, queue=self.queue)
        #timer, that we will use to get speed
        start_clock = datetime.now()
        self.threads = []
        for i in range(params_names["-threads"]):
            thread = ScannerThread(num=i)
            self.threads.append(thread)
        for th in self.threads:
            th.start()
        for th in self.threads:
            th.join()

    def calcTasks(self, threads_num=1, ports="0-65536", queue=[]):
        ports = ports.split(",")
        ports_pairs = []
        for item in ports:
            pp = item.split("-")
            ports_pairs.append(pp)
        print(ports_pairs)    


    def checkhost(self, ip="127.0.0.1"):
       # conf.verb = 0
        a 
        a=send(IP(ttl=10, dst=ip)/ICMP())
        print(a)
        print("\n[*] Target is up, Beginning scanning...")

        # try:
        #     a=send(IP(ttl=10, dst=ip)/ICMP())
        #     print(a)
        #     print("\n[*] Target is up, Beginning scanning...")
        # except Exception:
        #     print("\nCouldn't resolve Target: %s((", ip)
        #     print(Exception)
    