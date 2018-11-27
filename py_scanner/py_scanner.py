import logging, queue
from datetime import datetime
from time import strftime
from .scanner_thread import ScannerThread
from scapy.all import *

class PyScanner:
    def __init__(self, params_names={"-threads":5, "-ip": "127.0.0.1", "-ports":"0-100"}):
        # print("ok")
        # print(dir(queue))
        params_names["-threads"]=int(params_names["-threads"])
        threads_count = params_names["-threads"]
       #now we will calculate 
        self.lock = threading.Lock()
        self.queue = queue.Queue()
        ports_pair = params_names["-ports"].split("-")
        ports_pairs = self.calcTasks(threads_num=threads_count, ports=ports_pair)
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

    def calcTasks(self, threads_num=1, ports=[0,65536], queue=[]):
        ports_count_range = round((ports[1] - ports[0])/threads_num) #getting count of ports pairs
        ports_ranges = []
        last_from = ports[0]
        last_to = last_from + ports_count_range
        for i in range(threads_num):
            ports = {"from": last_from, "to": last_to}
            ports_ranges.append(ports)
            last_from = ports["to"]+1
            last_to = last_from + ports_count_range
        print(ports_ranges)    
        return ports_ranges


    def checkhost(self, ip="127.0.0.1"):
       # conf.verb = 0
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
    