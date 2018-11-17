from scapy.all import *
import threading
class ScannerThread(threading.Thread):
    def __init__(self, dest_ip="127.0.0.1", ports={"from":1, "to":2}, out_queue=[]):
        threading.Thread.__init__(self)
        self.states = {
            "from": 1,
            "to": 2
        }
        self.ports = ports
        self.ReturnObject=[]
        self.ScanResult={
            "id": 0,
            "port": 1,
            "SYN": 2,
            "ACK": 3,
            "FIN": 4
        }
        self.dest_ip = dest_ip
        self.scanports()
        
    def run(self):
        for port in range(self.ports["from"], self.ports["to"]):
            print("running port: " + port)
            res = scanports(ip=self.dest_ip, port=self.ports)

    def scanports(self, ip="127.0.0.1", ports=0):
        ACKpacket = IP(dst=ip)/TCP(dport=port, flags='A') # Forging ACK packet
        SYNpacket = IP(dst=ip)/TCP(dport=port, flags='S') # Forging SYN packet
        FINpacket = IP(dst=ip)/TCP(dport=port, flags='F') # Forging FIN packet
        resp = sr(p, timeout=2)
        
