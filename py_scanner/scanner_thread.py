import threading, scapy
class ScannerThread(threading.Thread):
    def __init__(self, ip="127.0.0.1", min_port=0, max_port= 65536, num=0):
        threading.Thread.__init__(self)
        self.num = num
    def run(self):
        print("hello from run " + str(self.num))

