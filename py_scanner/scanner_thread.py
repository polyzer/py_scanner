import threading, scapy
class ScannerThread(threading.Thread):
    def __init__(self, num):
        threading.Thread.__init__(self)
        self.num = num
    def run(self):
        print("hello from run" + str(self.num))

