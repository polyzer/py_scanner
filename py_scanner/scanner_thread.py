import threading, scapy
class ScannerThread(threading.Thread):
    def __init__(self, ip="127.0.0.1", queue, lock):
        threading.Thread.__init__(self)
        self.num = num
        self.scanport()
    def run(self):
        print("hello from run " + str(self.num))
        port = self.queue.get()
    def scanport(self, ip="127.0.0.1", port=0):
        SYNACKpack = sr1()

