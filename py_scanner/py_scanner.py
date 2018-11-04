import logging, queue
from .scanner_thread import ScannerThread
class PyScanner:
    def __init__(self, threads_num=1, host="127.0.0.1"):
        # print("ok")
        # print(dir(queue))
        self.work_queue = queue.Queue(1)
        self.threads = []
        for i in range(threads_num):
            thread = ScannerThread(i)
            self.threads.append(thread)
        for th in self.threads:
            th.start()
        for th in self.threads:
            th.join()
