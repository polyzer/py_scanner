import logging, queue
from .scanner_thread import ScannerThread
class PyScanner:
    def __init__(self, params_names={"-threads":5, "-ip": "127.0.0.1"}):
        # print("ok")
        # print(dir(queue))
        params_names["-threads"]=int(params_names["-threads"])
        self.work_queue = queue.Queue(1)
        self.threads = []
        for i in range(params_names["-threads"]):
            thread = ScannerThread(i)
            self.threads.append(thread)
        for th in self.threads:
            th.start()
        for th in self.threads:
            th.join()
