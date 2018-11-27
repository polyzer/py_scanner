from py_scanner import py_scanner
import sys
print(sys.argv)
args_names = {
    "-ip": "192.168.0.1",
    "-threads": 1,
    "-ports": "0-1000"
}

print(args_names)
scanner = py_scanner.PyScanner(params_names = args_names)