from py_scanner import py_scanner
import sys
print(sys.argv)
args_names = {
    "-ip": "127.0.0.1",
    "-threads": 4,
    "-ports": "21-100",
    "-scan_type": "S"
}
# vals = []
# for key in args_names.keys():
#     args_names[key] = sys.argv.index(key) if key in sys.argv else -1
#     if args_names[key] != -1:
#         idx = sys.argv.index(key)+1
#         args_names[key] = sys.argv[idx] if idx < len(sys.argv) else -1


print(args_names)
scanner = py_scanner.PyScanner(params_names = args_names)