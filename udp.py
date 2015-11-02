import socket
import sys

target_host = sys.argv[1]
target_port = int(sys.argv[2])

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

message = raw_input("MSG:")

client.sendto(message, (target_host, target_port))

data, addr = client.recvfrom(4096)

print data
