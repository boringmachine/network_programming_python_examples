import socket
import sys

target_host = sys.argv[1]
target_port = int(sys.argv[2])

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.connect((target_host, target_port))

message = raw_input("MSG:")

client.send(message)

response = client.recv(4096)

print response
