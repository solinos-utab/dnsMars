import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0', 5000))
s.listen(1)
print("Listening on 5000...")
conn, addr = s.accept()
print(f"Connected by {addr}")
conn.close()
