import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("127.0.0.1", 25565))
sock.listen()

conn, addr = sock.accept()

t = b""

try:
    d = b"\x00"
    while len(d) > 0:
        d = conn.recv(1)
        t += d
finally:
    sock.close()
    conn.close()

    print(t)
