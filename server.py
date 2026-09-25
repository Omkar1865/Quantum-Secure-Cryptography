# server.py
import socket
from encryption import EncryptionEngine

HOST = '127.0.0.1'
PORT = 5000

engine = EncryptionEngine()

file_counter = 1

def recv_exact(conn, size):

    data = b''

    while len(data) < size:

        packet = conn.recv(size - len(data))

        if not packet:
            return None

        data += packet

    return data

server = socket.socket()
server.bind((HOST, PORT))
server.listen(5)

print('🟢 Quantum Secure Server Running...')

while True:

    conn, addr = server.accept()

    print(f'🔗 Connected: {addr}')

    try:

        key_size = int.from_bytes(conn.recv(4), 'big')
        aes_key = recv_exact(conn, key_size)
        data_size = int.from_bytes(conn.recv(8), 'big')
        encrypted_data = recv_exact(conn, data_size)
        decrypted = engine.decrypt(encrypted_data, aes_key)
        filename = f'received_{file_counter}.txt'

        with open(filename, 'wb') as f:
            f.write(decrypted)

        print(f'📥 File saved as {filename}')

        file_counter += 1

    except Exception as e:

        print('❌ Error:', str(e))

    finally:

        conn.close()