import socket

from tkinter import *
from tkinter import filedialog

from encryption import EncryptionEngine
from key_manager import KeyManager
from qkd_quantum import BB84QuantumKeyGenerator

HOST = '127.0.0.1'
PORT = 5000

engine = EncryptionEngine()
km = KeyManager()
qkd = BB84QuantumKeyGenerator()

selected_file = ''
def choose_file():

    global selected_file

    selected_file = filedialog.askopenfilename()

    file_label.config(text=selected_file)


def log(message):

    log_box.insert(END, message + '\n')
    log_box.see(END)


def quantum_key_generator():

    result = qkd.generate_quantum_key()

    log(f"⚛ Sender Bits: {result['sender_bits']}")
    log(f"⚛ Sender Bases: {result['sender_bases']}")
    log(f"⚛ Receiver Bases: {result['receiver_bases']}")
    log(f"⚛ Shared Quantum Key: {result['shared_key']}")
    return result['aes_key']


def send_file():

    if not selected_file:

        log('⚠ Please select a file')
        return

    with open(selected_file, 'rb') as f:

        data = f.read()

    key_data = km.get_key(quantum_key_generator)

    aes_key = key_data['key']

    log(f"🔑 Key Status: {key_data['status']}")
    log(f"📊 Usage Count: {key_data['usage']}")
    log(f"⏱ Key Age: {key_data['age']} sec")

    encrypted = engine.encrypt(data, aes_key)
    client = socket.socket()

    client.connect((HOST, PORT))

    client.send(len(aes_key).to_bytes(4, 'big'))
    client.send(aes_key)

    client.send(len(encrypted).to_bytes(8, 'big'))
    client.sendall(encrypted)

    client.close()

    log('📤 File Encrypted & Sent Successfully\n')

# ---------------- GUI ----------------

root = Tk()
root.title('Quantum Secure File Transfer')
root.geometry('650x550')

Label(
    root,
    text='Quantum-Secure File Transfer Using QKD + AES',
    font=('Arial', 16, 'bold')
).pack(pady=10)

Button(
    root,
    text='Choose File',
    width=20,
    command=choose_file
).pack(pady=5)

file_label = Label(
    root,
    text='No file selected',
    wraplength=550
)
file_label.pack()

Button(
    root,
    text='Encrypt & Send File',
    width=20,
    command=send_file
).pack(pady=10)

Label(
    root,
    text='Key Policy: 15 Seconds OR 2 File Transfers'
).pack(pady=5)

Label(root, text='System Log:').pack()

log_box = Text(root, height=18, width=80)
log_box.pack(pady=10)

root.mainloop()