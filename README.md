# Quantum Secure File Transfer

A desktop file-transfer prototype that combines BB84-style quantum key distribution simulation with AES-compatible Fernet encryption.

## What it does

- Simulates BB84 sender and receiver bases with Qiskit Aer.
- Derives a 32-byte key from the shared quantum bits using SHA-256.
- Reuses a generated key for up to 15 seconds or 2 transfers.
- Encrypts a selected file in the Tkinter client.
- Sends the encrypted payload over a local TCP connection.
- Decrypts and saves received files on the server.

> This is an educational prototype. The current implementation sends the symmetric key over the same TCP connection as the encrypted file, so it is not a production-secure network protocol. Use it locally for demonstration and experimentation.

## Requirements

- Python 3.10 or newer
- Tkinter (included with most Windows Python installations)
- Qiskit and Qiskit Aer
- Cryptography

Install the Python dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Run locally

Open two terminals in the project directory.

Start the receiver first:

```powershell
python server.py
```

Start the desktop client in the second terminal:

```powershell
python client_gui.py
```

Choose a file in the client and select **Encrypt & Send File**. The server writes each decrypted payload as `received_N.txt` in its working directory.

The default connection is `127.0.0.1:5000`. Change `HOST` and `PORT` in both `client_gui.py` and `server.py` when using separate machines. Ensure the selected port is allowed by the local firewall.

## Project structure

| File | Purpose |
| --- | --- |
| `client_gui.py` | Tkinter client for selecting, encrypting, and sending files |
| `server.py` | TCP receiver that decrypts and stores files |
| `qkd_quantum.py` | BB84-style key-generation simulation using Qiskit Aer |
| `encryption.py` | Fernet encryption and decryption wrapper |
| `key_manager.py` | Time- and usage-based key reuse policy |
| `tests/` | Fast unit tests for reusable core components |
| `sample.txt` | Small example input file |

## Run tests

```powershell
python -m unittest discover -s tests -v
```

## Security notes

This project demonstrates concepts rather than providing a hardened secure-transfer product. Before using a design like this beyond a local demo, add authenticated peer identity, secure key exchange, message framing validation, replay protection, encrypted transport, access controls, and robust error handling. Do not commit private keys, credentials, or sensitive files.

## License

This project is released under the MIT License. See `LICENSE`.
