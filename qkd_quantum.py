

import random
import hashlib

from qiskit import QuantumCircuit
from qiskit_aer import Aer
from qiskit.compiler import transpile


class BB84QuantumKeyGenerator:

    def __init__(self, key_length=16):
        self.key_length = key_length

    def generate_random_bits(self):
        return [random.randint(0, 1) for _ in range(self.key_length)]

    def generate_random_bases(self):
        return [random.choice(['+', 'x']) for _ in range(self.key_length)]

    def create_quantum_circuit(self, bits, bases):

        qc = QuantumCircuit(self.key_length, self.key_length)

        for i in range(self.key_length):

            if bits[i] == 1:
                qc.x(i)

            if bases[i] == 'x':
                qc.h(i)

        return qc

    def measure_qubits(self, qc, receiver_bases):

        for i in range(self.key_length):

            if receiver_bases[i] == 'x':
                qc.h(i)

            qc.measure(i, i)

        simulator = Aer.get_backend('aer_simulator')

        compiled_circuit = transpile(qc, simulator)

        result = simulator.run(compiled_circuit, shots=1).result()

        counts = result.get_counts()

        measured_bits = list(counts.keys())[0]

        measured_bits = measured_bits[::-1]

        return measured_bits

    def generate_quantum_key(self):
        sender_bits = self.generate_random_bits()
        sender_bases = self.generate_random_bases()

        receiver_bases = self.generate_random_bases()

        qc = self.create_quantum_circuit(sender_bits, sender_bases)

        measured_bits = self.measure_qubits(qc, receiver_bases)

        shared_key_bits = []

        for i in range(self.key_length):

            if sender_bases[i] == receiver_bases[i]:
                shared_key_bits.append(measured_bits[i])

        shared_key = ''.join(shared_key_bits)
        if len(shared_key) < 8:
            shared_key += '10101010'

        aes_key = hashlib.sha256(shared_key.encode()).digest()

        return {
            'sender_bits': sender_bits,
            'sender_bases': sender_bases,
            'receiver_bases': receiver_bases,
            'measured_bits': measured_bits,
            'shared_key': shared_key,
            'aes_key': aes_key,
            'quantum_circuit': qc
        }