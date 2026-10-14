import secrets
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from qiskit import QuantumCircuit
from qiskit_aer import Aer
from qiskit.compiler import transpile


class QKDQualityAnalyzer:
    """
    QKD Quality Analyzer and BB84 Simulation Engine.
    
    Implements:
    1. BB84 preparation: random state and basis preparation (|0>, |1> in computational basis '+';
       |+>, |-> in Hadamard diagonal basis 'x').
    2. Simulated quantum channel with controlled depolarizing/bit-flip noise and Eve intercept-resend attack.
    3. Bob measurement in independently chosen bases ('+' or 'x').
    4. Sifting: Alice and Bob publicly announce bases (without revealing bit values).
    5. Parameter Estimation / Error Estimation:
       A configurable fraction (or count) of sifted bits is randomly sampled to compute the
       Quantum Bit Error Rate (QBER).
       *CRITICAL PROTOCOL REQUIREMENT*: The sample bits used for QBER estimation are public
       and DISCARDED from the key to avoid information leakage.
    6. Minimum Raw Secret Entropy Check:
       Deriving AES keys requires sufficient remaining secret sifted bits.
       Hashing a short key does NOT create genuine 256-bit entropy.
    7. Key Derivation:
       Uses HKDF-SHA256 (or cryptographic hash derivation with domain separation and salt)
       only when sufficient unrevealed sifted bits pass the QBER threshold.
    """

    def __init__(self, default_num_qubits: int = 48, default_qber_threshold: float = 0.11):
        self.default_num_qubits = default_num_qubits
        # In BB84, ~11% QBER is the theoretical security limit against general coherent attacks
        self.default_qber_threshold = default_qber_threshold

    def run_bb84_protocol(
        self,
        num_qubits: Optional[int] = None,
        noise_level: float = 0.0,
        eve_present: bool = False,
        qber_threshold: Optional[float] = None,
        sample_ratio: float = 0.33,
        seed: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Executes a BB84 QKD simulation round with quality analysis and security verification.
        """
        n = num_qubits or self.default_num_qubits
        threshold = qber_threshold if qber_threshold is not None else self.default_qber_threshold

        # Validation of input bounds
        n = max(16, min(n, 128))
        noise_level = max(0.0, min(noise_level, 0.50))
        sample_ratio = max(0.1, min(sample_ratio, 0.50))

        # Alice: generate random bits and bases using cryptographically secure RNG
        alice_bits = [secrets.randbelow(2) for _ in range(n)]
        alice_bases = ['+' if secrets.randbelow(2) == 0 else 'x' for _ in range(n)]

        # Bob: independent basis choices
        bob_bases = ['+' if secrets.randbelow(2) == 0 else 'x' for _ in range(n)]

        # Eve (if intercept-resend attack is active)
        eve_bases = []
        eve_measured = []
        if eve_present:
            eve_bases = ['+' if secrets.randbelow(2) == 0 else 'x' for _ in range(n)]

        # Prepare Quantum Circuit
        qc = QuantumCircuit(n, n)

        # 1. Alice prepares qubits
        for i in range(n):
            if alice_bits[i] == 1:
                qc.x(i)
            if alice_bases[i] == 'x':
                qc.h(i)

        # 2. Eve intercepts, measures, and resends (Intercept-Resend Attack)
        if eve_present:
            for i in range(n):
                if eve_bases[i] == 'x':
                    qc.h(i)
                qc.measure(i, i)
                # Resend in Eve's measured basis:
                # If Eve basis was 'x', measuring projects to |0> or |1> in 'x' basis.
                # To resend correctly into the channel:
                if eve_bases[i] == 'x':
                    qc.h(i)

        # 3. Channel Noise (Simulated Bit-Flip / Phase Error)
        if noise_level > 0.0:
            for i in range(n):
                # Apply noise probabilistically
                if secrets.randbelow(10000) / 10000.0 < noise_level:
                    qc.x(i)

        # 4. Bob measures
        for i in range(n):
            if bob_bases[i] == 'x':
                qc.h(i)
            qc.measure(i, i)

        # Run Qiskit Aer simulation directly without restrictive coupling map constraints
        from qiskit_aer import AerSimulator
        simulator = AerSimulator()
        job = simulator.run(qc, shots=1, seed_simulator=seed)
        counts = job.result().get_counts()

        measured_raw = list(counts.keys())[0]
        # Qiskit orders bitstrings from q_n-1 down to q_0; reverse to match 0..n-1
        bob_measured_bits = [int(b) for b in measured_raw[::-1]]

        # 5. Sifting Stage: Identify indices where Alice & Bob chose matching bases
        matching_indices = [i for i in range(n) if alice_bases[i] == bob_bases[i]]
        sifted_alice = [alice_bits[i] for i in matching_indices]
        sifted_bob = [bob_measured_bits[i] for i in matching_indices]
        sifted_length = len(matching_indices)

        # 6. Parameter Estimation (QBER calculation)
        # Select sample subset for error estimation
        sample_size = max(1, int(sifted_length * sample_ratio))
        
        # Deterministically or pseudo-randomly pick indices from matching_indices to disclose
        # We sample without replacement
        sample_indices_relative = sorted(secrets.SystemRandom().sample(range(sifted_length), sample_size))
        sample_indices_set = set(sample_indices_relative)

        sample_errors = 0
        retained_alice = []
        retained_bob = []

        for idx in range(sifted_length):
            if idx in sample_indices_set:
                # Publicly compared
                if sifted_alice[idx] != sifted_bob[idx]:
                    sample_errors += 1
            else:
                # Retained for secret key material
                retained_alice.append(sifted_alice[idx])
                retained_bob.append(sifted_bob[idx])

        measured_qber = sample_errors / float(sample_size) if sample_size > 0 else 1.0

        # 7. Security Acceptance Decision
        # Needs:
        # a) QBER <= threshold
        # b) Retained bits >= 8 (for simulation scale) or 16+ bits of secret material
        retained_key_str = "".join(str(b) for b in retained_alice)
        retained_bob_str = "".join(str(b) for b in retained_bob)

        # Check discrepancy in retained key bits
        retained_discrepancy = sum(1 for a, b in zip(retained_alice, retained_bob) if a != b)
        
        decision_reasons = []
        accepted = True

        if measured_qber > threshold:
            accepted = False
            decision_reasons.append(
                f"QBER {measured_qber*100:.2f}% exceeds safety threshold of {threshold*100:.2f}%. Eavesdropping or high channel noise detected."
            )

        if len(retained_alice) < 8:
            accepted = False
            decision_reasons.append(
                f"Insufficient sifted key length: {len(retained_alice)} retained bits is below minimum simulation requirement (8 bits)."
            )

        # In a real QKD setup, classical error correction (information reconciliation like CASCADE/Winnow)
        # and privacy amplification (universal hashing) would remove residual errors and eavesdropper info.
        # Here we perform simulated privacy amplification if accepted:
        derived_key_bytes = None
        if accepted:
            # Domain-separated derivation: salt with protocol parameters
            salt = f"BB84-QKD-SALT-{n}-{noise_level}".encode()
            # HKDF or SHA-256 derivation over retained secret bits
            derived_key_bytes = hashlib.sha256(salt + retained_key_str.encode()).digest()

        round_id = f"qkd-rnd-{secrets.token_hex(4)}"

        return {
            "round_id": round_id,
            "parameters": {
                "num_qubits": n,
                "noise_level": noise_level,
                "eve_present": eve_present,
                "qber_threshold": threshold,
                "sample_ratio": sample_ratio,
            },
            "statistics": {
                "total_qubits": n,
                "sifted_bits_count": sifted_length,
                "sifted_yield_pct": round((sifted_length / n) * 100, 2),
                "sample_bits_tested": sample_size,
                "sample_errors_found": sample_errors,
                "measured_qber": round(measured_qber, 4),
                "measured_qber_pct": round(measured_qber * 100, 2),
                "retained_secret_bits_count": len(retained_alice),
                "retained_discrepancies": retained_discrepancy,
            },
            "alice": {
                "bases": alice_bases,
                "bits": alice_bits,
            },
            "bob": {
                "bases": bob_bases,
                "measured": bob_measured_bits,
            },
            "eve": {
                "present": eve_present,
                "bases": eve_bases if eve_present else [],
            },
            "decision": {
                "accepted": accepted,
                "reasons": decision_reasons if not accepted else ["Acceptable QBER within security threshold and sufficient retained secret material."],
            },
            "derived_key_available": accepted and (derived_key_bytes is not None),
            # Never send actual raw secret keys in plain API representations unless requested securely by backend
            "_derived_key_bytes": derived_key_bytes if accepted else None,
            "key_fingerprint": hashlib.sha256(derived_key_bytes).hexdigest()[:16] if derived_key_bytes else None,
            "simulation_notice": "BB84 software simulation using Qiskit Aer statevector/qasm simulator. Not a physical optical fiber or free-space photon transmission."
        }
