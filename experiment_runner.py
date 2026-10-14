import time
from typing import Dict, Any, List
from qkd_analyzer import QKDQualityAnalyzer
from crypto_engine import RobustEncryptionEngine


class ExperimentRunner:
    """
    Runs reproducible empirical benchmarks on the QKD BB84 simulator and AES-256-GCM engine.
    Compares:
    - QKD qubit scaling (16, 32, 64 qubits)
    - Channel noise vs measured QBER and rejection rate
    - Intercept-Resend (Eve) attack vs baseline error rates
    - AES-256-GCM encryption/decryption throughput vs Fernet
    """

    def __init__(self, analyzer: QKDQualityAnalyzer):
        self.analyzer = analyzer

    def run_noise_benchmark(self, noise_levels: List[float] = [0.0, 0.05, 0.10, 0.15, 0.25], trials_per_level: int = 3) -> Dict[str, Any]:
        results = []
        for noise in noise_levels:
            qbers = []
            accepted_count = 0
            for _ in range(trials_per_level):
                res = self.analyzer.run_bb84_protocol(num_qubits=32, noise_level=noise, eve_present=False)
                qbers.append(res["statistics"]["measured_qber"])
                if res["decision"]["accepted"]:
                    accepted_count += 1
            avg_qber = sum(qbers) / len(qbers) if qbers else 0.0
            results.append({
                "noise_level": noise,
                "noise_level_pct": f"{noise*100:.1f}%",
                "avg_qber": round(avg_qber, 4),
                "avg_qber_pct": round(avg_qber * 100, 2),
                "acceptance_rate_pct": round((accepted_count / trials_per_level) * 100, 1),
                "trials": trials_per_level
            })
        return {"experiment": "channel_noise_impact", "data": results}

    def run_eavesdropping_benchmark(self, trials: int = 5) -> Dict[str, Any]:
        clean_qbers = []
        eve_qbers = []
        detected_attacks = 0

        for _ in range(trials):
            # Clean channel
            clean_res = self.analyzer.run_bb84_protocol(num_qubits=32, noise_level=0.0, eve_present=False)
            clean_qbers.append(clean_res["statistics"]["measured_qber"])

            # Channel with Eve
            eve_res = self.analyzer.run_bb84_protocol(num_qubits=32, noise_level=0.0, eve_present=True)
            eve_qbers.append(eve_res["statistics"]["measured_qber"])
            if not eve_res["decision"]["accepted"]:
                detected_attacks += 1

        avg_clean = sum(clean_qbers) / len(clean_qbers) if clean_qbers else 0.0
        avg_eve = sum(eve_qbers) / len(eve_qbers) if eve_qbers else 0.0

        return {
            "experiment": "intercept_resend_attack_detection",
            "trials": trials,
            "baseline_avg_qber_pct": round(avg_clean * 100, 2),
            "attack_avg_qber_pct": round(avg_eve * 100, 2),
            "theoretical_attack_qber_pct": 25.0,  # ~25% theoretical disturbance in BB84
            "attack_detection_rate_pct": round((detected_attacks / trials) * 100, 1)
        }

    def run_crypto_performance_benchmark(self, sample_sizes_kb: List[int] = [10, 100, 1000]) -> Dict[str, Any]:
        raw_key = b"\x07" * 32
        data_records = []

        for size_kb in sample_sizes_kb:
            payload = b"X" * (size_kb * 1024)

            # AES-GCM
            t0 = time.perf_counter()
            ciphertext_gcm = RobustEncryptionEngine.encrypt_aes_gcm(payload, raw_key)
            gcm_enc_ms = (time.perf_counter() - t0) * 1000

            t1 = time.perf_counter()
            decrypted_gcm = RobustEncryptionEngine.decrypt_aes_gcm(ciphertext_gcm, raw_key)
            gcm_dec_ms = (time.perf_counter() - t1) * 1000

            # Fernet
            t2 = time.perf_counter()
            ciphertext_fernet = RobustEncryptionEngine.encrypt_fernet(payload, raw_key)
            fernet_enc_ms = (time.perf_counter() - t2) * 1000

            t3 = time.perf_counter()
            decrypted_fernet = RobustEncryptionEngine.decrypt_fernet(ciphertext_fernet, raw_key)
            fernet_dec_ms = (time.perf_counter() - t3) * 1000

            data_records.append({
                "size_kb": size_kb,
                "aes_gcm": {
                    "enc_ms": round(gcm_enc_ms, 3),
                    "dec_ms": round(gcm_dec_ms, 3),
                    "throughput_mb_s": round((size_kb / 1024) / (max(gcm_enc_ms, 0.001) / 1000), 2)
                },
                "fernet": {
                    "enc_ms": round(fernet_enc_ms, 3),
                    "dec_ms": round(fernet_dec_ms, 3),
                    "throughput_mb_s": round((size_kb / 1024) / (max(fernet_enc_ms, 0.001) / 1000), 2)
                }
            })

        return {"experiment": "crypto_throughput", "benchmarks": data_records}
