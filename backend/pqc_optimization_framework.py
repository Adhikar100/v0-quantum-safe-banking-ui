"""
Post-Quantum Cryptography Optimization Framework
================================================
Implements the formal cost optimization algorithm J(P) for selecting
optimal ML-KEM and ML-DSA parameter sets for quantum-safe banking.

Research Goal: Validate hypothesis that P* (Category 3: ML-KEM-768 + ML-DSA-3)
minimizes operational costs compared to Category 5 (ML-KEM-1024 + ML-DSA-5)
"""

import time
import statistics
from typing import Dict, List, Tuple, Callable
from dataclasses import dataclass
import json

# Try to use production liboqs, fallback to simulation
try:
    import oqs
    LIBOQS_AVAILABLE = True
    print("[PQC Framework] Using production liboqs library")
except ImportError:
    LIBOQS_AVAILABLE = False
    print("[PQC Framework] Using simulated PQC operations")
    import hashlib
    import secrets

# ----------------------------------------------------------------------
# 1. GLOBAL SETUP AND MATHEMATICAL CONSTANTS
# ----------------------------------------------------------------------

# Cost Tensor (W): Weights for Latency, Bandwidth, Computation
# W[0]=0.1 (Latency), W[1]=0.7 (Bandwidth - HIGH priority), W[2]=0.2 (Computation)
W_VECTOR = [0.1, 0.7, 0.2]

# Parameter Sets (P): Algorithm selection based on NIST security levels
P_STAR = {
    'KEM': 'Kyber768',  # ML-KEM-768 (Category 3: 192-bit security)
    'DSA': 'Dilithium3'  # ML-DSA-3 (Category 3)
}

P_PRIME = {
    'KEM': 'Kyber1024',  # ML-KEM-1024 (Category 5: 256-bit security)
    'DSA': 'Dilithium5'  # ML-DSA-5 (Category 5)
}

# Simulation Parameters
N_ITERATIONS = 100  # Statistical sampling size for E[X] calculation
LAMBDA_SCALING = 250  # Constrained device complexity scaling factor

# Known sizes for bandwidth calculation (in bytes)
KEM_SIZES = {
    'Kyber768': {'pk': 1184, 'ct': 1088, 'ss': 32},
    'Kyber1024': {'pk': 1568, 'ct': 1568, 'ss': 32}
}

DSA_SIZES = {
    'Dilithium3': {'pk': 1952, 'sk': 4016, 'sig': 3293},
    'Dilithium5': {'pk': 2592, 'sk': 4880, 'sig': 4595}
}


# ----------------------------------------------------------------------
# 2. DATA STRUCTURES
# ----------------------------------------------------------------------

@dataclass
class MeasurementResult:
    """Captures statistical distribution of measurements"""
    e_value: float  # Expected Value E[X] (Mean)
    variance: float  # Variance Var[X]
    std_dev: float  # Standard Deviation σ
    min_val: float  # Minimum observed value
    max_val: float  # Maximum observed value
    samples: List[float]  # Raw samples for further analysis


@dataclass
class TransactionMetrics:
    """Aggregated metrics for cost function J(P)"""
    l_avg: float  # Average Latency (Key Exchange) in milliseconds
    m_size: float  # Total Bandwidth Cost in bytes
    t_avg: float  # Average Computation Time (Sign+Verify) in milliseconds


@dataclass
class KeyPair:
    """Generic keypair structure"""
    public_key: bytes
    secret_key: bytes


# ----------------------------------------------------------------------
# 3. PQC PRIMITIVE IMPLEMENTATIONS
# ----------------------------------------------------------------------

class PQCSimulator:
    """Simulated PQC operations when liboqs unavailable"""
    
    @staticmethod
    def kem_keygen(param_set: str) -> Tuple[bytes, bytes]:
        """Simulate KEM keypair generation"""
        sizes = KEM_SIZES[param_set]
        time.sleep(0.001)  # Simulate computation
        pk = secrets.token_bytes(sizes['pk'])
        sk = secrets.token_bytes(sizes['pk'] + 32)
        return pk, sk
    
    @staticmethod
    def kem_encaps(pk: bytes, param_set: str) -> Tuple[bytes, bytes]:
        """Simulate KEM encapsulation"""
        sizes = KEM_SIZES[param_set]
        time.sleep(0.0008)  # Simulate computation
        ct = secrets.token_bytes(sizes['ct'])
        ss = hashlib.sha3_256(pk + ct).digest()
        return ct, ss
    
    @staticmethod
    def kem_decaps(ct: bytes, sk: bytes, param_set: str) -> bytes:
        """Simulate KEM decapsulation"""
        sizes = KEM_SIZES[param_set]
        time.sleep(0.0007)  # Simulate computation
        ss = hashlib.sha3_256(sk[:32] + ct).digest()
        return ss
    
    @staticmethod
    def dsa_keygen(param_set: str) -> Tuple[bytes, bytes]:
        """Simulate DSA keypair generation"""
        sizes = DSA_SIZES[param_set]
        time.sleep(0.002)  # Simulate computation
        pk = secrets.token_bytes(sizes['pk'])
        sk = secrets.token_bytes(sizes['sk'])
        return pk, sk
    
    @staticmethod
    def dsa_sign(message: bytes, sk: bytes, param_set: str) -> bytes:
        """Simulate DSA signature"""
        sizes = DSA_SIZES[param_set]
        time.sleep(0.003)  # Simulate signing computation
        sig = hashlib.sha3_512(message + sk).digest()
        sig = sig + secrets.token_bytes(sizes['sig'] - len(sig))
        return sig[:sizes['sig']]
    
    @staticmethod
    def dsa_verify(message: bytes, signature: bytes, pk: bytes) -> bool:
        """Simulate DSA verification"""
        time.sleep(0.002)  # Simulate verification computation
        return len(signature) > 0  # Always valid in simulation


class PQCOperations:
    """Production PQC operations using liboqs"""
    
    @staticmethod
    def kem_keygen(param_set: str) -> Tuple[bytes, bytes]:
        """Generate KEM keypair"""
        if LIBOQS_AVAILABLE:
            kem = oqs.KeyEncapsulation(param_set)
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
            return pk, sk
        return PQCSimulator.kem_keygen(param_set)
    
    @staticmethod
    def kem_encaps(pk: bytes, param_set: str) -> Tuple[bytes, bytes]:
        """KEM encapsulation"""
        if LIBOQS_AVAILABLE:
            kem = oqs.KeyEncapsulation(param_set, secret_key=None)
            ct, ss = kem.encap_secret(pk)
            return ct, ss
        return PQCSimulator.kem_encaps(pk, param_set)
    
    @staticmethod
    def kem_decaps(ct: bytes, sk: bytes, param_set: str) -> bytes:
        """KEM decapsulation"""
        if LIBOQS_AVAILABLE:
            kem = oqs.KeyEncapsulation(param_set, secret_key=sk)
            ss = kem.decap_secret(ct)
            return ss
        return PQCSimulator.kem_decaps(ct, sk, param_set)
    
    @staticmethod
    def dsa_keygen(param_set: str) -> Tuple[bytes, bytes]:
        """Generate DSA keypair"""
        if LIBOQS_AVAILABLE:
            dsa = oqs.Signature(param_set)
            pk = dsa.generate_keypair()
            sk = dsa.export_secret_key()
            return pk, sk
        return PQCSimulator.dsa_keygen(param_set)
    
    @staticmethod
    def dsa_sign(message: bytes, sk: bytes, param_set: str) -> bytes:
        """Sign message"""
        if LIBOQS_AVAILABLE:
            dsa = oqs.Signature(param_set, secret_key=sk)
            signature = dsa.sign(message)
            return signature
        return PQCSimulator.dsa_sign(message, sk, param_set)
    
    @staticmethod
    def dsa_verify(message: bytes, signature: bytes, pk: bytes, param_set: str) -> bool:
        """Verify signature"""
        if LIBOQS_AVAILABLE:
            dsa = oqs.Signature(param_set)
            return dsa.verify(message, signature, pk)
        return PQCSimulator.dsa_verify(message, signature, pk)


# ----------------------------------------------------------------------
# 4. STATISTICAL MEASUREMENT FRAMEWORK
# ----------------------------------------------------------------------

def measure_statistical_time(operation: Callable, n_iterations: int) -> MeasurementResult:
    """
    Executes an operation N times to capture distribution D.
    Calculates E[X], Var[X], and other statistics.
    
    Args:
        operation: Callable function to measure
        n_iterations: Number of samples for statistical significance
    
    Returns:
        MeasurementResult with E[X] and distribution parameters
    """
    times_distribution = []
    
    for i in range(n_iterations):
        start_time = time.perf_counter()
        operation()
        end_time = time.perf_counter()
        elapsed_ms = (end_time - start_time) * 1000  # Convert to milliseconds
        times_distribution.append(elapsed_ms)
    
    # Calculate statistics
    mean_value = statistics.mean(times_distribution)
    variance = statistics.variance(times_distribution) if n_iterations > 1 else 0.0
    std_dev = statistics.stdev(times_distribution) if n_iterations > 1 else 0.0
    min_val = min(times_distribution)
    max_val = max(times_distribution)
    
    return MeasurementResult(
        e_value=mean_value,
        variance=variance,
        std_dev=std_dev,
        min_val=min_val,
        max_val=max_val,
        samples=times_distribution
    )


def calculate_m_tx(param_set: Dict[str, str]) -> float:
    """
    Calculates deterministic Bandwidth Cost M_Tx in bytes.
    M_Tx = M_KEM-PK + M_KEM-CT + M_DSA-Sig
    
    Args:
        param_set: Dictionary with 'KEM' and 'DSA' algorithm names
    
    Returns:
        Total bandwidth in bytes
    """
    kem_pk_size = KEM_SIZES[param_set['KEM']]['pk']
    kem_ct_size = KEM_SIZES[param_set['KEM']]['ct']
    dsa_sig_size = DSA_SIZES[param_set['DSA']]['sig']
    
    total_bandwidth = kem_pk_size + kem_ct_size + dsa_sig_size
    return total_bandwidth


# ----------------------------------------------------------------------
# 5. CORE TRANSACTION SIMULATION
# ----------------------------------------------------------------------

def simulate_core_transaction(param_set: Dict[str, str], n_iterations: int) -> TransactionMetrics:
    """
    Simulates complete quantum-safe banking transaction flow.
    
    Flow:
    1. Sender A initiates transfer (ML-KEM Key Exchange)
    2. System validates balance (non-PQC)
    3. Transaction created (ML-DSA Sign by Sender)
    4. Gateway verifies signature (ML-DSA Verify)
    5. Ledger update executed
    6. Audit log signed (ML-DSA Sign by System)
    
    Args:
        param_set: Algorithm configuration {'KEM': '...', 'DSA': '...'}
        n_iterations: Number of statistical samples
    
    Returns:
        TransactionMetrics with L_avg, M_size, T_avg
    """
    print(f"\n[Simulation] Starting transaction flow for {param_set['KEM']}/{param_set['DSA']}...")
    
    # Canonical transaction message
    message_m = b"TRANSFER_100_A_TO_B"
    
    # Pre-generate keys for sender and system
    print("  [1/6] Generating cryptographic keys...")
    pk_sender_a, sk_sender_a = PQCOperations.dsa_keygen(param_set['DSA'])
    pk_system, sk_system = PQCOperations.dsa_keygen(param_set['DSA'])
    pk_kem, sk_kem = PQCOperations.kem_keygen(param_set['KEM'])
    
    # --- Step 1: Key Exchange (Latency L) ---
    print(f"  [2/6] Measuring KEM operations ({n_iterations} iterations)...")
    def kem_operation():
        ct, ss = PQCOperations.kem_encaps(pk_kem, param_set['KEM'])
        ss_decap = PQCOperations.kem_decaps(ct, sk_kem, param_set['KEM'])
    
    result_l = measure_statistical_time(kem_operation, n_iterations)
    print(f"       KEM E[L] = {result_l.e_value:.4f} ms (σ={result_l.std_dev:.4f})")
    
    # --- Step 2: Balance Check (Non-PQC - skipped in measurement) ---
    print("  [3/6] Simulating balance validation...")
    # Simulated: SELECT balance FROM accounts WHERE user_id = 'A'
    
    # --- Step 3: Transaction Signing by Sender A ---
    print(f"  [4/6] Measuring DSA Sign by Sender ({n_iterations} iterations)...")
    def sign_operation_a():
        sig = PQCOperations.dsa_sign(message_m, sk_sender_a, param_set['DSA'])
    
    result_t_sign_a = measure_statistical_time(sign_operation_a, n_iterations)
    print(f"       DSA Sign E[T] = {result_t_sign_a.e_value:.4f} ms")
    
    # Generate signature for verification step
    signature_a = PQCOperations.dsa_sign(message_m, sk_sender_a, param_set['DSA'])
    
    # Calculate static bandwidth cost M_Tx
    m_tx_size = calculate_m_tx(param_set)
    print(f"  [5/6] Bandwidth M_Tx = {m_tx_size} bytes")
    
    # --- Step 4: Gateway Verification ---
    print(f"  [6/6] Measuring DSA Verify by Gateway ({n_iterations} iterations)...")
    def verify_operation_gw():
        valid = PQCOperations.dsa_verify(message_m, signature_a, pk_sender_a, param_set['DSA'])
    
    result_t_verify_gw = measure_statistical_time(verify_operation_gw, n_iterations)
    print(f"       DSA Verify E[T] = {result_t_verify_gw.e_value:.4f} ms")
    
    # --- Step 5: Ledger Update (DEBITED/COMPLETED) ---
    # Simulated: UPDATE accounts SET balance = balance - 100 WHERE user_id = 'A'
    
    # --- Step 6: Audit Log Signing ---
    audit_record = b"AUDIT:TX_12345:COMPLETED:100:A_TO_B"
    def sign_operation_audit():
        sig = PQCOperations.dsa_sign(audit_record, sk_system, param_set['DSA'])
    
    result_t_sign_audit = measure_statistical_time(sign_operation_audit, n_iterations)
    
    # --- AGGREGATION: Total Expected Costs ---
    e_t_compute = (result_t_sign_a.e_value + 
                   result_t_verify_gw.e_value + 
                   result_t_sign_audit.e_value)
    
    print(f"  [Complete] Total Computation E[T] = {e_t_compute:.4f} ms")
    
    return TransactionMetrics(
        l_avg=result_l.e_value,
        m_size=m_tx_size,
        t_avg=e_t_compute
    )


# ----------------------------------------------------------------------
# 6. OPTIMIZATION AND VALIDATION
# ----------------------------------------------------------------------

def calculate_objective_cost(metrics: TransactionMetrics, w_vector: List[float]) -> float:
    """
    Calculates objective cost function J(P).
    J(P) = W_L * L_avg + W_B * M_size + W_T * T_avg
    
    Args:
        metrics: Transaction performance metrics
        w_vector: Weight vector [W_L, W_B, W_T]
    
    Returns:
        Scalar cost J(P)
    """
    j_cost = (w_vector[0] * metrics.l_avg + 
              w_vector[1] * metrics.m_size + 
              w_vector[2] * metrics.t_avg)
    return j_cost


def run_optimization_framework():
    """
    Main execution: Runs complete PQC optimization framework.
    Validates hypothesis that P* (Cat 3) minimizes J(P).
    """
    print("=" * 70)
    print("POST-QUANTUM CRYPTOGRAPHY OPTIMIZATION FRAMEWORK")
    print("Quantum-Safe Banking Parameter Selection")
    print("=" * 70)
    
    print("\n[Configuration]")
    print(f"  Cost Vector W = {W_VECTOR}")
    print(f"  Iterations N = {N_ITERATIONS}")
    print(f"  P* Candidate: {P_STAR['KEM']} + {P_STAR['DSA']} (Category 3)")
    print(f"  P' Candidate: {P_PRIME['KEM']} + {P_PRIME['DSA']} (Category 5)")
    
    # --- Phase 1: Execute Scenario for P* ---
    print("\n" + "=" * 70)
    print("PHASE 1: Measuring P* (Optimized Candidate)")
    print("=" * 70)
    data_p_star = simulate_core_transaction(P_STAR, N_ITERATIONS)
    
    # --- Phase 2: Execute Scenario for P' ---
    print("\n" + "=" * 70)
    print("PHASE 2: Measuring P' (Maximum Security Candidate)")
    print("=" * 70)
    data_p_prime = simulate_core_transaction(P_PRIME, N_ITERATIONS)
    
    # --- Phase 3: Calculate Objective Costs ---
    print("\n" + "=" * 70)
    print("PHASE 3: Cost Function Analysis J(P)")
    print("=" * 70)
    
    cost_p_star = calculate_objective_cost(data_p_star, W_VECTOR)
    cost_p_prime = calculate_objective_cost(data_p_prime, W_VECTOR)
    
    print(f"\n[Cost Calculation]")
    print(f"  J(P*) = {W_VECTOR[0]}*{data_p_star.l_avg:.2f} + "
          f"{W_VECTOR[1]}*{data_p_star.m_size} + "
          f"{W_VECTOR[2]}*{data_p_star.t_avg:.2f}")
    print(f"  J(P*) = {cost_p_star:.2f}")
    
    print(f"\n  J(P') = {W_VECTOR[0]}*{data_p_prime.l_avg:.2f} + "
          f"{W_VECTOR[1]}*{data_p_prime.m_size} + "
          f"{W_VECTOR[2]}*{data_p_prime.t_avg:.2f}")
    print(f"  J(P') = {cost_p_prime:.2f}")
    
    # --- Phase 4: Constrained Device Scenario ---
    print("\n" + "=" * 70)
    print("PHASE 4: Constrained Endpoint Simulation (Scenario 3)")
    print("=" * 70)
    
    t_sign_a_scaled = data_p_star.l_avg * LAMBDA_SCALING
    print(f"  Scaled Latency (Mobile Device): {t_sign_a_scaled:.2f} ms")
    print(f"  Feasibility: {'PASS' if t_sign_a_scaled < 1000 else 'FAIL'} "
          f"(Threshold: 1000ms)")
    
    # --- Phase 5: Hypothesis Validation ---
    print("\n" + "=" * 70)
    print("PHASE 5: FORMAL VALIDATION")
    print("=" * 70)
    
    if cost_p_star < cost_p_prime:
        p_optimal = P_STAR
        delta_cost = ((cost_p_prime - cost_p_star) / cost_p_prime) * 100
        print(f"\n✓ HYPOTHESIS VALIDATED")
        print(f"  P* is ML-KEM-768 + ML-DSA-3 (Category 3)")
        print(f"  Cost Reduction: {delta_cost:.2f}% vs Category 5")
        print(f"\n[Conclusion]")
        print(f"  The empirical results prove that P* (Cat 3) minimizes")
        print(f"  operational cost J(P). Bandwidth optimization (W_B=0.7)")
        print(f"  is the critical design constraint for high-efficiency")
        print(f"  quantum-safe banking institutions.")
    else:
        p_optimal = P_PRIME
        print(f"\n✗ HYPOTHESIS REJECTED")
        print(f"  P_optimal is ML-KEM-1024 + ML-DSA-5 (Category 5)")
        print(f"  Higher security level provides better cost efficiency.")
    
    # --- Export Results ---
    results = {
        'configuration': {
            'w_vector': W_VECTOR,
            'n_iterations': N_ITERATIONS,
            'lambda_scaling': LAMBDA_SCALING
        },
        'p_star': {
            'algorithms': P_STAR,
            'metrics': {
                'l_avg_ms': data_p_star.l_avg,
                'm_size_bytes': data_p_star.m_size,
                't_avg_ms': data_p_star.t_avg
            },
            'j_cost': cost_p_star
        },
        'p_prime': {
            'algorithms': P_PRIME,
            'metrics': {
                'l_avg_ms': data_p_prime.l_avg,
                'm_size_bytes': data_p_prime.m_size,
                't_avg_ms': data_p_prime.t_avg
            },
            'j_cost': cost_p_prime
        },
        'validation': {
            'optimal_parameters': p_optimal,
            'hypothesis_validated': cost_p_star < cost_p_prime,
            'cost_reduction_percent': ((cost_p_prime - cost_p_star) / cost_p_prime * 100) if cost_p_star < cost_p_prime else 0
        }
    }
    
    with open('pqc_optimization_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print("\n" + "=" * 70)
    print("Results exported to: pqc_optimization_results.json")
    print("=" * 70)
    
    return results


# ----------------------------------------------------------------------
# 7. MAIN ENTRY POINT
# ----------------------------------------------------------------------

if __name__ == "__main__":
    results = run_optimization_framework()
