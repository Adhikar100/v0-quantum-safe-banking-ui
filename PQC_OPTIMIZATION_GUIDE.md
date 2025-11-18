# PQC Optimization Framework Guide

## Overview

This framework implements a formal cost optimization algorithm to determine the optimal Post-Quantum Cryptography (PQC) parameter set for quantum-safe banking systems.

## Research Question

**Hypothesis**: P* (ML-KEM-768 + ML-DSA-3, Category 3) minimizes operational costs compared to P' (ML-KEM-1024 + ML-DSA-5, Category 5) for high-efficiency banking institutions.

## Cost Function

\`\`\`
J(P) = W_L * L_avg + W_B * M_size + W_T * T_avg
\`\`\`

Where:
- **W_L = 0.1**: Latency weight (Key Exchange)
- **W_B = 0.7**: Bandwidth weight (HIGH priority for banking)
- **W_T = 0.2**: Computation weight (Sign/Verify operations)

## Installation

\`\`\`bash
cd backend
pip install -r requirements_optimization.txt
\`\`\`

## Running the Framework

\`\`\`bash
python run_pqc_optimization.py
\`\`\`

## Output

The framework will:
1. Measure KEM and DSA operations statistically (N=100 iterations)
2. Calculate expected values E[X] for latency and computation
3. Compute bandwidth costs M_Tx
4. Calculate objective costs J(P*) and J(P')
5. Validate hypothesis and export results to `pqc_optimization_results.json`

## Example Results

\`\`\`
J(P*) = 0.1*2.45 + 0.7*5565 + 0.2*8.32 = 3897.51
J(P') = 0.1*3.12 + 0.7*7753 + 0.2*12.45 = 5430.27

✓ HYPOTHESIS VALIDATED: P* reduces costs by 28.23%
\`\`\`

## Transaction Flow Simulation

1. **Key Exchange** (ML-KEM): Sender establishes secure session key
2. **Balance Check**: Non-PQC database validation
3. **Transaction Sign**: Sender signs transfer with ML-DSA
4. **Gateway Verify**: System verifies signature
5. **Ledger Update**: Debit/credit execution
6. **Audit Sign**: System signs audit log

## Integration with Banking System

The optimal parameters can be integrated into your FastAPI backend:

\`\`\`python
# Use validated optimal parameters
OPTIMAL_KEM = 'Kyber768'   # From framework results
OPTIMAL_DSA = 'Dilithium3'
\`\`\`

## References

- NIST FIPS 203 (ML-KEM)
- NIST FIPS 204 (ML-DSA)
- liboqs documentation: https://github.com/open-quantum-safe/liboqs-python
