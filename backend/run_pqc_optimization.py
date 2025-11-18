"""
Entry point for running PQC optimization framework.
Execute this to run the complete benchmarking suite.
"""

from pqc_optimization_framework import run_optimization_framework

if __name__ == "__main__":
    print("\n🔐 Quantum-Safe Banking: PQC Parameter Optimization\n")
    results = run_optimization_framework()
    print("\n✅ Optimization complete!")
