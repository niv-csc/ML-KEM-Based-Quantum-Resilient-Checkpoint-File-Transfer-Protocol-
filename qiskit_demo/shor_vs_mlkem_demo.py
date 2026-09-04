"""
Qiskit demo: why "harvest now, decrypt later" is real, and why ML-KEM
resists it.

This does NOT attack ML-KEM-768 -- no quantum computer today, real or
simulated, can run Shor's algorithm on a 3072-bit-equivalent lattice
problem, and a classical simulator like Aer certainly can't. What this
script DOES do, honestly:

  1. Runs a genuine, small-scale instance of Shor's order-finding algorithm
     on Qiskit's Aer simulator, factoring N=15 (the standard textbook-scale
     demo -- the smallest N for which the period-finding circuit is
     non-trivial). This is a real quantum circuit, really simulated, really
     finding the order of a mod N via quantum phase estimation, exactly
     the subroutine that breaks RSA and ECDH at cryptographic scale.
  2. Prints a clearly-labelled, non-simulated comparison table explaining
     *why* the same attack does not scale to ML-KEM: ML-KEM's hardness
     assumption (Module-LWE) is not a hidden-subgroup / period-finding
     problem, so Shor's algorithm has no purchase on it -- this is a
     textbook fact from FIPS 203 / NIST's PQC standardisation rationale,
     stated here, not derived by the circuit above.

Run as: python qiskit_demo/shor_vs_mlkem_demo.py
"""

from __future__ import annotations

import math
from fractions import Fraction

from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator
from qiskit.circuit.library import QFT


N_TO_FACTOR = 15   # textbook Shor's-algorithm demo size
COPRIME_A = 7      # a coprime to N, order r must satisfy a^r = 1 mod N


def _c_amod15(a: int, power: int) -> QuantumCircuit:
    """Controlled multiplication by a^power mod 15, for a in {2,4,7,8,11,13}.
    Standard fixed-N=15 modular exponentiation circuit (textbook Shor's)."""
    if a not in [2, 4, 7, 8, 11, 13]:
        raise ValueError("'a' must be coprime with 15 and in the supported set")
    U = QuantumCircuit(4)
    for _ in range(power):
        if a in [2, 13]:
            U.swap(2, 3); U.swap(1, 2); U.swap(0, 1)
        if a in [7, 8]:
            U.swap(0, 1); U.swap(1, 2); U.swap(2, 3)
        if a in [4, 11]:
            U.swap(1, 3); U.swap(0, 2)
        if a in [7, 11, 13]:
            for q in range(4):
                U.x(q)
    U = U.to_gate()
    U.name = f"{a}^{power} mod 15"
    c_U = U.control()
    return c_U


def run_shor_order_finding(a: int = COPRIME_A, n_count: int = 8, shots: int = 1) -> int:
    """Quantum phase estimation to find the order r of `a` mod 15. Returns
    the measured order r (or 0 if the shot did not yield a useful phase)."""
    qc = QuantumCircuit(n_count + 4, n_count)
    for q in range(n_count):
        qc.h(q)
    qc.x(n_count)  # ancilla register starts in |1>

    for q in range(n_count):
        qc.append(_c_amod15(a, 2 ** q), [q] + list(range(n_count, n_count + 4)))

    qc.append(QFT(n_count, inverse=True).to_gate(), range(n_count))
    qc.measure(range(n_count), range(n_count))

    backend = AerSimulator()
    compiled = transpile(qc, backend)
    result = backend.run(compiled, shots=shots).result()
    counts = result.get_counts()
    measured = max(counts, key=counts.get)
    phase = int(measured, 2) / (2 ** n_count)
    frac = Fraction(phase).limit_denominator(15)
    r = frac.denominator
    return r


def demo_shor_break() -> None:
    print("=== Quantum period-finding on N=15 (Qiskit Aer, real simulated circuit) ===")
    r = run_shor_order_finding()
    print(f"Measured order r = {r} for a={COPRIME_A}, N={N_TO_FACTOR}")
    if r % 2 == 0:
        guess1 = math.gcd(COPRIME_A ** (r // 2) - 1, N_TO_FACTOR)
        guess2 = math.gcd(COPRIME_A ** (r // 2) + 1, N_TO_FACTOR)
        factors = sorted({f for f in (guess1, guess2) if f not in (1, N_TO_FACTOR)})
        print(f"Recovered non-trivial factor(s) of 15: {factors}")
    else:
        print("Odd order this shot -- rerun for a fresh sample (textbook Shor's "
              "is probabilistic; this is expected behaviour, not a bug).")
    print(
        "\nThis is the exact subroutine (quantum order-finding via phase "
        "estimation) that, run at cryptographic scale on a fault-tolerant "
        "quantum computer, recovers the private key behind RSA and ECDH -- "
        "the key exchanges the paper's baseline arm would otherwise use. "
        "N=15 is the largest instance a laptop-scale simulator can run in "
        "reasonable time; RSA-2048 needs thousands of logical qubits, not "
        "yet built. 'Harvest now, decrypt later' means today's captured "
        "ciphertext is still at risk once that hardware exists."
    )


def print_mlkem_resistance_note() -> None:
    print("\n=== Why ML-KEM-768 is not affected the same way (not simulated -- "
          "this is the standardisation rationale from FIPS 203 / NIST PQC) ===")
    rows = [
        ("Hard problem", "Integer factorisation / discrete log", "Module-LWE (lattice)"),
        ("Quantum attack", "Shor's algorithm (polynomial time)", "No known sub-exponential quantum attack"),
        ("Structure exploited", "Hidden subgroup / periodicity", "None known -- worst-case lattice hardness"),
        ("Key/ciphertext size", "~256-384 B (P-256 ECDH)", "1184 B pk / 1088 B ct (ML-KEM-768)"),
        ("Status", "Breakable given a large fault-tolerant QC", "NIST-standardised PQC candidate (FIPS 203, 2024)"),
    ]
    width = max(len(r[0]) for r in rows) + 2
    for label, classical, pqc in rows:
        print(f"{label:<{width}}{classical:<42}{pqc}")


if __name__ == "__main__":
    demo_shor_break()
    print_mlkem_resistance_note()
