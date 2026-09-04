
# ML-KEM-Based Quantum-Resilient Checkpoint File Transfer Protocol for 6G Networks

---

## Abstract

The rapid evolution of wireless communication technologies toward sixth‑generation (6G) networks introduces unprecedented demands for secure, efficient, and resilient data transfer. Traditional cryptographic schemes are vulnerable to quantum adversaries, necessitating the adoption of post‑quantum cryptography (PQC). This project proposes and validates a **quantum‑resilient checkpoint file transfer protocol** built on ML‑KEM (Kyber), integrating advanced cryptographic primitives with checkpointing mechanisms to ensure disruption‑tolerant file transfer. The protocol combines ML‑KEM‑768 for key encapsulation, AES‑256‑GCM for authenticated encryption, and HMAC‑protected rolling checkpoints to enable secure resume after link interruptions. Analytical modeling and simulation demonstrate the protocol’s efficiency, with results closely matching theoretical predictions and reproducing benchmark figures. A Qiskit‑based demonstration further motivates the post‑quantum threat model by contrasting Shor’s algorithm with ML‑KEM resilience. This repository consolidates the complete implementation, benchmark harnesses, reproducible figures, and supporting documentation, providing a comprehensive foundation for academic review and practical validation of the proposed framework.

---

## Introduction

This repository accompanies the research paper *“ML-KEM-Based Quantum-Resilient Checkpoint File Transfer Protocol for 6G Networks.”* It contains the complete prototype implementation, analytical models, benchmark harnesses, and demonstration scripts used to validate the proposed framework. The work addresses the challenge of secure and efficient file transfer in next-generation wireless networks, with resilience against quantum adversaries ensured through the use of ML-KEM (Kyber) and robust checkpointing mechanisms.

The repository is structured to support both academic review and reproducibility. It includes the finalized 4‑page paper, presentation slides, architectural diagrams, source code for cryptographic and protocol components, test suites, benchmark scripts, and demonstration outputs. Together, these materials provide a comprehensive view of the system design, theoretical analysis, and practical validation.

---

## Repository Structure

```
.
├── README.md
├── requirements.txt
├── docs/
│   ├── mlkem_6g_checkpoint_4page.pdf
│   ├── ML-KEM-...-FINAL_final.pptx
│   ├── architecture_drawio.pdf
│   ├── flowchart_drawio.pdf
│   └── main_SOURCE_TRUNCATED.pdf
│
├── src/
│   ├── crypto/
│   │   ├── kem.py
│   │   └── aead.py
│   ├── checkpoint/
│   │   └── manager.py
│   ├── channel/
│   │   └── emulator.py
│   ├── protocol/
│   │   ├── model.py
│   │   └── simulator.py
│   └── benchmark/
│       ├── harness.py
│       └── plots.py
│
├── qiskit_demo/
│   └── shor_vs_mlkem_demo.py
│
├── tests/
│   └── test_protocol.py
│
└── results/
    ├── analytical_metrics.csv
    ├── fig3_completion_redundant_interval.png
    └── fig4_goodput_efficiency_reduction.png
```

---

## Components

### Documentation (`docs/`)
- **Review Paper:** `mlkem_6g_checkpoint_4page.pdf` — finalized 4‑page submission document.  
- **Presentation:** `ML-KEM-...-FINAL_final.pptx` — slides prepared for oral presentation.  
- **Figures:** `architecture_drawio.pdf` and `flowchart_drawio.pdf` — system architecture and protocol flow diagrams.  
- **Source Reference:** `main_SOURCE_TRUNCATED.pdf` — truncated TeX source retained for internal reference only.

### Source Code (`src/`)
- **Crypto Layer (`crypto/`):**  
  - `kem.py` — ML-KEM‑768 wrapper.  
  - `aead.py` — HKDF key schedule and AES‑256‑GCM implementation.  
- **Checkpoint Manager (`checkpoint/manager.py`):** Rolling hash and HMAC‑based checkpointing.  
- **Channel Emulator (`channel/emulator.py`):** Parameterized per‑generation network model.  
- **Protocol (`protocol/`):**  
  - `model.py` — closed‑form analytical model reproducing paper results.  
  - `simulator.py` — full end‑to‑end implementation of Algorithm 1.  
- **Benchmark (`benchmark/`):**  
  - `harness.py` — reproduces Table 2 and runs live crypto demo.  
  - `plots.py` — regenerates Figures 3 and 4.

### Demonstrations
- **Qiskit Demo (`qiskit_demo/shor_vs_mlkem_demo.py`):** Illustrates quantum threat model by contrasting Shor’s algorithm with ML-KEM resilience.

### Testing
- **Unit Tests (`tests/test_protocol.py`):** Seven correctness tests covering cryptographic roundtrip, checkpoint integrity, and disruption recovery.

### Results
- **Generated Outputs (`results/`):** Analytical metrics and regenerated figures saved for reproducibility.

---

## Validation Against Paper

- **ML-KEM-768 Parameters:** Public key, ciphertext, and shared secret sizes match FIPS 203 specifications.  
- **Analytical Metrics:** Completion times and checkpoint intervals align closely with published values.  
- **Figures:** Shapes and crossover points reproduced accurately, confirming model fidelity.  
- **Constant `epsilon`:** Derived value consistent with baseline recovery cost assumptions.

---

## References

The paper includes 14 references covering PQC standards, TLS benchmarking, and 5G/6G literature. Additional citations from IEEE ICC/GLOBECOM/CCNC/WCNC 2026 may be added if desired to reflect the most recent developments.

---

## Conclusion

This repository provides a complete package for demonstrating the proposed ML-KEM‑based quantum‑resilient checkpoint file transfer protocol. It integrates theoretical analysis, practical implementation, reproducibility of results, and live demonstrations. The materials herein are intended to support both academic review and practical validation, ensuring that the protocol can be evaluated rigorously and presented effectively.

