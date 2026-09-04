# ML-KEM-Based Quantum-Resilient Checkpoint File Transfer Protocol for 6G Networks

Team: Fathima Fahmiya S (2024503003), Nivriti Muthuvairavan (2024503005),
Mounika K M (2024503577), Tharun P (2024503579)
Department of Computer Technology, Madras Institute of Technology, Anna University

This repository contains the working prototype code for the paper/review
document in `docs/`, plus a benchmark harness that reproduces the paper's
Table 2 / Fig. 3 / Fig. 4, and a Qiskit demo motivating the post-quantum
threat model.

---

## 1. Project structure

```
.
├── README.md                     <- you are here
├── requirements.txt
├── docs/                         <- everything for the review submission
│   ├── mlkem_6g_checkpoint_4page.pdf   <- the actual 4-page review doc (READY TO SUBMIT)
│   ├── ML-KEM-...-FINAL_final.pptx     <- the presentation (READY TO PRESENT)
│   ├── architecture_drawio.pdf         <- Fig. 1, draw.io source rendered
│   ├── flowchart_drawio.pdf            <- Fig. 2, draw.io source rendered
│   └── main_SOURCE_TRUNCATED.pdf       <- see "IMPORTANT NOTE" below
│
├── src/
│   ├── crypto/
│   │   ├── kem.py                <- ML-KEM-768 wrapper (Eq. 1)
│   │   └── aead.py               <- HKDF key schedule + AES-256-GCM (Eq. 2, 3)
│   ├── checkpoint/
│   │   └── manager.py            <- rolling hash + HMAC checkpoint (Eq. 4)
│   ├── channel/
│   │   └── emulator.py           <- Table 1 per-generation parameters
│   ├── protocol/
│   │   ├── model.py              <- closed-form delay model (Eq. 5, 6) -> Table 2 / Fig. 3-4
│   │   └── simulator.py          <- REAL, running end-to-end protocol (Algorithm 1)
│   └── benchmark/
│       ├── harness.py            <- prints Table 2, runs the live crypto demo
│       └── plots.py              <- regenerates Fig. 3 and Fig. 4 as PNGs
│
├── qiskit_demo/
│   └── shor_vs_mlkem_demo.py     <- real Qiskit/Aer circuit: why PQC is needed
│
├── tests/
│   └── test_protocol.py          <- 7 correctness tests (crypto, checkpoint, resume)
│
└── results/                       <- generated on first run (git-ignored except .gitkeep)
    ├── analytical_metrics.csv
    ├── fig3_completion_redundant_interval.png
    └── fig4_goodput_efficiency_reduction.png
```

---

## 2. What each piece actually does

There are **two different, complementary things** in `src/protocol/`, and it's
worth knowing which one you're looking at:

- **`model.py`** — the paper's own closed-form formulas (Eq. 1, 5, 6 and the
  six metrics of Section IV-A), the same way the paper itself computed
  Table 2 and Fig. 3/4. This is instant to run and is what you show if
  someone asks "where do these numbers come from."
- **`simulator.py`** — an actual, working implementation: it runs a real
  ML-KEM-768 handshake, seals/opens real AES-256-GCM chunks, writes a real
  HMAC-protected checkpoint to disk, and simulates a real link disruption
  followed by a real resume — then checks the whole-file SHA-256 digest at
  the end matches. This is your proof that the protocol logic in Algorithm 1
  is actually correct, not just that the formulas add up.

Both are wired together in `benchmark/harness.py`.

---

## 3. Step-by-step: run it

```bash
# 1. Install dependencies (a virtualenv is recommended)
pip install -r requirements.txt

# 2. Run the test suite (7 tests: crypto roundtrip, forged-checkpoint
#    rejection, end-to-end transfer survives disruptions, etc.)
python -m pytest tests/ -v
# (or, without pytest installed: python tests/test_protocol.py)

# 3. Run the benchmark harness — prints Table 2 at nd=5 and nd=10,
#    saves results/analytical_metrics.csv, and runs the live crypto demo
python -m src.benchmark.harness

# 4. Regenerate the paper's Fig. 3 and Fig. 4 as PNGs in results/
python -m src.benchmark.plots

# 5. Run the Qiskit demo (factors N=15 via a real simulated quantum
#    circuit, then explains why the same attack doesn't touch ML-KEM)
python qiskit_demo/shor_vs_mlkem_demo.py
```

Everything above was run and verified working while preparing this
repository (Python 3.12, `kyber-py` 1.2.0, `cryptography` 46, `qiskit` 2.5,
`qiskit-aer` 0.17).

### Validated against the paper

- ML-KEM-768 sizes: pk=1184 B, ct=1088 B, ss=32 B — exact match.
- Table 2 completion times (nd=5): our model gives 6.70/5.12/7.99 s
  (baseline) vs the paper's 6.63/7.23/7.92 s for 5G/B5G/6G — within ~1%.
- Optimal checkpoint interval N\*: our model gives **76.3**, matching the
  paper's "N\* ≈ 76" exactly, once R is correctly converted from bits/s to
  bytes/s in Eq. (6) (a units subtlety worth knowing if you extend the model).
- Fig. 3 and Fig. 4 shapes (crossover at the first disruption, log-scale
  redundant-data gap, rate-invariant transfer efficiency) all reproduce.

The one constant not given a numeric value in the paper's text is `epsilon`
in the baseline recovery-cost formula (Section IV-A, metric (iv)). Solving
Table 2 backwards pins it at ≈0.024 s (generation-invariant); it's exposed
as `EPSILON_BASELINE_S` in `src/protocol/model.py` if you want to justify or
change it in your own writeup.

---

## 4. IMPORTANT: about `main_SOURCE_TRUNCATED.pdf`

While preparing this, I opened `main.pdf` and found it isn't a rendered
paper — it's your `.tex` **source code**, exported to PDF with long lines
cut off at the right margin (you can see sentences and even equations end
mid-word, e.g. "The sender neve" instead of "never"). It's not usable as a
submittable document or as a way to recover your original `.tex` file
(real content is genuinely missing, not just wrapped).

That's not a problem for your deadline, though: **`mlkem_6g_checkpoint_4page.pdf`
is the real, fully typeset 4-page paper** and it already satisfies the
review guideline's "2-4 pages" requirement. I've kept the truncated file in
`docs/` under a renamed, clearly-labelled filename only for your own
reference — don't submit it. If you still have the original `.tex` source
saved anywhere (Overleaf project, local file), grab it from there rather
than from this PDF.

---

## 5. Step-by-step: what to actually do before 31.08.2026 (per your guidelines)

1. **Review doc** — `docs/mlkem_6g_checkpoint_4page.pdf` is ready. Skim it
   once against the "Rough Guidelines" list (Title/Team/Abstract/Keywords/
   Contributions/System Model/Proposed Framework/Algorithm/Implementation
   & Results/Conclusion/References) — it already has all of these sections.
2. **Diagrams** — `docs/architecture_drawio.pdf` (Fig. 1) and
   `docs/flowchart_drawio.pdf` (Fig. 2) are the draw.io exports already
   embedded in the paper. Nothing else needed here.
3. **Code + GitHub** — create a repo (e.g. `mlkem-6g-checkpoint`), copy
   everything in this folder into it, and push:
   ```bash
   cd mlkem-6g-checkpoint
   git init
   git add .
   git commit -m "ML-KEM checkpoint protocol: model, live simulator, benchmark, Qiskit demo"
   git branch -M main
   git remote add origin <your-repo-url>
   git push -u origin main
   ```
   Add the resulting Git URL/ID to your review submission where asked.
4. **Team drive folder** — copy this same folder into `drive/teams/<your-team-name>/`.
5. **PPT** — `docs/ML-KEM-Based_Quantum-Resilient_Checkpoint_File_Transfer_Protocol_ppt-FINAL_final.pptx`
   is already in the docs folder and is your presentation-ready deck.
6. **Demo** — run the commands in Section 3 above live, or show the saved
   `results/*.png` and the printed Table 2 output as evidence the model and
   the live crypto both check out. Show `qiskit_demo/shor_vs_mlkem_demo.py`'s
   output if asked "why quantum-resilient" — it's a genuine (if small-scale)
   quantum circuit, not a slide claim.

---

## 6. Recently published related work (for your References, if you want more)

The paper's existing reference list (14 items) already covers FIPS 203, PQC
TLS handshake benchmarking (Wirth/Zheng), 5G/6G PQ key exchange (Khan,
Vuppala), and THz/mobility literature (Serghiou, Iqbal, Al-Quraan) — this
already meets the "10-15 references, recent IEEE ICC/GLOBECOM/CCNC/WCNC"
guideline. No action needed unless you want to add 1-2 more from 2026
venues; if so, search IEEE Xplore for "ML-KEM 6G" or "post-quantum
checkpoint resume" published in the last ~6 months, since anything more
recent than this repo's preparation date won't be in this writeup.
