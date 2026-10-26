# ThreatLens model evaluation report

This report summarises **measured** results stored in the repository’s evaluation JSON artifacts. Values are copied from those files. No metrics were recalculated for this document, and no missing numbers were invented.

| Artifact | Role |
| --- | --- |
| `artifacts/models/rf_baseline_ddos_friday_metrics.json` | Random Forest validation/test metrics |
| `artifacts/models/if_baseline_ddos_friday_metrics.json` | Isolation Forest proxy metrics |
| `artifacts/models/hybrid_eval_ddos_friday.json` | Hybrid decision counts + RF/IF/hybrid binary proxy |
| `scripts/train_rf_baseline.py` | RF train + evaluate (wrote RF metrics) |
| `scripts/train_if_baseline.py` | IF fit + evaluate (wrote IF metrics) |
| `scripts/eval_hybrid.py` | Hybrid fusion evaluation **without retraining** |

Related reading: [ARCHITECTURE.md](ARCHITECTURE.md), [README](../README.md).

The report separates **measured results**, **interpretation**, and **future recommendations**.

---

## 1. Dataset and split methodology (measured setup)

### Dataset

All three metric files record the same input:

- `data/processed/Friday-WorkingHours-Afternoon-DDos.cleaned.csv`

That file is a cleaned copy of the CICIDS2017 **Friday Working Hours Afternoon DDoS** flow export placed under `data/raw/`. Cleaning (non-finite row removal, exact-duplicate removal, header normalisation) is implemented in `threatlens.data.clean` and does not overwrite the raw CSV.

The subset is **DDoS-heavy** (labels used in evaluation are `BENIGN` and `DDoS`). It is not a multi-attack CICIDS2017 full-week corpus.

### Features and reproducibility

From the RF metrics artifact:

- Seed: `42`
- Features after policy exclusions and train-only constant drops: **66**
- Policy-excluded columns: `Label`, `Destination Port`, `Fwd Header Length.1`
- Train-constant columns dropped (learned on train only):  
  `Bwd PSH Flags`, `Fwd URG Flags`, `Bwd URG Flags`, `CWE Flag Count`,  
  `Fwd Avg Bytes/Bulk`, `Fwd Avg Packets/Bulk`, `Fwd Avg Bulk Rate`,  
  `Bwd Avg Bytes/Bulk`, `Bwd Avg Packets/Bulk`, `Bwd Avg Bulk Rate`

### Train / validation / test split

Implemented in `threatlens.data.split.split_xy`:

1. Stratified `train_test_split` with `test_size=0.2`, `random_state=42`.
2. Stratified split of the remainder with `val_size=0.2` (20% of non-test rows).

Recorded split sizes (RF and IF metrics):

| Split | Rows |
| --- | ---: |
| Train | 142772 |
| Validation | 35693 |
| Test | 44617 |

Models are fit on the **training** split only. Validation metrics are reported as a sanity check; the training scripts state that validation is not used for hyperparameter tuning in this baseline step. Test metrics are the single final holdout evaluation on this CSV.

---

## 2. Random Forest — measured results

**Source:** `rf_baseline_ddos_friday_metrics.json`  
**Hyperparameters recorded:** `n_estimators=100`, `max_depth=20`, seed `42`  
**Class ordering in confusion matrices:** rows = true, columns = predicted, order `(BENIGN, DDoS)`  
**Positive class for FPR:** `DDoS` (FPR = FP / (FP + TN), FP = predicted DDoS when true BENIGN)

### Validation

| Metric | Value |
| --- | --- |
| Accuracy | 0.9998318998122881 |
| Macro-F1 | 0.9998281579308199 |
| Weighted-F1 | 0.9998319026540436 |
| False-positive rate | 6.57418973111564e-05 |
| True-positive rate | 0.9997558832145298 |

| Class | Precision | Recall | F1 | Support |
| --- | ---: | ---: | ---: | ---: |
| BENIGN | 0.9996713769306605 | 0.9999342581026889 | 0.9998028002366397 | 15211 |
| DDoS | 0.9999511671061627 | 0.9997558832145298 | 0.999853515625 | 20482 |

Confusion matrix `(BENIGN, DDoS)`:

|  | Pred BENIGN | Pred DDoS |
| --- | ---: | ---: |
| True BENIGN | 15210 | 1 |
| True DDoS | 5 | 20477 |

### Test

| Metric | Value |
| --- | --- |
| Accuracy | 0.9997310442208127 |
| Macro-F1 | 0.9997250589111059 |
| Weighted-F1 | 0.9997310496760548 |
| False-positive rate | 0.0001577784790154623 |
| True-positive rate | 0.999648478693903 |

| Class | Precision | Recall | F1 | Support |
| --- | ---: | ---: | ---: | ---: |
| BENIGN | 0.9995268138801262 | 0.9998422215209846 | 0.9996844928222117 | 19014 |
| DDoS | 0.9998827987654804 | 0.999648478693903 | 0.999765625 | 25603 |

Confusion matrix `(BENIGN, DDoS)`:

|  | Pred BENIGN | Pred DDoS |
| --- | ---: | ---: |
| True BENIGN | 19011 | 3 |
| True DDoS | 9 | 25594 |

Model artifact path recorded in the metrics file: `artifacts\models\rf_baseline_ddos_friday.joblib`.

---

## 3. Isolation Forest — measured proxy results

**Source:** `if_baseline_ddos_friday_metrics.json`  
**Model:** IsolationForest, `n_estimators=100`, `contamination=0.1`, seed `42`  
**Contamination note (from artifact):** expected outlier proportion for the algorithm, **not** the true attack rate  
**Score direction (from artifact):** higher `decision_function` = more normal; lower = more anomalous  
**Eval mapping (from artifact):** `anomaly→DDoS`, `normal→BENIGN` (**proxy only**; anomaly ≠ attack)  
**Fit note (from artifact):** Isolation Forest was not trained with labels

These binary classification metrics evaluate a **label proxy**, not a claim that Isolation Forest is a supervised DDoS detector.

### Validation (proxy)

| Metric | Value |
| --- | --- |
| Accuracy | 0.3561202476676099 |
| Macro-F1 | 0.2804184910089914 |
| Weighted-F1 | 0.24595153416805005 |
| False-positive rate | 0.20163039905331667 |
| True-positive rate | 0.027682843472317156 |

| Class | Precision | Recall | F1 | Support |
| --- | ---: | ---: | ---: | ---: |
| BENIGN | 0.3788015845784335 | 0.7983696009466833 | 0.5138142585149144 | 15211 |
| DDoS | 0.15602641717116125 | 0.027682843472317156 | 0.0470227235030685 | 20482 |

Confusion matrix `(BENIGN, DDoS)`:

|  | Pred BENIGN | Pred DDoS |
| --- | ---: | ---: |
| True BENIGN | 12144 | 3067 |
| True DDoS | 19915 | 567 |

### Test (proxy)

| Metric | Value |
| --- | --- |
| Accuracy | 0.35538023623282605 |
| Macro-F1 | 0.27906931449266154 |
| Weighted-F1 | 0.24443080089759792 |
| False-positive rate | 0.2013253392237299 |
| True-positive rate | 0.026168808342772333 |

| Class | Precision | Recall | F1 | Support |
| --- | ---: | ---: | ---: | ---: |
| BENIGN | 0.3785238914230165 | 0.7986746607762701 | 0.5136218355233119 | 19014 |
| DDoS | 0.14895509115162295 | 0.026168808342772333 | 0.04451679346201123 | 25603 |

Confusion matrix `(BENIGN, DDoS)`:

|  | Pred BENIGN | Pred DDoS |
| --- | ---: | ---: |
| True BENIGN | 15186 | 3828 |
| True DDoS | 24933 | 670 |

---

## 4. Hybrid decision engine — measured results

**Source:** `hybrid_eval_ddos_friday.json`  
**Script:** `scripts/eval_hybrid.py` (loads existing RF/IF joblibs; does not retrain)  
**Seed:** `42`  
**Input:** same cleaned Friday DDoS CSV  

Hybrid decisions use the fixed fusion policy in `threatlens.models.hybrid`. Binary proxy metrics map `SUSPICIOUS → BENIGN` so anomalies are not promoted to confirmed DDoS (`hybrid_binary_proxy_note` in the artifact).

### Hybrid decision counts (measured)

**Validation** (35693 rows; counts sum to validation size):

| Decision | Count | Proportion of split |
| --- | ---: | ---: |
| BENIGN | 12148 | 12148 / 35693 |
| DDoS | 20478 | 20478 / 35693 |
| SUSPICIOUS | 3067 | 3067 / 35693 |

Recorded `suspicious_rate`: **0.08592721261872076**

**Test** (44617 rows; counts sum to test size):

| Decision | Count | Proportion of split |
| --- | ---: | ---: |
| BENIGN | 15192 | 15192 / 44617 |
| DDoS | 25597 | 25597 / 44617 |
| SUSPICIOUS | 3828 | 3828 / 44617 |

Recorded `suspicious_rate`: **0.08579689356075039**

### Hybrid binary proxy metrics

Under the artifact’s mapping (`SUSPICIOUS` counted as `BENIGN` for binary metrics), the hybrid binary proxy **matches the Random Forest metrics** on the same split (same accuracy, F1, confusion matrix, and FPR values as RF). That is expected when RF alone determines the `DDoS` class and `SUSPICIOUS` is not treated as a positive detection.

**Validation `hybrid_binary_proxy`**

| Metric | Value |
| --- | --- |
| Accuracy | 0.9998318998122881 |
| Macro-F1 | 0.9998281579308199 |
| Weighted-F1 | 0.9998319026540436 |
| FPR | 6.57418973111564e-05 |
| TPR | 0.9997558832145298 |

Confusion matrix: `[[15210, 1], [5, 20477]]` with labels `(BENIGN, DDoS)`.

**Test `hybrid_binary_proxy`**

| Metric | Value |
| --- | --- |
| Accuracy | 0.9997310442208127 |
| Macro-F1 | 0.9997250589111059 |
| Weighted-F1 | 0.9997310496760548 |
| FPR | 0.0001577784790154623 |
| TPR | 0.999648478693903 |

Confusion matrix: `[[19011, 3], [9, 25594]]` with labels `(BENIGN, DDoS)`.

The hybrid JSON also embeds the same RF and Isolation Forest proxy blocks already listed in sections 2 and 3; they agree with the dedicated RF/IF metrics files.

---

## 5. Interpretation (not additional measurements)

### Meaning of Isolation Forest results

Isolation Forest marks **statistical outliers** relative to the training feature distribution. Offline proxy accuracy near ~0.36 and very low DDoS recall under the `anomaly→DDoS` mapping show that “anomaly” is a poor substitute for the supervised DDoS label on this DDoS-heavy subset. Many true DDoS flows are scored `normal`; many BENIGN flows are scored `anomaly`.

That is why the runtime hybrid policy emits **`SUSPICIOUS`** when RF says BENIGN and IF says anomaly, instead of confirming an attack.

### Why `SUSPICIOUS` is not proof of an attack

`SUSPICIOUS` only means the unsupervised detector flagged unusual structure while the supervised classifier did not label DDoS. No ground-truth attack confirmation is implied. Binary evaluation intentionally maps `SUSPICIOUS` to non-DDoS so research metrics do not silently inflate attack detections.

### Why risk scores are not calibrated attack probabilities

Risk scores (`threatlens.models.alerts.compute_risk_score`) are a **prioritisation heuristic** (decision base plus small adjustments from uncalibrated RF probability and IF decision scores). They are clipped to 0–100 and are not trained as probability calibrators. Isolation Forest contamination is not used as a score input. Treat them as investigation ordering aids, not P(attack).

### Why high RF / hybrid binary scores do not establish real-world performance

Measured near-perfect RF scores apply to:

- One cleaned CICIDS2017 **Friday afternoon DDoS** CSV.
- A random stratified row split (not necessarily a time-aware or cross-environment split).
- Features derived from the same recorded lab traffic distribution.

They do **not** prove performance on other CICIDS days, other attack types, other networks, encrypted/modern traffic, or adversarial evasion. `/health` readiness only means artifacts and SQLite loaded.

### Duplicate-flow, leakage, and generalisation concerns

| Concern | What the project does / does not claim |
| --- | --- |
| Exact duplicate rows | Cleaning drops exact duplicates (`keep=first`). Near-duplicates or bidirectional variants may remain. |
| Label leakage | `Label` is excluded from `X`. |
| Metadata leakage | `Destination Port` excluded by default; duplicate `Fwd Header Length.1` excluded. |
| Constant-column leakage | Zero-variance drops are fit on **train** only (`filter_splits_drop_constants`). |
| Temporal leakage | Split is stratified random by row, **not** a chronological cut; related flows can appear across train/val/test. |
| Distribution shift | No multi-site or multi-week generalisation study is included in the saved artifacts. |
| Hybrid vs RF alone | Hybrid notes state the initial policy is **not claimed** to improve metrics over RF alone; binary proxy metrics here match RF when `SUSPICIOUS→BENIGN`. |

---

## 6. Future recommendations (experiments not yet reported here)

These are suggested follow-ups. They are **not** completed results in this repository:

1. Time-ordered or session-aware splits to reduce leakage between related flows.
2. Evaluation on additional CICIDS2017 days and non-DDoS attack classes.
3. Cross-dataset testing (for example another public IDS corpus) without retuning on the test set.
4. Calibration study for RF probabilities if probability-like outputs are required.
5. Explicit analysis of `SUSPICIOUS` quality (analyst review sample, not only binary proxy).
6. Ablations on feature exclusions (e.g. impact of keeping `Destination Port`).
7. Cost-sensitive or threshold analysis for operational false-positive budgets.
8. Robustness checks under feature noise or simple evasion perturbations.

---

## 7. How to regenerate evaluation JSON (optional)

Do **not** run these unless you intentionally want new files. Existing artifacts already contain the numbers above.

```powershell
# RF / IF training writes joblib + metrics (overwrites those artifacts if run)
.\.venv\Scripts\python.exe scripts/train_rf_baseline.py --input data/processed/Friday-WorkingHours-Afternoon-DDos.cleaned.csv
.\.venv\Scripts\python.exe scripts/train_if_baseline.py --input data/processed/Friday-WorkingHours-Afternoon-DDos.cleaned.csv

# Hybrid evaluation loads existing joblibs; writes hybrid_eval JSON only
.\.venv\Scripts\python.exe scripts/eval_hybrid.py --input data/processed/Friday-WorkingHours-Afternoon-DDos.cleaned.csv
```
