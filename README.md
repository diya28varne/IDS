# ThreatLens

AI-driven hybrid machine learning intrusion detection system for network threat analysis, evidence-based incident investigation, and adaptive reliability monitoring.

## Mission

Turn suspicious network activity into explainable, evidence-backed, prioritized, and measurable security investigations.

ThreatLens is a final-year research prototype for students, researchers, and analysts who want to study an intrusion-detection workflow. It is not an enterprise security platform and it is not a live network defence system.

## Current status

Present now:

- Python package foundation (`src/threatlens`) with a local virtual environment workflow
- Minimal dependencies in `requirements.txt` / `pyproject.toml`
- Dataset **intake** helpers: path conventions, CSV schema checks, load, and stratified train/val/test split
- Synthetic fixture at `tests/fixtures/synthetic_flows.csv` (not a real IDS corpus)
- Smoke tests and intake tests (`pytest`)

Not implemented yet:

- Loading a real CICIDS2017 / UNSW-NB15 extract
- Feature scaling / encoders fitted only on train (next preprocessing step)
- A supervised baseline (planned: Random Forest)
- An anomaly baseline (planned: Isolation Forest)
- A tested hybrid fusion rule
- Explanations, a 0–100 risk score, and an incident ledger
- A backend API and an investigation dashboard
- Drift tests, retraining checks, and reported evaluation numbers

No accuracy, precision, recall, or other model results exist here, because no model has been trained.

## Intended path

Recorded network-flow data, such as CICIDS2017 or UNSW-NB15 when a local copy is available, will be validated and split so that preprocessing is fit only on training data. Two models and a documented fusion rule will score that data. The system will recommend investigation. It will not block live traffic or capture traffic without authorization.

The first build step is a reproducible data pipeline and one evaluated baseline. The dashboard comes after there is real backend data to show.

The later interface will follow the visual language of the public [Mycelium](https://mycelium.nandanadileep.com/) site: warm paper background, large two-colour headlines, and mono labels. That site is a design reference only. Its code and product are not part of this repository.
