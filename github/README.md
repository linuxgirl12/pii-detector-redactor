# Project Guardian 2.0 - PII Detector & Redactor

Author: Nidhi Sahu

## Contents
- `detector_full_nidhi_sahu.py` - Python script that detects and redacts PII from a CSV input.
- `DEPLOYMENT_STRATEGY_Project_Guardian_2_0.md` - Deployment strategy and architecture notes (includes links to attachments).
- `iscp_pii_dataset_-_Sheet1 (1).csv` - (Uploaded dataset) - include in repo as provided.
- `iscp_pii_dataset_sample.csv` - small sample dataset used for demonstration.
- `mermaid-diagram-2025-08-14-130116.png` - architecture diagram used in the deployment doc.

## Usage
```bash
python3 detector_full_nidhi_sahu.py "iscp_pii_dataset_-_Sheet1 (1).csv"
```

## Notes
- The script follows the challenge PII definitions for standalone vs combinatorial PII.
- Before pushing to GitHub, remove any sensitive production data from the CSV files.
- Add tests and CI as needed for scoring and evaluation pipelines.
