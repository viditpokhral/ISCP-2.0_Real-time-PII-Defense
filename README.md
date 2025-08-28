# Project Guardian 2.0 - PII Detection & Redaction

## Overview

This project addresses a PII leak issue at Flixkart, where personal data like phone numbers escapes through unmonitored areas, leading to fraud. I’ve created a Python script to detect and redact this data efficiently.

## Contents

- `detector_full_candidate_name.py`: The Python script for PII detection and redaction.
- `redacted_output_candidate_full_name.csv`: The output file with masked PII.
- `deployment_strategy.md`: My deployment plan for Flixkart’s system.

## How to Run

1. **Requirements**: Python 3.x installed.
2. **Steps**:
    - Place your input CSV (e.g., `iscp_pii_dataset.csv`) in the same folder as the script.
    - Run the command below:

        ```
        python3 detector_full_candidate_name.py iscp_pii_dataset.csv
        ```

        This generates `redacted_output_candidate_full_name.csv`.
3. **Verify**: Open the output file to check the redacted data.
