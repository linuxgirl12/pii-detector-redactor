#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Project Guardian 2.0 — PII Detector & Redactor (Final Fixed Version)
Author: Nidhi Sahu
Usage:
    python3 detector_full_nidhi_sahu.py iscp_pii_dataset.csv
"""

import csv
import json
import re
import sys
from typing import Dict, Any, Tuple

# --------- Regexes (more flexible) ----------
PHONE_RE = re.compile(r'(\+91[-\s]?)?[6-9]\d{9}')   # matches +91, spaces, dashes
AADHAAR_RE = re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b')  # Aadhaar with/without spaces/dashes
PASSPORT_RE = re.compile(r'\b([A-Z]{1}[0-9]{7})\b', re.IGNORECASE)  # passport (case-insensitive)
UPI_RE = re.compile(r'\b[\w.\-+]{2,}@[a-zA-Z]{2,}\b', re.IGNORECASE) # UPI IDs
EMAIL_RE = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', re.IGNORECASE) # emails
IPV4_RE = re.compile(r'\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b')

# Device ID: also allow UUIDs (with dashes)
DEVICE_ID_RE = re.compile(r'\b[a-fA-F0-9]{16,64}\b|\b[A-Za-z0-9\-]{20,64}\b')

# --------- Masking functions ----------
def mask_phone(s: str) -> str:
    return PHONE_RE.sub(lambda m: m.group(0)[:2] + "XXXXXX" + m.group(0)[-2:], s)

def mask_aadhaar(s: str) -> str:
    return AADHAAR_RE.sub("XXXX XXXX XXXX", s)

def mask_passport(s: str) -> str:
    return PASSPORT_RE.sub(lambda m: m.group(0)[0] + "XXXXXXX", s)

def mask_upi(s: str) -> str:
    def _m(m):
        v = m.group(0)
        local, domain = v.split("@", 1)
        keep = local[:2]
        return f"{keep}{'X'*max(0,len(local)-2)}@{domain}"
    return UPI_RE.sub(_m, s)

def mask_email(s: str) -> str:
    def _m(m):
        v = m.group(0)
        local, domain = v.split("@", 1)
        keep = local[:2]
        return f"{keep}{'X'*max(0,len(local)-2)}@{domain}"
    return EMAIL_RE.sub(_m, s)

def mask_ipv4(s: str) -> str:
    return IPV4_RE.sub(lambda m: ".".join(m.group(1).split(".")[:-1] + ["x"]), s)

def mask_device_id(s: str) -> str:
    def _m(m):
        v = m.group(0)
        if len(v) <= 6:
            return "X"*len(v)
        return v[:3] + "X"*(len(v)-6) + v[-3:]
    return DEVICE_ID_RE.sub(_m, s)

# --------- Detection + Redaction ----------
def detect_and_redact(record_obj: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    has_pii = False
    redacted = dict(record_obj)

    for k, v in record_obj.items():
        if not isinstance(v, str):
            continue
        original = v

        # Apply all masks
        v = mask_phone(v)
        v = mask_aadhaar(v)
        v = mask_passport(v)
        v = mask_upi(v)
        v = mask_email(v)
        v = mask_ipv4(v)
        v = mask_device_id(v)

        if v != original:   # means something was redacted
            has_pii = True
            redacted[k] = v

    return redacted, has_pii

# --------- CSV Processing ----------
def process(input_csv: str, output_csv: str):
    with open(input_csv, newline='', encoding='utf-8') as f_in, \
         open(output_csv, 'w', newline='', encoding='utf-8') as f_out:
        reader = csv.DictReader(f_in)
        fieldnames = ['record_id', 'redacted_data_json', 'is_pii']
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            rid = row.get('record_id')
            data_json = row.get('data_json', '')   # <-- FIXED (was 'Data_json')

            try:
                obj = json.loads(data_json) if data_json else {}
            except json.JSONDecodeError:
                try:
                    obj = json.loads(data_json.replace("'", '"'))
                except Exception:
                    obj = {"_raw": data_json}

            redacted_obj, is_pii = detect_and_redact(obj)

            redacted_str = json.dumps(redacted_obj, ensure_ascii=False)
            redacted_csv_cell = redacted_str.replace('"', '""')

            writer.writerow({
                'record_id': rid,
                'redacted_data_json': f'"{redacted_csv_cell}"',
                'is_pii': str(bool(is_pii))
            })

# --------- Main ----------
def main():
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_nidhi_sahu.py iscp_pii_dataset.csv")
        sys.exit(1)
    input_csv = sys.argv[1]
    output_csv = "redacted_output_nidhi_sahu.csv"
    process(input_csv, output_csv)
    print(f"Done. Wrote: {output_csv}")

if __name__ == "__main__":
    main()
