#!/usr/bin/env python
import csv
import json
import pyotp
import re
import time
from base64 import b64decode, b64encode
from dataclasses import dataclass
from pathlib import Path
from pprint import pprint

from cryptography.fernet import Fernet

@dataclass
class TOTPRecord:
    name: str
    secret: str
    issuer: str | None
    digits: int
    period: int
    uuid: str | None

def import_json(path):
    records = []
    with open(path, "r") as f:
        j = json.load(f)
    for ent in j["db"]["entries"]:
        if ent["type"] != "totp":
            continue
        records.append(TOTPRecord(
            name=ent["name"],
            secret=ent["info"]["secret"],
            issuer=ent.get("issuer"),
            digits=ent["info"]["digits"],
            period=ent["info"]["period"],
            uuid=ent["uuid"]
        ))
    return records

def export_json(records: list[TOTPRecord], path):
    j = {
        "version": 1,
        "header": {
            "slots": None,
            "params": None
        },
        "db": {
            "version": 3,
            "entries": [],
            "groups": [],
            "icons_optimized": True
        }
    }
    entries = j["db"]["entries"]
    for rec in records:
        entries.append({
            "type": "totp",
            "uuid": rec.uuid,
            "name": rec.name,
            "issuer": rec.issuer,
            "note": "",
            "favorite": False,
            "icon": None,
            "info": {
                "secret": rec.secret,
                "algo": "SHA1",
                "digits": rec.digits,
                "period": rec.period
            },
            "groups": []
        })
    with open(path, "w") as f:
        json.dump(j, f, indent=4)

def search_records(records, substr):
    return [
        r for r in records
        if re.search(substr, r.name, re.IGNORECASE)
        or (r.issuer and re.search(substr, r.issuer, re.IGNORECASE))
    ]

def create_totp(rec: TOTPRecord) -> pyotp.TOTP:
    return pyotp.TOTP(
        rec.secret,
        digits=rec.digits,
        interval=rec.period
    )

def remaining_secs(totp: pyotp.TOTP):
    return int(totp.interval - (time.time() % totp.interval))

def encrypt_str(fe: Fernet, s):
    return fe.encrypt(s.encode()).decode()

def decrypt_str(fe: Fernet, s):
    return fe.decrypt(s.encode()).decode()

def store_records(records, path, user_pw):
    fe = Fernet(b64encode(user_pw.encode()[: 32].ljust(32, b"\x00")))
    with open(path, "w") as f:
        writer = csv.writer(f)
        writer.writerow(("name", "secret", "issuer", "digits", "period", "uuid"))
        for rec in records:
            writer.writerow((
                encrypt_str(fe, rec.name),
                encrypt_str(fe, rec.secret),
                encrypt_str(fe, rec.issuer) if rec.issuer else "",
                rec.digits,
                rec.period,
                encrypt_str(fe, rec.uuid) if rec.uuid else ""
            ))

def init_vault(path):
    with open(path, "w") as f:
        writer = csv.writer(f)
        writer.writerow(("name", "secret", "issuer", "digits", "period", "uuid"))

def load_records(path, user_pw):
    p = Path(path)
    if not p.is_file():
        init_vault(path)
        return []
    
    recs = []
    fe = Fernet(b64encode(user_pw.encode()[: 32].ljust(32, b"\x00")))
    with open(path, "r") as f:
        reader = csv.reader(f)
        next(reader)
        for name, secret, issuer, digits, period, uuid in reader:
            recs.append(TOTPRecord(
                name=decrypt_str(fe, name),
                secret=decrypt_str(fe, secret),
                issuer=decrypt_str(fe, issuer) if issuer else None,
                digits=int(digits),
                period=int(period),
                uuid=decrypt_str(fe, uuid) if uuid else None
            ))
    return recs


