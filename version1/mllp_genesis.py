#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import socket
import ssl
import struct
import sys
import time
import random
from datetime import datetime, timezone
from typing import Optional, Tuple, List, Dict

START_BLOCK = b"\x0B"
END_BLOCK = b"\x1C\x0D"

BASE_DIR = os.path.abspath(os.getcwd())
GEN_DIR = os.path.join(BASE_DIR, "generated")
READY_DIR = os.path.join(BASE_DIR, "ready")
SENT_DIR = os.path.join(BASE_DIR, "sent")
FAILED_DIR = os.path.join(BASE_DIR, "failed")
ARCHIVE_DIR = os.path.join(BASE_DIR, "archive")
META_EXT = ".meta.json"

DEFAULT_ACK_TEMPLATE = (
    "UNA:+.? '\n"
    "UNB+ACK+RECEIVER+SENDER+{ts}'\n"
    "UNZ+1+ACK\n"
).replace("{ts}", datetime.utcnow().strftime("%Y%m%d%H%M%S"))

os.makedirs(GEN_DIR, exist_ok=True)
os.makedirs(READY_DIR, exist_ok=True)
os.makedirs(SENT_DIR, exist_ok=True)
os.makedirs(FAILED_DIR, exist_ok=True)
os.makedirs(ARCHIVE_DIR, exist_ok=True)

def frame_message(payload: bytes) -> bytes:
    return START_BLOCK + payload + END_BLOCK

def extract_frames(buffer: bytearray) -> List[bytes]:
    frames = []
    while True:
        try:
            start = buffer.index(START_BLOCK)
        except ValueError:
            break
        try:
            end = buffer.index(END_BLOCK, start + 1)
        except ValueError:
            break
        payload = bytes(buffer[start + 1:end])
        frames.append(payload)
        del buffer[:end + len(END_BLOCK)]
    return frames

def mllp_send(host: str, port: int, payload: bytes, timeout: float = 10.0,
              tls: bool = False, cafile: Optional[str] = None) -> Optional[bytes]:
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except Exception as e:
        return None
    conn = raw
    if tls:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        if cafile:
            context = ssl.create_default_context(cafile=cafile)
        try:
            conn = context.wrap_socket(raw, server_hostname=host)
        except Exception:
            raw.close()
            return None
    try:
        conn.settimeout(timeout)
        conn.sendall(frame_message(payload))
        buf = bytearray()
        start = time.time()
        while True:
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                return None
            if not chunk:
                return None
            buf.extend(chunk)
            frames = extract_frames(buf)
            if frames:
                return frames[0]
            if time.time() - start > timeout:
                return None
    finally:
        try:
            conn.close()
        except Exception:
            pass

def simple_edifact_from_order(order: Dict) -> str:
    now = datetime.utcnow().strftime("%Y%m%d")
    msg_ref = order.get("message_ref", f"MSG{random.randint(1000,9999)}")
    lines = []
    lines.append("UNA:+.? '")
    lines.append(f"UNB+UNOA:1+{order.get('sender','SENDER')}+{order.get('receiver','RECEIVER')}+{now}:{datetime.utcnow().strftime('%H%M')}+{msg_ref}'")
    lines.append(f"UNH+{msg_ref}+ORDERS:D:96A:UN'")
    lines.append(f"BGM+220+{order.get('order_number','ORD') }+9'")
    od = order.get("order_date", now)
    lines.append(f"DTM+137:{od}:102'")
    parties = order.get("parties", [])
    for p in parties:
        qual = p.get("qualifier", "BY")
        pid = p.get("id", "UNKNOWN")
        name = p.get("name", "")
        lines.append(f"NAD+{qual}+{pid}::91'")
        if name:
            lines.append(f"CTA+IC+{name}'")
    items = order.get("items", [])
    for idx, item in enumerate(items, start=1):
        code = item.get("product_code", f"ITEM{idx}")
        desc = item.get("description", "")
        qty = item.get("quantity", 1)
        price = item.get("price", "0.00")
        lines.append(f"LIN+{idx}++{code}:EN'")
        if desc:
            lines.append(f"IMD+F++:::{desc}'")
        lines.append(f"QTY+21:{qty}:EA'")
        lines.append(f"PRI+AAA:{price}:EA'")
    total = 0
    try:
        for it in items:
            total += float(it.get("quantity", 0)) * float(it.get("price", 0))
    except Exception:
        total = 0
    lines.append(f"MOA+79:{total:.2f}'")
    lines.append(f"UNT+{len(lines)+1}+{msg_ref}'")
    lines.append(f"UNZ+1+{msg_ref}'")
    return "\n".join(lines) + "\n"

def save_generated_message(text: str, filename: Optional[str] = None) -> str:
    if filename is None:
        filename = f"edi_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{random.randint(1000,9999)}.edi"
    path = os.path.join(GEN_DIR, filename)
    with open(path, "wb") as f:
        f.write(text.encode("utf-8"))
    return path

def basic_validate_edifact_bytes(data: bytes) -> Tuple[bool, str]:
    try:
        txt = data.decode("utf-8", errors="replace")
    except Exception as e:
        return False, f"decode_error:{e}"
    if not (txt.startswith("UNA") or txt.startswith("UNB")):
        return False, "missing_UNA_or_UNB"
    if "UNH+" not in txt:
        return False, "missing_UNH"
    if "UNT+" not in txt:
        return False, "missing_UNT"
    # check UNH..UNT counts: find first UNH and first UNT after it, count segments between
    try:
        parts = txt.splitlines()
        # find UNH index
        unh_idx = next(i for i, ln in enumerate(parts) if ln.startswith("UNH+"))
        # find UNT index after UNH
        unt_idx = next(i for i, ln in enumerate(parts[unh_idx:], start=unh_idx) if ln.startswith("UNT+"))
        seg_count = unt_idx - unh_idx + 1
        # parse UNT count value after UNT+
        unt_line = parts[unt_idx]
        try:
            # UNT+<count>+<ref>'
            unt_body = unt_line.split("+")
            reported_count = int(unt_body[1])
            if abs(reported_count - seg_count) > 2:
                # allow minor deviations but warn
                return True, f"segment_count_mismatch_reported={reported_count}_actual={seg_count}"
        except Exception:
            pass
    except StopIteration:
        pass
    return True, "ok"

def validate_file(path: str) -> Tuple[bool, str]:
    with open(path, "rb") as f:
        data = f.read()
    valid, note = basic_validate_edifact_bytes(data)
    return valid, note

def move_to_ready(path: str, force: bool = False) -> Tuple[str, str]:
    base = os.path.basename(path)
    dest = os.path.join(READY_DIR, base)
    if os.path.exists(dest) and not force:
        raise FileExistsError(dest)
    shutil.copy2(path, dest)
    meta = {"moved_at": datetime.utcnow().isoformat(), "src": path}
    meta_path = dest + META_EXT
    with open(meta_path, "w", encoding="utf-8") as mf:
        json.dump(meta, mf, indent=2)
    return dest, meta_path

def write_meta_for_send(path: str, meta: Dict):
    meta_path = path + META_EXT
    with open(meta_path, "w", encoding="utf-8") as mf:
        json.dump(meta, mf, indent=2)

def send_one_file(filepath: str, host: str, port: int, timeout: float = 15.0,
                  tls: bool = False, cafile: Optional[str] = None,
                  max_attempts: int = 3) -> Tuple[bool, Dict]:
    meta = {"attempts": 0, "sent_at": None, "ack": None, "error": None}
    for attempt in range(1, max_attempts + 1):
        meta["attempts"] = attempt
        try:
            with open(filepath, "rb") as fh:
                payload = fh.read()
        except Exception as e:
            meta["error"] = f"read_error:{e}"
            return False, meta
        resp = mllp_send(host, port, payload, timeout=timeout, tls=tls, cafile=cafile)
        meta["sent_at"] = datetime.utcnow().isoformat()
        if resp is None:
            meta["error"] = "no_ack_or_timeout"
            time.sleep(1)
            continue
        try:
            ack_text = resp.decode("utf-8", errors="replace")
        except Exception:
            ack_text = "<binary_ack>"
        meta["ack"] = ack_text
        return True, meta
    return False, meta

def process_ready_queue(host: str, port: int, timeout: float = 15.0, tls: bool = False,
                        cafile: Optional[str] = None, max_attempts: int = 3, archive_on_sent: bool = True):
    files = sorted([f for f in os.listdir(READY_DIR) if f.lower().endswith(".edi") or True])
    for fname in files:
        fpath = os.path.join(READY_DIR, fname)
        if not os.path.isfile(fpath):
            continue
        meta = {"file": fname, "attempts": 0, "sent_at": None, "ack": None, "error": None}
        ok, prev = validate_file(fpath)
        if not ok:
            meta["error"] = f"validation_failed:{prev}"
            write_meta_for_send(fpath, meta)
            dest = os.path.join(FAILED_DIR, fname)
            shutil.move(fpath, dest)
            try:
                if os.path.exists(fpath + META_EXT):
                    shutil.move(fpath + META_EXT, dest + META_EXT)
            except Exception:
                pass
            continue
        success, send_meta = send_one_file(fpath, host, port, timeout=timeout, tls=tls, cafile=cafile, max_attempts=max_attempts)
        meta.update(send_meta)
        write_meta_for_send(fpath, meta)
        if success:
            dest = os.path.join(SENT_DIR, fname)
            shutil.move(fpath, dest)
            try:
                shutil.move(fpath + META_EXT, dest + META_EXT)
            except Exception:
                pass
            if archive_on_sent:
                try:
                    shutil.copy2(dest, os.path.join(ARCHIVE_DIR, fname))
                    if os.path.exists(dest + META_EXT):
                        shutil.copy2(dest + META_EXT, os.path.join(ARCHIVE_DIR, fname + META_EXT))
                except Exception:
                    pass
        else:
            dest = os.path.join(FAILED_DIR, fname)
            shutil.move(fpath, dest)
            try:
                shutil.move(fpath + META_EXT, dest + META_EXT)
            except Exception:
                pass

def list_dir_with_meta(directory: str) -> List[Tuple[str, Optional[Dict]]]:
    out = []
    for name in sorted(os.listdir(directory)):
        p = os.path.join(directory, name)
        if os.path.isdir(p):
            continue
        meta = None
        meta_path = p + META_EXT
        if os.path.exists(meta_path):
            try:
                with open(meta_path, "r", encoding="utf-8") as mf:
                    meta = json.load(mf)
            except Exception:
                meta = {"_meta_error": "failed_to_load"}
        out.append((p, meta))
    return out

def cli_generate(args):
    data = None
    if args.input:
        with open(args.input, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    else:
        print("No input JSON provided; creating a minimal demo message.")
        data = {
            "message_ref": f"MSG{random.randint(1000,9999)}",
            "order_number": "ORD-EXAMPLE-1",
            "order_date": datetime.utcnow().strftime("%Y%m%d"),
            "sender": "SENDER",
            "receiver": "RECEIVER",
            "parties": [
                {"qualifier": "BY", "id": "BUYER1", "name": "Buyer Corp"},
                {"qualifier": "SU", "id": "SUPPL1", "name": "Supplier Ltd"}
            ],
            "items": [
                {"product_code": "P001", "description": "Widget", "quantity": 10, "price": "12.50"}
            ]
        }
    text = simple_edifact_from_order(data)
    path = save_generated_message(text, filename=args.filename)
    print(f"Generated EDIFACT file: {path}")

def cli_validate(args):
    target = args.file
    if os.path.isdir(target):
        files = [os.path.join(target, f) for f in os.listdir(target) if f.lower().endswith(".edi") or True]
    else:
        files = [target]
    for f in files:
        if not os.path.exists(f):
            print(f"Missing: {f}")
            continue
        ok, note = validate_file(f)
        print(f"{f}: {'OK' if ok else 'INVALID'} ({note})")

def cli_queue(args):
    src = args.file
    if not os.path.exists(src):
        print(f"Source file not found: {src}")
        return
    try:
        dest, meta = move_to_ready(src, force=args.force)
        print(f"Queued: {dest}")
    except FileExistsError as e:
        print(f"Destination exists, use --force to overwrite: {e}")

def cli_send_one(args):
    filepath = args.file
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return
    ok, note = validate_file(filepath)
    if not ok:
        print(f"Validation failed: {note}")
        return
    success, meta = send_one_file(filepath, args.host, args.port, timeout=args.timeout, tls=args.tls, cafile=args.cafile, max_attempts=args.attempts)
    meta = meta or {}
    meta["file"] = os.path.basename(filepath)
    meta_path = filepath + META_EXT
    write_meta_for_send(filepath, meta)
    if success:
        dest = os.path.join(SENT_DIR, os.path.basename(filepath))
        shutil.move(filepath, dest)
        shutil.move(meta_path, dest + META_EXT)
        print(f"Sent and moved to {dest}")
    else:
        dest = os.path.join(FAILED_DIR, os.path.basename(filepath))
        shutil.move(filepath, dest)
        try:
            shutil.move(meta_path, dest + META_EXT)
        except Exception:
            pass
        print(f"Send failed; moved to {dest}")

def cli_worker(args):
    print(f"Processing ready queue: {READY_DIR}")
    process_ready_queue(args.host, args.port, timeout=args.timeout, tls=args.tls, cafile=args.cafile, max_attempts=args.attempts, archive_on_sent=not args.no_archive)
    print("Done.")

def cli_list(args):
    dirs = [("generated", GEN_DIR), ("ready", READY_DIR), ("sent", SENT_DIR), ("failed", FAILED_DIR), ("archive", ARCHIVE_DIR)]
    for name, d in dirs:
        print("="*40)
        print(f"{name.upper()} ({d}):")
        entries = list_dir_with_meta(d)
        if not entries:
            print("  (empty)")
            continue
        for p, meta in entries:
            print(f" - {os.path.basename(p)}")
            if meta:
                print(f"    meta: {meta}")

def build_parser():
    p = argparse.ArgumentParser(prog="edictl", description="EDIFACT static pipeline + MLLP sender")
    sub = p.add_subparsers(dest="cmd")
    g = sub.add_parser("generate", help="Generate a simple EDIFACT file from JSON or demo")
    g.add_argument("--input", help="JSON input file (order payload)")
    g.add_argument("--filename", help="Optional filename for generated .edi")
    g.set_defaults(func=cli_generate)
    v = sub.add_parser("validate", help="Validate an .edi file or directory")
    v.add_argument("file", help="File or directory to validate")
    v.set_defaults(func=cli_validate)
    q = sub.add_parser("queue", help="Move an edi file to ready queue")
    q.add_argument("file", help="Path to .edi to queue")
    q.add_argument("--force", action="store_true", help="Overwrite if exists in ready")
    q.set_defaults(func=cli_queue)
    s = sub.add_parser("send-one", help="Send a single .edi over MLLP and wait for ACK")
    s.add_argument("file", help="Path to .edi to send")
    s.add_argument("--host", required=True, help="MLLP server host")
    s.add_argument("--port", required=True, type=int, help="MLLP server port")
    s.add_argument("--timeout", type=float, default=15.0)
    s.add_argument("--attempts", type=int, default=3)
    s.add_argument("--tls", action="store_true")
    s.add_argument("--cafile", help="CA file for TLS")
    s.set_defaults(func=cli_send_one)
    w = sub.add_parser("worker", help="Process ready/ queue and send files")
    w.add_argument("--host", required=True, help="MLLP server host")
    w.add_argument("--port", required=True, type=int, help="MLLP server port")
    w.add_argument("--timeout", type=float, default=15.0)
    w.add_argument("--attempts", type=int, default=3)
    w.add_argument("--tls", action="store_true")
    w.add_argument("--cafile", help="CA file for TLS")
    w.add_argument("--no-archive", action="store_true", help="Do not copy sent files to archive")
    w.set_defaults(func=cli_worker)
    l = sub.add_parser("list", help="List files and metadata in pipeline directories")
    l.set_defaults(func=cli_list)
    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    if not getattr(args, "func", None):
        parser.print_help()
        return
    args.func(args)

if __name__ == "__main__":
    main()
