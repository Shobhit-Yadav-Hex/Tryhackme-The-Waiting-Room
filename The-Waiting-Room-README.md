# TryHackMe: The Waiting Room

![Platform](https://img.shields.io/badge/Platform-TryHackMe-red)
![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange)
![Category](https://img.shields.io/badge/Category-DFIR%20%7C%20Malware%20Analysis%20%7C%20Network%20Forensics-blue)

Writeup for the TryHackMe room **The Waiting Room**. A supplier email carried an attachment that "did not open as expected". The goal is to reconstruct the execution chain from three pieces of evidence (an email, Sysmon events and a packet capture) and work out what left the workstation.

Room: https://tryhackme.com/room/thewaitingroom

> Flags, hashes, keys and other exact answers are intentionally redacted (`<redacted>`). TryHackMe asks people not to publish them. The method below is enough to reproduce every result yourself.

---

## Evidence

| File | Description |
|------|-------------|
| `vendor.eml` | Supplier email sent to the victim |
| `Sysmon-incident.evtx` | Sysmon events from the workstation |
| `incident.pcap` | Network capture around the incident |
| `tools/` | `evtx_dump`, CyberChef (provided on the AttackBox) |

## Tools Used

`python3` (stdlib `email`, `hashlib`, `json`), `evtx_dump`, `tshark`, `xxd`, `file`, `fold`

> Rule of the room: analyse the attachment **without executing it**. Everything below is static analysis only.

---

## Methodology

### 1. Parse the email and list attachments

```bash
python3 - <<'EOF'
import email, hashlib
from email import policy
m = email.message_from_file(open('vendor.eml'), policy=policy.default)
for k in ('From','To','Subject','Date'): print(k, ':', m[k])
for i, p in enumerate(m.walk()):
    fn = p.get_filename()
    print('part', i, p.get_content_type(), repr(fn))
    if fn:
        data = p.get_payload(decode=True)
        print('  sha256 :', hashlib.sha256(data).hexdigest())
        open('att_%d.bin' % i, 'wb').write(data)
EOF
file att_*.bin
```

The email has a single attachment, a OneNote file (`Remittance.one`). Its hash is the hash of the **wrapper**, not of the file that actually caused the activity. The question asks for the *embedded* attachment, so the wrapper has to be opened up.

### 2. Extract files embedded inside the OneNote file

OneNote stores embedded files as raw bytes after a fixed GUID. Each record has a 36-byte header: 16-byte GUID, 8-byte size, 4 bytes unused, 8 bytes reserved.

```bash
python3 - <<'EOF'
import hashlib
d = open('att_2.bin','rb').read()
guid = bytes.fromhex('e716e3bd65261145a4c48d4d0b7a9eac')
pos = 0; n = 0
while True:
    i = d.find(guid, pos)
    if i < 0: break
    size = int.from_bytes(d[i+16:i+24], 'little')
    blob = d[i+36:i+36+size]
    open('embedded_%d.bin' % n, 'wb').write(blob)
    print(n, size, blob[:8], hashlib.sha256(blob).hexdigest())
    n += 1; pos = i + 16
EOF
file embedded_*.bin
```

Six embedded files came out: three small PNGs, a PDF, a CSV and one HTML document. The PNG, PDF and CSV are decoys that make the note look like a normal remittance advice. The HTML file contains `hta:application` and `ActiveXObject` and is the real payload (an HTA).

### 3. Read the HTA (never run it)

```bash
fold -w 120 embedded_1.bin
```

Observations:
- Strings are stored in an array as hex and each byte is XOR-ed with a single-byte key. A helper function decodes them at runtime, so keyword searches find nothing.
- A `transform()` function is a textbook **RC4** implementation.
- Flow: create `MSXML2.XMLHTTP`, `Scripting.FileSystemObject` and `WScript.Shell`, `GET` a remote file, RC4-decrypt it, save it under `%LOCALAPPDATA%`, then run it with `cscript.exe //B //Nologo`.

Decoding the string table:

```bash
python3 - <<'EOF'
import re
src = open('embedded_1.bin').read()
arr = re.search(r'var entries=\[(.*?)\];', src, re.S).group(1)
for i, h in enumerate(re.findall(r'"([0-9a-f]+)"', arr)):
    print(i, bytes(int(h[j:j+2],16)^57 for j in range(0,len(h),2)).decode('latin1'))
EOF
```

This reveals the download URL, the drop path and filename, the interpreter used, and the RC4 key (hex).

### 4. Correlate with the packet capture

```bash
tshark -r incident.pcap -Y http.request -T fields -e frame.number -e http.host -e http.request.method -e http.request.uri
mkdir -p out && tshark -r incident.pcap --export-objects http,out -q
ls -la out
```

Two requests are visible: a `GET` for an image-looking file, and later a `POST` to an API endpoint. The "image" is not a real PNG. It is the RC4-encrypted second stage.

### 5. Decrypt the second stage (read only)

```bash
python3 - <<'EOF'
key = bytes.fromhex('<KEY_FROM_HTA>')
data = open('out/<downloaded_file>','rb').read()
S = list(range(256)); j = 0
for i in range(256):
    j = (j + S[i] + key[i % len(key)]) & 255
    S[i], S[j] = S[j], S[i]
i = j = 0; out = bytearray()
for b in data:
    i = (i + 1) & 255
    j = (j + S[i]) & 255
    S[i], S[j] = S[j], S[i]
    out.append(b ^ S[(S[i] + S[j]) & 255])
open('receipt_stage.js','wb').write(bytes(out))
EOF
fold -w 120 receipt_stage.js
```

The decrypted script reads a finance spreadsheet from the user's `Documents\Finance` folder, **RC4-encrypts it with the same key** that the HTA wrote into the script as `cacheToken`, base64-encodes it, and POSTs it as JSON to the server.

### 6. Recover the exfiltrated document

The upload is JSON (`reference`, `workstation`, `user`, `document`, `data`). The `data` field is base64 of the RC4 ciphertext, so decrypting with the same key recovers the original file:

```bash
python3 - <<'EOF'
import json, base64, hashlib
key = bytes.fromhex('<KEY_FROM_HTA>')
j = json.load(open('out/receipt'))
data = base64.b64decode(j['data'])
S = list(range(256)); x = 0
for i in range(256):
    x = (x + S[i] + key[i % len(key)]) & 255
    S[i], S[x] = S[x], S[i]
i = x = 0; out = bytearray()
for b in data:
    i = (i + 1) & 255
    x = (x + S[i]) & 255
    S[i], S[x] = S[x], S[i]
    out.append(b ^ S[(S[i] + S[x]) & 255])
open('payment-register.csv','wb').write(bytes(out))
print(hashlib.sha256(bytes(out)).hexdigest())
EOF
cat payment-register.csv
```

The recovered CSV holds invoice numbers, vendor names, amounts and bank account numbers (IBANs).

### 7. Build the Sysmon timeline

```bash
evtx_dump -o jsonl Sysmon-incident.evtx > sysmon.json
python3 - <<'EOF'
import json
for l in open('sysmon.json'):
    d = json.loads(l)
    e = d.get('Event', {}); s = e.get('System', {}); ed = e.get('EventData', {})
    if any(k in json.dumps(ed).lower() for k in ('cscript','mshta','receipt','.hta','.one')):
        print(s.get('EventID'), ed.get('UtcTime'), '| PID', ed.get('ProcessId'), '| PPID', ed.get('ParentProcessId'))
        for k in ('Image','ParentImage','CommandLine','TargetFilename'):
            if ed.get(k): print('   ', k, ':', str(ed[k])[:250])
EOF
```

Execution chain from the logs:

1. `explorer.exe` opens `ONENOTE.EXE` with the `.one` file.
2. `ONENOTE.EXE` writes the HTA into the user's `Downloads` folder (Sysmon Event ID 11). The filename contains a hidden Unicode bidirectional control character, which reverses the end of the name so it looks like a PDF.
3. About 16 minutes later `explorer.exe` launches `mshta.exe` against that file (Event ID 1).
4. `mshta.exe` drops `receipt.js` (Event ID 11) and starts `cscript.exe` as its **child process** (Event ID 1).

Watch the parent/child relationship carefully. The interpreter that runs the downloaded script is `cscript.exe`, not its parent `mshta.exe`.

---

## Attack Chain

```
vendor.eml (supplier phish)
      |
      v
Remittance.one  (OneNote wrapper, 6 embedded files)
      |   user opens .hta from Downloads (RTLO-disguised filename)
      v
mshta.exe  ->  HTA (XOR-hidden strings, RC4 routine)
      |   GET "image" from attacker portal
      v
RC4-encrypted JScript  ->  receipt.js  ->  cscript.exe //B //Nologo
      |   reads Documents\Finance\payment-register.csv
      v
RC4 encrypt + base64  ->  POST /api/receipt  (HTTP 200, accepted)
```

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|----|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 |
| Execution | User Execution: Malicious File | T1204.002 |
| Defense Evasion | Masquerading: Right-to-Left Override | T1036.002 |
| Defense Evasion | System Binary Proxy Execution: Mshta | T1218.005 |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 |
| Defense Evasion | Obfuscated Files or Information | T1027 |
| Command and Control | Ingress Tool Transfer | T1105 |
| Collection | Data from Local System | T1005 |
| Collection | Archive Collected Data (encryption) | T1560 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |

## Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| Email | Supplier-themed message with a `.one` attachment (`Remittance.one`) |
| File | HTA with a Right-to-Left Override character in its name, dropped to `Downloads\PO-*\` |
| File | `%LOCALAPPDATA%\<folder>\receipt.js` |
| Process chain | `mshta.exe` -> `cscript.exe //B //Nologo ... receipt.js` |
| Network | `GET` of a fake `.png` and `POST /api/receipt` to the attacker's portal host (`<redacted>`) |
| Crypto | RC4 key reused for payload decryption and for exfiltration (`<redacted>`) |

## Detection Ideas

- Block or sandbox `.one` attachments at the mail gateway (OneNote can embed executable content).
- Alert on `ONENOTE.EXE` writing `.hta`, `.js`, `.vbs` or `.exe` files to disk (Sysmon Event ID 11).
- Alert on `mshta.exe` launching from `explorer.exe` with a file in `Downloads`.
- Alert on `mshta.exe` spawning `cscript.exe` or `wscript.exe`.
- Alert on `cscript.exe //B //Nologo` running a script from `AppData`.
- Detect Unicode bidirectional control characters (U+202A to U+202E, U+2066 to U+2069) in file names.
- Alert on a user process reading `Documents\Finance` followed by an HTTP POST to a rarely seen host.

## Lessons Learned

- A hash of an email attachment is not always the hash of the malicious file. Look inside container formats (OneNote, ISO, ZIP) for embedded payloads.
- My first extraction used a 32-byte header instead of 36 and produced wrong hashes (each file had 4 extra zero bytes at the start). Always check the magic bytes (`file`, `xxd`) before trusting a hash.
- Sysmon file hashes belong to process images, not to every file seen in the email. I wrongly expected to match the HTA there.
- Filename tricks may not show in plain output. Print the string with `repr()` or `cat -A` to see invisible characters.
- In a parent/child chain, the process that executes the downloaded script is the child. Do not answer with the parent PID.
- Reusing one key for both delivery and exfiltration made the whole exfiltrated document recoverable from the pcap alone.

---

*Written by Shobhit | Cybersecurity learner, CTF and DFIR practice*
