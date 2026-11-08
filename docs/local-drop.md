# Local drop — how it works

AirDrop-style transfer between Windows PCs. The PCs connect **directly over Wi-Fi Direct**
(no router, no internet). Using a normal shared network instead is possible, but only when
you ask for it explicitly with `--via lan`.

## What is exposed to the network

| | Default (Wi-Fi Direct) | `--via lan` (opt-in) |
|---|---|---|
| Ports while waiting for a sender | **none** | TCP 47802 + UDP 47801 on all networks |
| Port after the link is up | TCP 47802, **only on the direct link's own IP** | same as above |
| Who may connect | **only the PC at the other end of the link** | anyone on the network (still needs the code) |
| How long the port stays open | until one connection arrives (max 2 min), then closed | same |
| Sender | never listens, only connects out | never listens, only connects out |

You never need to turn the firewall off. Windows may ask once whether Python may accept
connections. Allowing it is safe for the reasons above. Nothing is reachable from your
home, work or café network in the default mode.

## Layers

```
 sender PC                                          receiver PC
 ─────────                                          ───────────
 sdt drop send  ──── protocol.py (sdt-drop/1) ────  sdt drop receive
                     code check (SPAKE2)                shows code 482-913
                     AES-256-GCM, both directions
                ──── TCP port 47802 ─────────────
                ──── link: wifidirect.py  (direct radio link)
                         or lan.py        (same network, UDP discovery on 47801)
```

The link is just a pipe. **All security comes from `protocol.py`**, so it doesn't matter
whether someone else is on the network or can see the radio traffic.

## Security

| Concern | How it's handled |
|---|---|
| Someone else connects pretending to be the sender | They need the 6-digit code, which the receiver shows on screen and tells the sender in person. |
| Guessing the code | SPAKE2 is a password-authenticated key exchange: an attacker gets **one** guess per session (1 in 1,000,000), and the receiver stops after any failed attempt. Recorded traffic doesn't help offline guessing. |
| Man-in-the-middle | Without the code a MITM can't complete SPAKE2. Both sides prove they hold the same key (HMAC key confirmation) before anything is sent. |
| Eavesdropping | File names, sizes and contents are all AES-256-GCM encrypted, with a separate key per direction derived by HKDF from the SPAKE2 key. |
| Tampering, replay, reordering | Every frame is authenticated; nonces are counters, so a replayed, reordered or modified frame fails decryption and the transfer stops. |
| Corrupted / partial files | Each file is written to a hidden `.sdt-partial` file, its SHA-256 is checked, and only then is it renamed into place. Failed files are deleted. |
| Malicious file names | Paths from the sender are sanitized: no `..`, no drive letters or absolute paths, no Windows reserved names (`CON`, `COM¹`, `CONOUT$`, …), no control or invisible characters (e.g. the right-to-left override that makes `invoice[RLO]fdp.exe` look like a PDF). Existing files are never overwritten; a new copy is saved as `name (1).ext`. |
| Unwanted files | The receiver sees the sender name, the file list (exactly as it will be saved) and the total size, and must type `y` before anything is written. Offers larger than the free disk space are refused. |
| Fake prompts on screen | Everything the other side sends (names, messages) has control characters removed before it is printed, so it can't inject terminal escape codes. |
| Other nearby devices | The receiver accepts **one** Wi-Fi Direct link per session and stops advertising as soon as it is up. Further link requests are ignored. |
| Received files and Windows | Received files get the "Mark of the Web", like a browser download, so SmartScreen warns before a received program runs and Office opens documents in Protected View. They are marked "do not index" for Windows Search. Partial files are overwritten before they are deleted. A OneDrive/Dropbox destination is refused unless you pass `--allow-cloud`. |
| Being identified nearby | The receiver advertises a random name (`sdt-4821`) unless you pick one with `--name`; your PC's name is only sent inside the encrypted channel, after the code was verified. |
| Lasting trust between devices | Wi-Fi Direct pairings that sdt creates for a transfer are removed (`unpair`) when the transfer ends. Pairings that already existed are left alone. |
| Picking the wrong receiver | `--to` takes an exact name, or a partial name that matches exactly one receiver. |
| Sending more than you picked | When you send a folder, links/junctions inside it are skipped, so a junction can't make you send e.g. your whole user folder. |

Wi-Fi Direct pairing itself uses "push button" (no PIN). That only controls who can bring
up the radio link and is **not** relied on for security.

## Usage

```powershell
# On the receiving PC
sdt drop receive                 # shows: Code: 482-913

# On the sending PC
sdt drop send report.pdf photos\ # finds the receiver, asks for the code
sdt drop send x.zip --to LAPTOP --code 482-913
sdt drop receive --via lan       # opt-in: normal network (trusted networks only)
sdt drop send x.zip --via lan
sdt drop send x.zip --host 192.168.1.20   # skip discovery
sdt drop peers                   # just list receivers
```

## First-run notes

- **Windows Firewall** may ask once, on the receiver, the first time a link comes up.
  Allowing it is safe (see "What is exposed" above). If you deny it, the sender can't connect.
  On a Windows account without admin rights, "Allow access" asks for an admin password.
  sdt itself still runs without admin rights; the password only lets Windows add the rule.
  The sender never gets this prompt: it only connects out.
- **Finding the receiver** can take a while. The sender keeps looking for up to 30 seconds
  (and stops as soon as it finds one). If it still finds nothing: check Wi-Fi is on on both
  PCs, move them closer, and start `sdt drop receive` first. To check that a PC supports
  Wi-Fi Direct, run `ipconfig /all` and look for a "Microsoft Wi-Fi Direct Virtual Adapter".
- **First Wi-Fi Direct connection** between two PCs: Windows pairs them, and may show a
  prompt or notification. After that they show up under Settings → Bluetooth & devices.
- Wi-Fi must be **on** on both PCs (it doesn't need to be connected to a network).

## Status

- Protocol, encryption, one-connection/linked-PC-only rule: covered by automated tests.
- Verified on one PC: the waiting receiver owns no TCP or UDP ports.
- Wi-Fi Direct: advertising and scanning tested on one PC. A real
  PC-to-PC Wi-Fi Direct transfer still needs testing with **two** Windows PCs.

## Ideas for later
- Remember trusted PCs so the code is only needed the first time.
- Explorer right-click "Send to → sdt" and a tray icon.
- Progress bar and resume for very large transfers.
