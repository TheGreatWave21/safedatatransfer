"""Part 2 — Local drop: an AirDrop-style secure file transfer between Windows PCs.

wifidirect.py  direct PC-to-PC radio link (no router)
lan.py         same-network discovery (fallback)
protocol.py    one-time code (SPAKE2) + AES-256-GCM transfer, used over either link
"""
