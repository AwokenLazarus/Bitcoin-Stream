#!/usr/bin/env python3
"""AGP-038: write base.tar, the image layer shared by every agentpay image (docs/CONTAINER.md).

Deterministic (mtime 0, sorted, numeric owners) so the layer digest is the same on every build. It holds:
  /etc/passwd, /etc/group   the service users; each socket group lists its clients (xbt-signer is in
                            xbt-anchor-witness's group; xbt-wallet-mcp and xbt-wallet-ui are in xbt-signer's;
                            xbt-wallet-mcp is in xbt-wallet-ui's, to read the UI-owned MCP token, AGP-042)
  /tmp                      1777 (a tmpfs in compose; the root filesystem is read-only)
  /data/<component>         0700, owned by the component (a named volume mounted here inherits this)
  /data/run/signer, /data/run/anchor   0750, the socket dirs (owner = the server, group = its clients)
  /data/run/ui      0750, the UI's shared dir: mcp-http-token (0640), which the MCP only reads (AGP-042)
    python3 container/mkbase.py OUT.tar
"""
import io
import sys
import tarfile

USERS = [("xbt-signer", 10001), ("xbt-anchor-witness", 10002), ("xbt-wallet-mcp", 10003), ("xbt402-hub", 10004), ("xbt-wallet-ui", 10005),
         ("xbt-work-relay", 10006)]
HOME = {"xbt-signer": "/data/signer", "xbt-anchor-witness": "/data/witness", "xbt-wallet-mcp": "/data/mcp", "xbt402-hub": "/data/hub",
        "xbt-wallet-ui": "/data/ui", "xbt-work-relay": "/data/relay"}
MEMBERS = {"xbt-signer": "xbt-wallet-mcp,xbt-wallet-ui", "xbt-anchor-witness": "xbt-signer", "xbt-wallet-ui": "xbt-wallet-mcp"}

passwd = "root:x:0:0:root:/:/nonexistent\n" + "".join(f"{n}:x:{u}:{u}:{n}:{HOME[n]}:/nonexistent\n" for n, u in USERS)
group = "root:x:0:\n" + "".join(f"{n}:x:{u}:{MEMBERS.get(n, '')}\n" for n, u in USERS)

DIRS = [("etc", 0, 0, 0o755), ("tmp", 0, 0, 0o1777), ("usr", 0, 0, 0o755), ("usr/bin", 0, 0, 0o755), ("data", 0, 0, 0o755),
        ("data/signer", 10001, 10001, 0o700), ("data/witness", 10002, 10002, 0o700), ("data/mcp", 10003, 10003, 0o700),
        ("data/hub", 10004, 10004, 0o700), ("data/ui", 10005, 10005, 0o700), ("data/relay", 10006, 10006, 0o700), ("data/run", 0, 0, 0o755), ("data/run/signer", 10001, 10001, 0o750),
        ("data/run/anchor", 10002, 10002, 0o750), ("data/run/ui", 10005, 10005, 0o750)]
FILES = [("etc/passwd", passwd, 0o644), ("etc/group", group, 0o644)]

entries = []
for path, uid, gid, mode in DIRS:
    t = tarfile.TarInfo(path)
    t.type, t.uid, t.gid, t.mode = tarfile.DIRTYPE, uid, gid, mode
    entries.append((t, None))
for path, text, mode in FILES:
    t = tarfile.TarInfo(path)
    data = text.encode()
    t.size, t.mode = len(data), mode
    entries.append((t, data))
with tarfile.open(sys.argv[1], "w", format=tarfile.PAX_FORMAT) as tar:
    for t, data in sorted(entries, key=lambda e: e[0].name):
        t.mtime, t.uname, t.gname = 0, "", ""
        tar.addfile(t, io.BytesIO(data) if data is not None else None)
