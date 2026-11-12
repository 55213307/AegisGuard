import sys, os, gzip, hashlib, tempfile
from pathlib import Path

from _paths import BACKEND, DATA, DATASETS  # noqa: E402  (tests/_paths.py)
sys.path.insert(0, str(BACKEND))
os.chdir(str(BACKEND))
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.threat_intel import ThreatIndicator
from app.services import threat_intel as ti

# 1. the built-in hashes really are EICAR's: build the 68-byte string in memory (never written to disk)
eicar = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-" + "TEST-FILE!$H+H*").encode()
print("EICAR is", len(eicar), "bytes")
print("sha256 matches:", hashlib.sha256(eicar).hexdigest() == ti.BUILTIN[0][1])
print("md5 matches:   ", hashlib.md5(eicar).hexdigest() == ti.BUILTIN[1][1])

engine = create_engine("sqlite://")
Base.metadata.create_all(engine, tables=[ThreatIndicator.__table__])
db = sessionmaker(bind=engine)()

print("\nseed:", ti.seed_builtin(db), "| again (no duplicates):", ti.seed_builtin(db), "| rows:", db.query(ThreatIndicator).count())
h = ti.lookup(db, "sha256", hashlib.sha256(eicar).hexdigest().upper())  # upper case still found
print("lookup sha256 (upper case):", h.source if h else None, h.category if h else None)
print("lookup unknown hash:", ti.lookup(db, "sha256", "0" * 64))
print("lookup not a hash:", ti.lookup(db, "sha256", "hello"))

# 2. URLs and domains
tmp = Path(tempfile.mkdtemp())
(tmp / "feed.txt").write_text("http://Phish.Example.com/login?x=1#top\nhttps://bad.example.net/a\nnot a url\n\n", encoding="utf-8")
print("\nimport openphish-style list:", ti.add_many(db, ti.read_list(tmp / "feed.txt", "url", "openphish")))
for u in ("http://phish.example.com/login?x=1", "HTTP://PHISH.EXAMPLE.COM/login?x=1#other", "http://phish.example.com/other", "https://eicar.example.org/"):
    hit = ti.check_url(db, u)
    print(f"  {u:50} -> {hit.source + ' ' + hit.value if hit else 'not known'}")
ti.add_many(db, [("domain", "malware-host.example.org", "urlhaus", "malware_download", None)])
hit = ti.check_url(db, "https://malware-host.example.org/any/path.exe")
print("  a URL on a known bad domain ->", hit.kind, hit.value, hit.source if hit else None)

# 3. a MalwareBazaar-style CSV (header as a comment line, quoted cells) and a URLhaus-style one
bazaar = '# MalwareBazaar recent additions\n# "first_seen_utc", "sha256_hash", "md5_hash", "signature", "file_name"\n' \
         '"2026-11-05 10:11:12", "' + "ab" * 32 + '", "' + "cd" * 16 + '", "Emotet", "a.exe"\n' \
         '"2026-11-05 10:11:13", "' + "ef" * 32 + '", "' + "01" * 16 + '", "n/a", "b.exe"\n'
(tmp / "bazaar.csv").write_text(bazaar, encoding="utf-8")
with gzip.open(tmp / "bazaar.csv.gz", "wt", encoding="utf-8") as f:
    f.write(bazaar)
print("\nimport MalwareBazaar-style csv:", ti.add_many(db, ti.read_list(tmp / "bazaar.csv", "sha256", "malwarebazaar")))
print("import the same as .gz (nothing new):", ti.add_many(db, ti.read_list(tmp / "bazaar.csv.gz", "sha256", "malwarebazaar")), "rows:", db.query(ThreatIndicator).count())
h = ti.lookup(db, "sha256", "ab" * 32)
print("  Emotet entry:", h.category, h.first_seen)
print("  entry with no family:", ti.lookup(db, "sha256", "ef" * 32).category)
urlhaus = '# URLhaus\n# id,dateadded,url,url_status,threat,tags\n"1","2026-11-05 09:00:00","http://x.example.net/m.exe","online","malware_download","elf,Mozi"\n'
(tmp / "urlhaus.csv").write_text(urlhaus, encoding="utf-8")
print("import URLhaus-style csv:", ti.add_many(db, ti.read_list(tmp / "urlhaus.csv", "url", "urlhaus")), "->", ti.check_url(db, "http://x.example.net/m.exe").category)
print("\nlookup_many:", sorted(ti.lookup_many(db, "sha256", ["AB" * 32, "0" * 64, "ef" * 32])))
print("stats:", ti.stats(db))
