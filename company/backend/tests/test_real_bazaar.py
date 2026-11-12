import sys, os
from collections import Counter
from pathlib import Path

from _paths import BACKEND, DATA, DATASETS  # noqa: E402  (tests/_paths.py)
sys.path.insert(0, str(BACKEND))
os.chdir(str(BACKEND))
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.threat_intel import ThreatIndicator
from app.services import threat_intel as ti

f = Path(DATASETS / "public" / "malwarebazaar-recent.csv")
engine = create_engine("sqlite://")
Base.metadata.create_all(engine, tables=[ThreatIndicator.__table__])
db = sessionmaker(bind=engine)()

entries = list(ti.read_list(f, "sha256", "malwarebazaar"))
print("rows parsed:", len(entries))
print("example:", entries[1][:2], entries[1][3:])
print("with a family name:", sum(1 for e in entries if e[3]), "| without:", sum(1 for e in entries if not e[3]))
print("top families:", Counter(e[3] for e in entries if e[3]).most_common(6))
print("add_many:", ti.add_many(db, entries), "| in table:", db.query(ThreatIndicator).count())

win = list(ti.read_list(f, "sha256", "malwarebazaar", types={"exe", "dll", "msi", "scr", "lnk", "js", "vbs"}))
print("only Windows-style types:", len(win), "of", len(entries))
h = ti.lookup(db, "sha256", "f2087ad1d210ebaf2f15e5523eb2a0993483ce4e9541759299365b46a53619c7")
print("lookup the first hash:", h.source, h.category, h.first_seen)
md5 = list(ti.read_list(f, "md5", "malwarebazaar"))
print("the same file as md5 list:", len(md5), md5[0][1])
