"""Where things are, worked out from this file so the checks run on any computer."""
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]  # company/backend
DATA = Path(__file__).resolve().parent / "data"  # the scan uploads the checks post
DATASETS = BACKEND.parents[3] / "datasets"  # Final Year Project/datasets (real events and public lists, kept outside the repository)
