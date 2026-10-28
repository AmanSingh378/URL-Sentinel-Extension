from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"
OUTPUT = ROOT / "data" / "urls.csv"

if not SOURCE.exists():
    raise FileNotFoundError(f"Dataset not found: {SOURCE}")

total_rows = 0
skipped_rows = 0
legitimate_count = 0
phishing_count = 0

with OUTPUT.open("w", encoding="utf-8", newline="") as output_file:
    first_chunk = True

    for chunk in pd.read_csv(
        SOURCE,
        usecols=["URL", "label"],
        chunksize=25000,
    ):
        chunk = chunk.rename(columns={"URL": "url"})
        chunk["label"] = pd.to_numeric(chunk["label"], errors="coerce")

        valid = chunk["url"].notna() & chunk["label"].isin([0, 1])
        skipped_rows += int((~valid).sum())

        chunk = chunk.loc[valid, ["url", "label"]].copy()
        chunk["url"] = chunk["url"].astype(str).str.strip()
        chunk = chunk[chunk["url"] != ""]

        # Source dataset: 1 = legitimate, 0 = phishing.
        # Our model: 0 = legitimate, 1 = phishing.
        chunk["label"] = 1 - chunk["label"].astype(int)

        legitimate_count += int((chunk["label"] == 0).sum())
        phishing_count += int((chunk["label"] == 1).sum())
        total_rows += len(chunk)

        chunk.to_csv(
            output_file,
            index=False,
            header=first_chunk,
        )
        first_chunk = False

print("\nDataset preparation complete!")
print(f"Output file: {OUTPUT}")
print(f"Valid rows: {total_rows}")
print(f"Skipped rows: {skipped_rows}")
print(f"Legitimate URLs (0): {legitimate_count}")
print(f"Phishing URLs (1): {phishing_count}")
