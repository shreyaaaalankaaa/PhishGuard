"""Train PhishGuard on a public labeled URL dataset and compare it with the heuristic fallback.

Dataset: faizann24/Using-machine-learning-to-detect-malicious-URLs (data/data.csv, ~420K URLs, labels good/bad).
Usage:  python scripts/evaluate_model.py data.csv --sample 60000 --legit-domains top-100000-domains

Why --legit-domains: in that dataset the "good" URLs are mostly long paths on a few
sites, while short bare domains are mostly "bad". A model trained on it alone learns
"short URL = phishing" and flags github.com. Adding homepages and common pages of
popular domains (one domain per line, e.g. zer0h/top-1000000-domains) removes that
shortcut. Domains after the ones used for training are kept aside to measure how
often the model wrongly flags a popular site.
"""
import argparse
import json
import random
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ml_pipeline import PhishingDetectionPipeline


def metrics(y, p):
    return {"accuracy": round(accuracy_score(y, p), 4), "precision": round(precision_score(y, p, zero_division=0), 4),
            "recall": round(recall_score(y, p, zero_division=0), 4), "f1": round(f1_score(y, p, zero_division=0), 4)}


ap = argparse.ArgumentParser()
ap.add_argument("csv"); ap.add_argument("--sample", type=int, default=50000); ap.add_argument("--seed", type=int, default=42)
ap.add_argument("--legit-domains", help="file with one popular domain per line, most popular first")
ap.add_argument("--legit-count", type=int, default=15000, help="popular domains added as legitimate examples")
ap.add_argument("--fp-check-count", type=int, default=3000, help="further popular domains held out to measure false positives")
a = ap.parse_args()

df = pd.read_csv(a.csv).dropna().drop_duplicates("url")
df["y"] = (df["label"].str.lower() == "bad").astype(int)
pipe = PhishingDetectionPipeline(); pipe.model = None
ok = []
for u in df["url"]:
    try: pipe.extractor.normalize(u); ok.append(True)
    except ValueError: ok.append(False)
df = df[ok]
if a.sample < len(df):
    df, _ = train_test_split(df, train_size=a.sample, random_state=a.seed, stratify=df["y"])
urls, labels = df["url"].tolist(), df["y"].tolist()

PAGE_SHAPES = ["{d}", "https://{d}/", "https://www.{d}/", "http://{d}", "www.{d}/about",
               "https://{d}/login", "https://accounts.{d}/signin", "https://{d}/help/contact",
               "https://{d}/products?id=42&ref=home", "https://blog.{d}/2025/11/release-notes",
               "https://docs.{d}/3/library/index.html", "https://{d}/en-us/support/article/12345",
               "https://{d}/wiki/Main_Page", "https://{d}/search?q=python+tutorial",
               "https://help.{d}/hc/en-us/articles/360001234567-Account-settings",
               "https://{d}/user/profile/settings.php?tab=security", "https://cdn.{d}/static/app.min.js"]


def popular_urls(domains, rng):
    return [rng.choice(PAGE_SHAPES).format(d=d) for d in domains]


rng = random.Random(a.seed)
fp_urls = []
if a.legit_domains:
    domains = [line.strip().lower() for line in Path(a.legit_domains).read_text(encoding="utf-8").splitlines() if line.strip()]
    train_domains = domains[: a.legit_count]
    check_domains = domains[a.legit_count : a.legit_count + a.fp_check_count]
    extra = popular_urls(train_domains, rng)
    urls += extra
    labels += [0] * len(extra)
    fp_urls = popular_urls(check_domains, rng)
    print(f"Added {len(extra)} popular-site URLs as legitimate; {len(fp_urls)} held out for the false-positive check")
print(f"Sample: {len(urls)} URLs, {sum(labels)} malicious ({sum(labels)/len(labels):.1%})")

# Same split train_model uses (test_size=0.25, random_state=42, stratified) -> heuristic baseline on the identical holdout
idx = np.arange(len(urls))
_, test_idx = train_test_split(idx, test_size=0.25, random_state=42, stratify=labels)
t0 = time.perf_counter()
heur = [1 if pipe.predict(urls[i])["prediction"] == "phishing" else 0 for i in test_idx]
heur_s = time.perf_counter() - t0
baseline = metrics([labels[i] for i in test_idx], heur)

t0 = time.perf_counter()
meta = pipe.train_model(urls, labels)
train_s = time.perf_counter() - t0

fp_check = None
if fp_urls:
    flagged = sum(r["prediction"] == "phishing" for r in pipe.predict_batch(fp_urls))
    fp_check = {"popular_sites_checked": len(fp_urls), "wrongly_flagged": flagged,
                "false_positive_rate": round(flagged / len(fp_urls), 4)}

result = {"samples": len(urls), "popular_site_check": fp_check, "heuristic_holdout": baseline, "model": meta["model_name"],
          "cross_validation": meta["cross_validation"], "model_holdout": meta["holdout_metrics"],
          "f1_gain_points": round((meta["holdout_metrics"]["f1"] - baseline["f1"]) * 100, 1),
          "heuristic_urls_per_sec": round(len(test_idx) / heur_s), "train_seconds": round(train_s, 1)}
print(json.dumps(result, indent=2))
Path("models/evaluation.json").write_text(json.dumps(result, indent=2))
