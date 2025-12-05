import os
import io
import gzip
import math
import urllib.parse
from collections import Counter

import requests
from bs4 import BeautifulSoup, Comment
from flask import Blueprint, request, jsonify

url_bp = Blueprint("url_bp", __name__)

# ----------------- Config -----------------

PHISH_LIST_PATH = "PHISH_LIST_PATH.txt"  # adjust path if needed
LEGIT_HTML_FOLDER = "url_legit"      # folder of known legit HTML pages
PHISH_HTML_FOLDER = "url_phished"    # folder of known phish HTML pages


# ----------------- Utility Functions -----------------

def normalize_html(html_content: str):
    """Clean HTML by removing scripts, styles, comments, and whitespace."""
    soup = BeautifulSoup(html_content, "html.parser")

    # Remove script/style tags
    for tag in soup(["script", "style"]):
        tag.decompose()

    # Remove comments
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comment.extract()

    return soup


def soup_and_text_from_html(html_content: str):
    """Return BeautifulSoup + encoded text for NCD from raw HTML string."""
    soup = normalize_html(html_content)
    text_bytes = soup.get_text(separator=" ", strip=True).encode("utf-8")
    return soup, text_bytes


def read_html_file(file_path: str):
    """Read and return normalized BeautifulSoup object + text for NCD from file."""
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        raw_html = f.read()
    return soup_and_text_from_html(raw_html)


# ----------------- NCD Approach -----------------

def compress(data: bytes) -> int:
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb") as f:
        f.write(data)
    return len(out.getvalue())


def ncd(x: bytes, y: bytes) -> float:
    Cx = compress(x)
    Cy = compress(y)
    Cxy = compress(x + y)
    return (Cxy - min(Cx, Cy)) / max(Cx, Cy)


# ----------------- DOM Parsing Similarity -----------------

def dom_similarity(soup1, soup2) -> float:
    """Compare HTML tag distributions between two pages."""
    tags1 = Counter([tag.name for tag in soup1.find_all()])
    tags2 = Counter([tag.name for tag in soup2.find_all()])

    set1, set2 = set(tags1.keys()), set(tags2.keys())
    intersection = len(set1 & set2)
    union = len(set1 | set2)
    tag_similarity = intersection / union if union > 0 else 0.0

    return tag_similarity


# ----------------- Link Structure Similarity -----------------

def extract_domains(soup):
    """Extract domains from href/src attributes in HTML."""
    domains = []
    for tag in soup.find_all(["a", "img", "script", "link"]):
        url = tag.get("href") or tag.get("src")
        if url:
            parsed = urllib.parse.urlparse(url)
            if parsed.netloc:
                domains.append(parsed.netloc.lower())
    return set(domains)


def link_similarity(soup1, soup2) -> float:
    """Compare domain sets between two pages."""
    dom1, dom2 = extract_domains(soup1), extract_domains(soup2)
    if not dom1 and not dom2:
        return 0.0
    return len(dom1 & dom2) / len(dom1 | dom2)


# ----------------- Folder Comparison -----------------

def find_best_match(input_soup, input_text: bytes, folder_path: str):
    best_file = None
    best_scores = {"ncd": float("inf"), "dom": 0.0, "links": 0.0}

    if not os.path.isdir(folder_path):
        return None, best_scores

    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path):
            try:
                soup, text = read_html_file(file_path)

                ncd_val = ncd(input_text, text)
                dom_val = dom_similarity(input_soup, soup)
                link_val = link_similarity(input_soup, soup)

                if ncd_val < best_scores["ncd"]:
                    best_file = filename
                    best_scores = {"ncd": ncd_val, "dom": dom_val, "links": link_val}

            except Exception as e:
                print(f"Error reading {file_path}: {e}")
                continue

    return best_file, best_scores


# ----------------- Known Phishing URL List -----------------

def load_phish_list(path: str):
    if not os.path.isfile(path):
        print(f"[WARN] Phish list file not found at {path}")
        return set()

    urls = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            url = line.strip()
            if url:
                urls.add(url.lower())
    print(f"[INFO] Loaded {len(urls)} phishing URLs from {path}")
    return urls


KNOWN_PHISH_URLS = load_phish_list(PHISH_LIST_PATH)


def is_known_phish(url: str) -> bool:
    """Check if URL or its domain appears in the known phishing list."""
    url_norm = url.strip().lower()
    if url_norm in KNOWN_PHISH_URLS:
        return True

    parsed = urllib.parse.urlparse(url_norm)
    domain = parsed.netloc.lower()
    for p_url in KNOWN_PHISH_URLS:
        if domain and domain in p_url:
            return True
    return False


# ----------------- Helper: JSON-safe score objects -----------------

def sanitize_scores(scores: dict | None) -> dict | None:
    """Replace non-finite numbers with None so JSON is valid."""
    if scores is None:
        return None
    safe = {}
    for k, v in scores.items():
        if isinstance(v, (int, float)):
            if math.isfinite(v):
                safe[k] = v
            else:
                safe[k] = None
        else:
            safe[k] = v
    return safe


def ncd_to_sim(ncd_val: float) -> float:
    if not isinstance(ncd_val, (int, float)) or not math.isfinite(ncd_val):
        return 0.0
    return max(0.0, 1.0 - ncd_val)


# ----------------- Classification Logic -----------------

def classify_url(url: str):
    base_result = {
        "url": url,
        "known_phish": False,
        "best_legit_file": None,
        "best_phish_file": None,
        "best_legit_scores": None,
        "best_phish_scores": None,
        "legit_total_score": 0.0,
        "phish_total_score": 0.0,
        "decision": None,
        "message": "",
    }

    # 1) Quick check: is this URL in the phishing list?
    if is_known_phish(url):
        base_result["known_phish"] = True
        base_result["decision"] = "PHISHED"
        base_result["message"] = "⚠️ URL found in known phishing dataset."
        return base_result

    # 2) Try to download the page and do structural comparison
    try:
        resp = requests.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        html = resp.text
    except Exception as e:
        base_result["message"] = f"Could not fetch URL content: {e}"
        return base_result

    input_soup, input_text = soup_and_text_from_html(html)

    legit_file, legit_scores = find_best_match(input_soup, input_text, LEGIT_HTML_FOLDER)
    phish_file, phish_scores = find_best_match(input_soup, input_text, PHISH_HTML_FOLDER)

    # Sanitize scores for JSON
    legit_scores_safe = sanitize_scores(legit_scores) if legit_file else None
    phish_scores_safe = sanitize_scores(phish_scores) if phish_file else None

    base_result["best_legit_file"] = legit_file
    base_result["best_phish_file"] = phish_file
    base_result["best_legit_scores"] = legit_scores_safe
    base_result["best_phish_scores"] = phish_scores_safe

    # No reference HTML? Just return what we have
    if legit_file is None and phish_file is None:
        base_result["message"] = (
            "URL not in phishing list, and no reference HTML pages available for similarity comparison."
        )
        return base_result

    # Convert NCD to similarity
    legit_ncd_sim = ncd_to_sim(legit_scores["ncd"]) if legit_file else 0.0
    phish_ncd_sim = ncd_to_sim(phish_scores["ncd"]) if phish_file else 0.0

    legit_total = (
        legit_ncd_sim + (legit_scores["dom"] or 0.0) + (legit_scores["links"] or 0.0)
        if legit_file
        else 0.0
    )
    phish_total = (
        phish_ncd_sim + (phish_scores["dom"] or 0.0) + (phish_scores["links"] or 0.0)
        if phish_file
        else 0.0
    )

    base_result["legit_total_score"] = legit_total
    base_result["phish_total_score"] = phish_total

    if legit_total > phish_total and legit_total > 0:
        base_result["decision"] = "LEGITIMATE"
        base_result["message"] = (
            f"✅ Classified as LEGITIMATE (Legit score={legit_total:.3f}, Phish score={phish_total:.3f})"
        )
    elif phish_total > 0:
        base_result["decision"] = "PHISHED"
        base_result["message"] = (
            f"⚠️ Classified as PHISHED (Phish score={phish_total:.3f}, Legit score={legit_total:.3f})"
        )
    else:
        base_result["decision"] = None
        base_result["message"] = "No strong evidence from similarity metrics."

    return base_result


# ----------------- Flask Route -----------------

@url_bp.route("/api/url", methods=["POST"])
def url_classify_route():
    """
    Expects JSON: { "url": "http://example.com" }
    """
    data = request.get_json(silent=True) or {}
    url = data.get("url")

    if not url or not isinstance(url, str):
        return jsonify({"error": "Missing or invalid 'url' field"}), 400

    result = classify_url(url)
    return jsonify(result), 200
