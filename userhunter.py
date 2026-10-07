#!/usr/bin/env python3
"""
userhunter.py — Username OPSEC-variant generator, multi-site account checker,
and cross-account correlation engine for OSINT/investigative use.

USAGE EXAMPLES:
    # Basic run: generate variants, check accounts, correlate, write reports
    python3 userhunter.py -i seeds.txt -o case001

    # More variants per seed, more threads, verbose
    python3 userhunter.py -i seeds.txt -o case001 --max-variants 250 --threads 40 -v

    # Also merge in results from a local Sherlock install if present
    python3 userhunter.py -i seeds.txt -o case001 --use-sherlock

    # Skip profile-content fetch (faster, less correlation signal)
    python3 userhunter.py -i seeds.txt -o case001 --no-profile-fetch

INPUT:
    A text file, one seed username per line (blank lines / '#' comments ignored).

OUTPUT (written to <output>.json and <output>.csv):
    - Every seed + every variant checked against a built-in list of ~45 platforms
    - For each hit: site, url, http status, page title/meta snippet (if fetched)
    - A correlation section grouping hits that are likely the same person,
      based on username similarity AND/OR overlapping bio/title text across
      different seeds/variants/sites.

DEPENDENCIES:
    pip install requests beautifulsoup4 --break-system-packages

EXIT CODES:
    0 success, 1 input error, 2 no sites reachable (network issue)
"""

import argparse
import concurrent.futures
import csv
import difflib
import itertools
import json
import logging
import re
import shutil
import string
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

try:
    import requests
except ImportError:
    print("Missing dependency: requests. Install with:\n"
          "  pip install requests beautifulsoup4 --break-system-packages", file=sys.stderr)
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
    HAVE_BS4 = True
except ImportError:
    HAVE_BS4 = False

log = logging.getLogger("userhunter")

# Raw triple-quoted so every backslash in the ASCII art stays literal —
# ANSI color codes are spliced in separately via ESC below, never inside
# a raw string (where "\033" would print as four literal characters).
ESC = chr(27)
GREEN, DIM, GREY, RESET = f"{ESC}[92m", f"{ESC}[2m", f"{ESC}[90m", f"{ESC}[0m"

ASCII_ART = r"""
                                 .-------.
                                |  o   o |
                                |   o    |
                                |  o   o |
                                 '-------'
"""

FIGLET = r"""
   _   _ ____  _____ ____  _   _ _   _ _   _ _____ _____ ____
  | | | / ___|| ____|  _ \| | | | | | | \ | |_   _| ____|  _ \
  | | | \___ \|  _| | |_) | |_| | | | |  \| | | | |  _| | |_) |
  | |_| |___) | |___|  _ <|  _  | |_| | |\  | | | | |___|  _ <
   \___/|____/|_____|_| \_\_| |_|\___/|_| \_| |_| |_____|_| \_\
"""

TAGLINE = "          variant-storm your targets. correlate the leads."


def print_banner(use_color: bool = True):
    if use_color and sys.stdout.isatty():
        sys.stdout.write(GREY + ASCII_ART + RESET + "\n")
        sys.stdout.write(GREEN + FIGLET + RESET + DIM + TAGLINE + RESET + "\n\n")
    else:
        # piped output / non-tty / --no-banner-color: plain, no escape codes
        sys.stdout.write(ASCII_ART + "\n" + FIGLET + "\n" + TAGLINE + "\n\n")

# --------------------------------------------------------------------------
# Built-in site list. "exists_if" describes how to decide a profile is real:
#   "status_200"   -> HTTP 200 means it exists, anything else means it doesn't
#   "status_200_not_text" -> HTTP 200 AND absence of error_text means it exists
#                            (many sites return 200 on a "user not found" page)
# --------------------------------------------------------------------------
SITES = {
    "GitHub":        {"url": "https://github.com/{}",                "mode": "status_200"},
    "GitLab":        {"url": "https://gitlab.com/{}",                 "mode": "status_200"},
    "Reddit":        {"url": "https://www.reddit.com/user/{}/about.json", "mode": "status_200_not_text", "error_text": '"error"'},
    "Twitter/X":     {"url": "https://x.com/{}",                      "mode": "status_200_not_text", "error_text": "page doesn\u2019t exist"},
    "Instagram":     {"url": "https://www.instagram.com/{}/",         "mode": "status_200_not_text", "error_text": "Sorry, this page"},
    "TikTok":        {"url": "https://www.tiktok.com/@{}",            "mode": "status_200_not_text", "error_text": "Couldn't find this account"},
    "YouTube":       {"url": "https://www.youtube.com/@{}",           "mode": "status_200_not_text", "error_text": "This channel does not exist"},
    "Twitch":        {"url": "https://www.twitch.tv/{}",              "mode": "status_200_not_text", "error_text": "Sorry. Unless you've got a time machine"},
    "Steam":         {"url": "https://steamcommunity.com/id/{}",      "mode": "status_200_not_text", "error_text": "The specified profile could not be found"},
    "Pinterest":     {"url": "https://www.pinterest.com/{}/",         "mode": "status_200_not_text", "error_text": "Page not found"},
    "Tumblr":        {"url": "https://{}.tumblr.com",                 "mode": "status_200"},
    "Medium":        {"url": "https://medium.com/@{}",                "mode": "status_200_not_text", "error_text": "No stories or Highlights yet"},
    "DeviantArt":    {"url": "https://www.deviantart.com/{}",         "mode": "status_200_not_text", "error_text": "This user doesn't exist"},
    "SoundCloud":    {"url": "https://soundcloud.com/{}",             "mode": "status_200_not_text", "error_text": "Error 404"},
    "Flickr":        {"url": "https://www.flickr.com/people/{}",      "mode": "status_200_not_text", "error_text": "Page Not Found"},
    "Vimeo":         {"url": "https://vimeo.com/{}",                  "mode": "status_200_not_text", "error_text": "Page not found"},
    "Keybase":       {"url": "https://keybase.io/{}",                 "mode": "status_200_not_text", "error_text": "User not found"},
    "HackerNews":    {"url": "https://news.ycombinator.com/user?id={}", "mode": "status_200_not_text", "error_text": "No such user"},
    "StackOverflow": {"url": "https://stackoverflow.com/users/{}",    "mode": "status_200_not_text", "error_text": "Page Not Found"},
    "Replit":        {"url": "https://replit.com/@{}",                "mode": "status_200_not_text", "error_text": "404"},
    "CodePen":       {"url": "https://codepen.io/{}",                 "mode": "status_200_not_text", "error_text": "404"},
    "Dribbble":      {"url": "https://dribbble.com/{}",               "mode": "status_200_not_text", "error_text": "Whoops, that page is gone"},
    "Behance":       {"url": "https://www.behance.net/{}",            "mode": "status_200_not_text", "error_text": "Page not found"},
    "Patreon":       {"url": "https://www.patreon.com/{}",            "mode": "status_200_not_text", "error_text": "Page Not Found"},
    "Telegram":      {"url": "https://t.me/{}",                       "mode": "status_200_not_text", "error_text": "If you have Telegram"},
    "Mastodon.social": {"url": "https://mastodon.social/@{}",         "mode": "status_200_not_text", "error_text": "The page you are looking for"},
    "Kik":           {"url": "https://kik.me/{}",                     "mode": "status_200_not_text", "error_text": "This page is not available"},
    "Spotify":       {"url": "https://open.spotify.com/user/{}",      "mode": "status_200_not_text", "error_text": "not found"},
    "LeetCode":      {"url": "https://leetcode.com/{}/",              "mode": "status_200_not_text", "error_text": "404"},
    "NPM":           {"url": "https://www.npmjs.com/~{}",             "mode": "status_200_not_text", "error_text": "Not Found"},
    "PyPI":          {"url": "https://pypi.org/user/{}/",             "mode": "status_200"},
    "Docker Hub":    {"url": "https://hub.docker.com/u/{}",           "mode": "status_200"},
    "Quora":         {"url": "https://www.quora.com/profile/{}",      "mode": "status_200_not_text", "error_text": "Page not found"},
    "Trello":        {"url": "https://trello.com/{}",                 "mode": "status_200_not_text", "error_text": "trello.com"},
    "Roblox":        {"url": "https://www.roblox.com/user.aspx?username={}", "mode": "status_200_not_text", "error_text": "Page cannot be found"},
    "Chess.com":     {"url": "https://www.chess.com/member/{}",       "mode": "status_200_not_text", "error_text": "Not Found"},
    "ProductHunt":   {"url": "https://www.producthunt.com/@{}",       "mode": "status_200_not_text", "error_text": "Product Hunt - Page not found"},
    "HackerOne":     {"url": "https://hackerone.com/{}",              "mode": "status_200_not_text", "error_text": "Page not found"},
    "Gravatar":      {"url": "https://en.gravatar.com/{}",            "mode": "status_200_not_text", "error_text": "Profile Not Found"},
    "AngelList/Wellfound": {"url": "https://wellfound.com/u/{}",      "mode": "status_200_not_text", "error_text": "Page not found"},
    "VK":            {"url": "https://vk.com/{}",                     "mode": "status_200_not_text", "error_text": "This page has been deleted"},
    "Ask.fm":        {"url": "https://ask.fm/{}",                     "mode": "status_200_not_text", "error_text": "Page not found"},
    "LiveJournal":   {"url": "https://{}.livejournal.com",            "mode": "status_200_not_text", "error_text": "Unknown Journal"},
    "About.me":      {"url": "https://about.me/{}",                   "mode": "status_200_not_text", "error_text": "the page you were looking for"},
    "Linktree":      {"url": "https://linktr.ee/{}",                  "mode": "status_200_not_text", "error_text": "not found"},
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
}

# Generic bot-protection / interstitial markers. Any of these appearing in a
# "200 OK" response means the site challenged the request rather than serving
# the real profile page — treat as inconclusive, never as a hit. This matters
# a lot for accuracy: several platforms front everything (including 404s)
# behind Cloudflare, so a naive status-code check produces false positives.
CHALLENGE_MARKERS = [
    "just a moment", "client challenge", "attention required",
    "cf-chl", "checking your browser", "access denied", "are you a robot",
    "enable javascript and cookies", "unusual traffic",
]

LEET_MAP = {
    "a": ["4", "@"], "e": ["3"], "i": ["1", "!"], "o": ["0"],
    "s": ["5", "$"], "t": ["7"], "b": ["8"], "g": ["9"], "l": ["1"],
}

COMMON_SUFFIXES = [
    "1", "01", "007", "123", "x", "xx", "xxx", "og", "real", "official",
    "_official", "_real", "_og", "69", "420", "99", "2024", "2025", "2026",
    "tv", "hq", "ig", "yt", "gg", "ttv", "dev", "xo", "z",
]
COMMON_PREFIXES = ["the_real_", "real_", "its_", "im_", "iam_", "mr_", "ms_", "x", "_", "."]
DELIMITERS = ["_", ".", "-"]


@dataclass
class Hit:
    seed: str
    variant: str
    site: str
    url: str
    status: str          # "found" / "error"
    title_snippet: str = ""


@dataclass
class CorrelationGroup:
    accounts: list = field(default_factory=list)   # list of "site:url"
    reason: str = ""
    score: float = 0.0


# --------------------------------------------------------------------------
# Variant generation
# --------------------------------------------------------------------------
def leet_variants(word: str, max_combos: int = 20) -> set:
    """Generate leetspeak substitutions. Doesn't explode every combo (that's
    exponential) — samples a bounded set of single and double substitutions."""
    out = set()
    chars = list(word)
    subbable = [i for i, c in enumerate(chars) if c.lower() in LEET_MAP]

    # single-character substitutions
    for i in subbable:
        for repl in LEET_MAP[chars[i].lower()]:
            new = chars.copy()
            new[i] = repl
            out.add("".join(new))

    # pairwise substitutions (bounded)
    count = 0
    for i, j in itertools.combinations(subbable, 2):
        if count >= max_combos:
            break
        for r1 in LEET_MAP[chars[i].lower()]:
            for r2 in LEET_MAP[chars[j].lower()]:
                new = chars.copy()
                new[i], new[j] = r1, r2
                out.add("".join(new))
                count += 1

    # full leet (all substitutions at once)
    full = chars.copy()
    for i in subbable:
        full[i] = LEET_MAP[chars[i].lower()][0]
    out.add("".join(full))

    return out


def case_variants(word: str) -> set:
    out = {word.lower(), word.upper(), word.title(), word.capitalize()}
    # alternating case: tIaN, TiAn
    alt1 = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(word))
    alt2 = "".join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(word))
    out.update({alt1, alt2})
    return out


def delimiter_variants(word: str) -> set:
    out = set()
    for d in DELIMITERS:
        out.add(f"{d}{word}{d}")       # _tian_
        out.add(f"{d}{word}")          # _tian
        out.add(f"{word}{d}")          # tian_
    # delimiter inserted at midpoint for compound-looking names
    if len(word) > 3:
        mid = len(word) // 2
        for d in DELIMITERS:
            out.add(word[:mid] + d + word[mid:])
    return out


def affix_variants(word: str) -> set:
    out = set()
    for s in COMMON_SUFFIXES:
        out.add(word + s)
    for p in COMMON_PREFIXES:
        out.add(p + word)
    return out


def structural_variants(word: str) -> set:
    out = set()
    out.add(word[::-1])                          # reversal
    if len(word) > 2:
        out.add("".join(c for c in word if c.lower() not in "aeiou"))  # vowel drop
    out.add(word.replace("i", "ii"))              # doubled letter trick
    out.add(word[0] + word)                       # doubled first letter
    return out


def generate_variants(seed: str, max_variants: int = 150, no_case_variants: bool = False) -> list:
    """Compose all technique layers, dedupe, cap at max_variants.
    Always attempts to exceed 100 unless the combinatorics genuinely run out
    for a very short seed. --no-case-variants drops the case-mangling layer:
    many platforms are case-insensitive on lookup, so those checks are often
    duplicates of the same account — skipping them frees up variant budget
    for leet/delimiter/affix combinations instead."""
    pool = {seed}
    pool |= leet_variants(seed)
    if not no_case_variants:
        pool |= case_variants(seed)
    pool |= delimiter_variants(seed)
    pool |= affix_variants(seed)
    pool |= structural_variants(seed)

    # second-order: combine leet output with delimiters/affixes for more coverage
    base_leet = list(leet_variants(seed))[:10]
    for lv in base_leet:
        pool |= delimiter_variants(lv)
        pool |= affix_variants(lv)
        if not no_case_variants:
            pool |= case_variants(lv)

    pool.discard("")
    pool.discard(seed)
    variants = sorted(pool, key=len)
    if len(variants) > max_variants - 1:
        variants = variants[:max(max_variants - 1, 0)]
    # the literal seed is always tested, regardless of the cap
    return [seed] + variants


# --------------------------------------------------------------------------
# Account checking
# --------------------------------------------------------------------------
CONNECT_TIMEOUT_CAP = 5  # don't burn the full --timeout waiting on a TCP handshake that isn't coming.
                          # This only affects how long we wait to *establish* a connection — it
                          # never touches how much of the body gets read, so it can't affect
                          # detection accuracy. (A body-size cap was tried and reverted: some
                          # sites inject large JS/JSON blobs before the actual not-found marker
                          # text, so truncating risked silently missing that marker on a few
                          # sites and misreading a real 404 as a hit. Not worth the risk — every
                          # check always reads the full page, same as before.)


def check_one(session: requests.Session, seed: str, variant: str, site: str,
              cfg: dict, timeout: int, fetch_profile: bool,
              retries: int = 0, min_title_length: int = 0) -> Optional[Hit]:
    url = cfg["url"].format(variant)
    connect_timeout = min(CONNECT_TIMEOUT_CAP, timeout)

    resp = None
    last_err = None
    for attempt in range(retries + 1):
        try:
            resp = session.get(url, headers=HEADERS, timeout=(connect_timeout, timeout), allow_redirects=True)
            break
        except Exception as e:
            # Deliberately broad: a malformed variant plugged into a URL template
            # (e.g. a trailing "." landing in a subdomain slot, producing an
            # invalid double-dot hostname) raises urllib3's LocationParseError
            # here — not a requests.RequestException — before any network call
            # is even attempted. One bad variant must never be allowed to take
            # down a multi-hour unattended scan; treat any failure here the
            # same way: log it, skip this one check, move on.
            last_err = e
            if attempt < retries:
                log.debug("Retry %d/%d for %s after: %s: %s", attempt + 1, retries, url, type(e).__name__, e)
                time.sleep(0.5 * (attempt + 1))  # small backoff, not a full retry-storm
    if resp is None:
        log.debug("Request failed for %s after %d attempt(s): %s: %s",
                   url, retries + 1, type(last_err).__name__, last_err)
        return None

    body_text = resp.text
    body_lower = body_text.lower()

    # Bot-protection interstitials masquerade as 200 OK with no real profile
    # content behind them — never count these as a hit either way.
    if resp.status_code == 200 and any(m in body_lower for m in CHALLENGE_MARKERS):
        log.debug("Challenge/interstitial page at %s — treating as inconclusive", url)
        return None

    found = False
    if cfg["mode"] == "status_200":
        found = resp.status_code == 200
    elif cfg["mode"] == "status_200_not_text":
        found = resp.status_code == 200 and cfg["error_text"].lower() not in body_lower

    if not found:
        return None

    snippet = ""
    title = ""
    if fetch_profile and HAVE_BS4:
        try:
            soup = BeautifulSoup(body_text, "html.parser")
            title = soup.title.string.strip() if soup.title and soup.title.string else ""
            desc_tag = soup.find("meta", attrs={"name": "description"}) or \
                       soup.find("meta", attrs={"property": "og:description"})
            desc = desc_tag["content"].strip() if desc_tag and desc_tag.get("content") else ""
            snippet = (title + " | " + desc)[:300]
        except Exception as e:
            log.debug("Profile parse failed for %s: %s", url, e)

    # A "found" page with a suspiciously short/empty title is often a soft-404:
    # passed the status/error-text check but has no real profile content behind
    # it (parked page, template bug, generic placeholder). Only applies when a
    # title was actually extracted (fetch_profile on, bs4 available) — with
    # those off, there's no title to measure, so the filter can't apply.
    if min_title_length > 0 and fetch_profile and HAVE_BS4 and len(title) < min_title_length:
        log.debug("Discarded %s as likely soft-404 (title %d chars, min %d): %r",
                   url, len(title), min_title_length, title)
        return None

    return Hit(seed=seed, variant=variant, site=site, url=url, status="found", title_snippet=snippet)


def build_site_list(exclude: Optional[str], sites_file: Optional[str]) -> dict:
    """Start from the built-in SITES, drop anything in --exclude-sites,
    then merge in anything from --sites-file (same {name: {url, mode, ...}}
    shape; a name already in SITES gets overridden by the file's version)."""
    sites = dict(SITES)

    if exclude:
        names = {n.strip() for n in exclude.split(",") if n.strip()}
        lower_to_real = {k.lower(): k for k in sites}
        unknown = []
        for name in names:
            real = lower_to_real.get(name.lower())
            if real:
                del sites[real]
            else:
                unknown.append(name)
        if unknown:
            log.warning("--exclude-sites: no match for %s (check spelling against the built-in site names)",
                        ", ".join(unknown))

    if sites_file:
        try:
            extra = json.loads(Path(sites_file).read_text(encoding="utf-8"))
        except Exception as e:
            log.error("Could not read --sites-file %s: %s", sites_file, e)
            sys.exit(1)
        added, skipped = 0, []
        for name, cfg in extra.items():
            if not isinstance(cfg, dict) or "url" not in cfg or "mode" not in cfg:
                skipped.append(name)
                continue
            if cfg["mode"] not in ("status_200", "status_200_not_text"):
                skipped.append(name)
                continue
            if cfg["mode"] == "status_200_not_text" and "error_text" not in cfg:
                skipped.append(name)
                continue
            sites[name] = cfg
            added += 1
        log.info("--sites-file: added/overrode %d site(s) from %s", added, sites_file)
        if skipped:
            log.warning("--sites-file: skipped malformed entries: %s", ", ".join(skipped))

    return sites


class LiveWriter:
    """Persists hits to disk as they're found, not just at the end.
    A long scan can run for hours; if it's killed or crashes partway
    through, everything found so far is still on disk — CSV rows are
    appended immediately, and a partial JSON snapshot is rewritten after
    each hit (marked "partial": true, no correlation yet — correlation
    needs the complete hit set and only runs once the scan finishes)."""

    def __init__(self, output_prefix: str, seeds: list):
        self.csv_path = f"{output_prefix}.csv"
        self.partial_json_path = f"{output_prefix}.partial.json"
        self.seeds = seeds
        self.lock = threading.Lock()
        self.hits: list = []
        with open(self.csv_path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(["seed", "variant", "site", "url", "status", "title_snippet"])

    def add(self, hit: "Hit"):
        with self.lock:
            self.hits.append(hit)
            with open(self.csv_path, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow([hit.seed, hit.variant, hit.site, hit.url, hit.status, hit.title_snippet])
            Path(self.partial_json_path).write_text(
                json.dumps({"partial": True, "seeds": self.seeds, "hits": [asdict(h) for h in self.hits]}, indent=2),
                encoding="utf-8",
            )


def run_checks(seed_variant_pairs: list, threads: int, timeout: int,
               fetch_profile: bool, verbose: bool, live: Optional[LiveWriter] = None,
               sites: Optional[dict] = None, retries: int = 0, min_title_length: int = 0) -> list:
    sites = sites if sites is not None else SITES
    hits = []
    session = requests.Session()
    jobs = [(seed, variant, site, cfg)
            for seed, variant in seed_variant_pairs
            for site, cfg in sites.items()]
    total = len(jobs)
    log.info("Dispatching %d checks across %d sites (%d threads)...",
              total, len(sites), threads)

    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {
            pool.submit(check_one, session, seed, variant, site, cfg, timeout, fetch_profile,
                        retries, min_title_length): (seed, variant, site)
            for seed, variant, site, cfg in jobs
        }
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            if verbose and done % 200 == 0:
                log.info("Progress: %d/%d checks complete", done, total)
            try:
                result = fut.result()
            except Exception as e:
                # Belt-and-suspenders: check_one already catches everything it can,
                # but a scan that's going to run for hours unattended must never
                # die from one unanticipated error in a single check. Log it,
                # skip that one check, keep going.
                seed, variant, site = futures[fut]
                log.debug("Unexpected error on %s/%s @ %s: %s: %s", seed, variant, site, type(e).__name__, e)
                continue
            if result:
                hits.append(result)
                if live:
                    live.add(result)
                log.info("[FOUND] %-14s %-25s -> %s", result.site, result.variant, result.url)
    return hits


# --------------------------------------------------------------------------
# Optional Sherlock merge
# --------------------------------------------------------------------------
def run_sherlock(seed: str, timeout: int) -> list:
    """If sherlock is installed on PATH, run it for extra site coverage and
    parse its '[+] Site: url' stdout lines into Hit objects."""
    if not shutil.which("sherlock"):
        log.warning("Sherlock not found on PATH; skipping --use-sherlock for '%s'", seed)
        return []
    try:
        proc = subprocess.run(
            ["sherlock", seed, "--timeout", str(timeout), "--print-found", "--no-color"],
            capture_output=True, text=True, timeout=timeout * 60
        )
    except Exception as e:
        log.warning("Sherlock run failed for %s: %s", seed, e)
        return []

    hits = []
    pattern = re.compile(r"\[\+\]\s*([^:]+):\s*(\S+)")
    for line in proc.stdout.splitlines():
        m = pattern.search(line)
        if m:
            site, url = m.group(1).strip(), m.group(2).strip()
            hits.append(Hit(seed=seed, variant=seed, site=f"sherlock:{site}", url=url, status="found"))
    return hits


# --------------------------------------------------------------------------
# Correlation
# --------------------------------------------------------------------------
def correlate(hits: list, similarity_threshold: float, require_signals: int = 1) -> list:
    """Group hits into likely-same-identity clusters using two signals:
      1. Username text similarity across different seeds (catches a suspect
         reusing a near-identical handle across platforms/seed lists).
      2. Overlapping meaningful words in fetched title/bio snippets.
    require_signals=1 (default) flags a pair if either signal fires.
    require_signals=2 only flags a pair where BOTH agree — fewer, stronger leads.
    Output groups are suggestions for investigator review, not conclusions.
    """
    groups = []
    used_pairs = set()

    def norm(s):
        return re.sub(r"[^a-z0-9]", "", s.lower())

    def snippet_words(s):
        words = re.findall(r"[a-zA-Z]{4,}", s.lower())
        stop = {"page", "profile", "user", "account", "home", "welcome", "https", "http"}
        return set(w for w in words if w not in stop)

    for h1, h2 in itertools.combinations(hits, 2):
        if h1.url == h2.url:
            continue
        key = tuple(sorted([h1.url, h2.url]))
        if key in used_pairs:
            continue

        reasons = []
        score = 0.0

        # signal 1: username similarity (only meaningful across different seeds
        # or sites — same seed/variant on two sites is expected, not a correlation)
        ratio = difflib.SequenceMatcher(None, norm(h1.variant), norm(h2.variant)).ratio()
        if ratio >= similarity_threshold:
            reasons.append(f"username similarity {ratio:.2f}")
            score = max(score, ratio)

        # signal 2: bio/title overlap
        w1, w2 = snippet_words(h1.title_snippet), snippet_words(h2.title_snippet)
        overlap = w1 & w2
        if len(overlap) >= 2:
            reasons.append(f"shared bio/title terms: {', '.join(list(overlap)[:5])}")
            score = max(score, 0.5 + 0.1 * len(overlap))

        if len(reasons) >= require_signals:
            used_pairs.add(key)
            groups.append(CorrelationGroup(
                accounts=[f"{h1.site}:{h1.url}", f"{h2.site}:{h2.url}"],
                reason="; ".join(reasons),
                score=round(min(score, 1.0), 2),
            ))

    groups.sort(key=lambda g: g.score, reverse=True)
    return groups


# --------------------------------------------------------------------------
# I/O
# --------------------------------------------------------------------------
def load_seeds(path: str) -> list:
    p = Path(path)
    if not p.is_file():
        log.error("Input file not found: %s", path)
        sys.exit(1)
    seeds = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            seeds.append(line)
    if not seeds:
        log.error("No usernames found in %s", path)
        sys.exit(1)
    return seeds


def write_reports(output_prefix: str, hits: list, groups: list, seeds: list, variant_map: dict):
    json_path = f"{output_prefix}.json"
    csv_path = f"{output_prefix}.csv"

    report = {
        "seeds": seeds,
        "variants_generated": {s: len(v) for s, v in variant_map.items()},
        "total_hits": len(hits),
        "hits": [asdict(h) for h in hits],
        "correlation_groups": [asdict(g) for g in groups],
    }
    Path(json_path).write_text(json.dumps(report, indent=2), encoding="utf-8")

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["seed", "variant", "site", "url", "status", "title_snippet"])
        for h in hits:
            writer.writerow([h.seed, h.variant, h.site, h.url, h.status, h.title_snippet])

    return json_path, csv_path


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Generate OPSEC-aware username variants, check them against "
                    "known platforms, and correlate findings for investigation leads.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-i", "--input", required=True, help="Text file, one seed username per line")
    parser.add_argument("-o", "--output", default="userhunter_report", help="Output file prefix (default: userhunter_report)")
    parser.add_argument("--max-variants", type=int, default=150, help="Max variants generated per seed (default 150, min effectively ~100)")
    parser.add_argument("--threads", type=int, default=30, help="Concurrent HTTP workers (default 30)")
    parser.add_argument("--timeout", type=int, default=8, help="Per-request timeout in seconds (default 8)")
    parser.add_argument("--similarity-threshold", type=float, default=0.82, help="Min ratio (0-1) for username correlation (default 0.82)")
    parser.add_argument("--use-sherlock", action="store_true", help="Also run Sherlock (if installed) on each seed for extra site coverage")
    parser.add_argument("--no-profile-fetch", action="store_true", help="Skip fetching title/bio snippets (faster, less correlation signal)")
    parser.add_argument("--retries", type=int, default=0, help="Retry a check this many times on timeout/connection failure before giving up (default 0)")
    parser.add_argument("--min-title-length", type=int, default=0, help="Discard a hit if its extracted title is shorter than this — filters soft-404s (default 0, off)")
    parser.add_argument("--exclude-sites", help="Comma-separated site names to skip, e.g. 'Kik,VK,Ask.fm'")
    parser.add_argument("--sites-file", help="JSON file of additional/override site definitions, same shape as the built-in list")
    parser.add_argument("--no-case-variants", action="store_true", help="Skip case-mangled variants (TiAn, TIAN, ...) — frees variant budget for other techniques")
    parser.add_argument("--require-signal", type=int, choices=[1, 2], default=1, help="1 = flag a correlation if either signal fires (default). 2 = require both (fewer, stronger leads)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    print_banner()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    # -v is meant to show userhunter's own progress, not every HTTP library
    # internal (connection setup, raw request/response lines). Keep those
    # libraries quiet regardless of verbosity so -v output stays readable.
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("charset_normalizer").setLevel(logging.WARNING)

    if not HAVE_BS4 and not args.no_profile_fetch:
        log.warning("beautifulsoup4 not installed — profile snippets disabled. "
                    "Install with: pip install beautifulsoup4 --break-system-packages")

    seeds = load_seeds(args.input)
    log.info("Loaded %d seed username(s): %s", len(seeds), ", ".join(seeds))

    sites = build_site_list(args.exclude_sites, args.sites_file)

    variant_map = {}
    seed_variant_pairs = []
    for seed in seeds:
        variants = generate_variants(seed, max_variants=args.max_variants, no_case_variants=args.no_case_variants)
        variant_map[seed] = variants
        log.info("Seed '%s': %d variants generated", seed, len(variants))
        for v in variants:
            seed_variant_pairs.append((seed, v))

    live = LiveWriter(args.output, seeds)
    log.info("Live results will be written to %s and %s as they're found "
              "(safe to interrupt — nothing found so far will be lost).",
              live.csv_path, live.partial_json_path)

    start = time.time()
    hits = run_checks(
        seed_variant_pairs,
        threads=args.threads,
        timeout=args.timeout,
        fetch_profile=(not args.no_profile_fetch) and HAVE_BS4,
        verbose=args.verbose,
        live=live,
        sites=sites,
        retries=args.retries,
        min_title_length=args.min_title_length,
    )

    if args.use_sherlock:
        for seed in seeds:
            sherlock_hits = run_sherlock(seed, timeout=args.timeout)
            for h in sherlock_hits:
                live.add(h)
            hits.extend(sherlock_hits)

    elapsed = time.time() - start
    log.info("Scan complete in %.1fs — %d account(s) found across %d checks",
              elapsed, len(hits), len(seed_variant_pairs) * len(sites))

    groups = correlate(hits, similarity_threshold=args.similarity_threshold, require_signals=args.require_signal)
    log.info("Correlation: %d candidate link(s) flagged for review", len(groups))

    json_path, csv_path = write_reports(args.output, hits, groups, seeds, variant_map)
    log.info("Reports written: %s, %s", json_path, csv_path)

    # scan finished cleanly — the partial snapshot is superseded by the final report
    Path(live.partial_json_path).unlink(missing_ok=True)

    if not hits:
        log.warning("No accounts found. Check network access or widen --max-variants.")
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
