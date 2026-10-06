<p align="center">
  <img src="logo.svg" alt="userhunter logo" width="480"/>
</p>

<h1 align="center">USERHUNTER</h1>
<p align="center"><i>OPSEC-aware username variant generator, multi-site account checker, and cross-account correlation engine for OSINT investigations.</i></p>

---

## What it does

Give it a list of seed usernames. It will:

1. **Generate 100+ OPSEC-style variants per seed** — the same tricks suspects use to make a handle harder to find: leetspeak (`tian` → `t1AN`, `7!an`), delimiter wrapping (`_tian_`, `ti.an`), case mangling (`TiAn`, `tIaN`), common prefix/suffix patterns (`the_real_tian`, `tian_og`, `tian2026`), vowel-dropping, reversal, and doubled-letter tricks — then composes these layers together for broader coverage.
2. **Check every seed + variant against ~45 known platforms** (GitHub, Reddit, Instagram, TikTok, Twitch, Steam, Telegram, Mastodon, and more) concurrently, with per-site true/false-positive logic — including a filter for Cloudflare/bot-challenge interstitials that would otherwise masquerade as false "found" hits.
3. **Pull a content snippet off every hit** (page title + meta description/bio) and **correlate accounts** across different seeds and sites using both username-string similarity and shared bio/title language — surfacing candidate links between accounts for you to review and confirm manually, last, not first.
4. **Optionally merge in [Sherlock](https://github.com/sherlock-project/sherlock)** results if it's installed locally, for broader site coverage beyond the built-in list.
5. **Tune accuracy to taste** — retry flaky checks, filter out soft-404s, tighten correlation to require multiple signals, or scope which sites get queried at all.

Output is a JSON report (full detail, including correlation groups) and a flat CSV (for quick triage in a spreadsheet).

```
$ python3 userhunter.py -i seeds.txt -o case001

                                 .-------.
                                |  o   o |
                                |   o    |
                                |  o   o |
                                 '-------'

   _   _ ____  _____ ____  _   _ _   _ _   _ _____ _____ ____
  | | | / ___|| ____|  _ \| | | | | | | \ | |_   _| ____|  _ \
  | | | \___ \|  _| | |_) | |_| | | | |  \| | | | |  _| | |_) |
  | |_| |___) | |___|  _ <|  _  | |_| | |\  | | | | |___|  _ <
   \___/|____/|_____|_| \_\_| |_|\___/|_| \_| |_| |_____|_| \_\

          variant-storm your targets. correlate the leads.

09:19:01 [INFO] Loaded 1 seed username(s): torvalds
09:19:01 [INFO] Seed 'torvalds': 150 variants generated
09:19:01 [INFO] Dispatching 6750 checks across 45 sites (30 threads)...
09:19:03 [INFO] [FOUND] GitHub         torvalds   -> https://github.com/torvalds
09:19:04 [INFO] Scan complete in 3.0s — 1 account(s) found
09:19:04 [INFO] Correlation: 0 candidate link(s) flagged for review
09:19:04 [INFO] Reports written: case001.json, case001.csv
```

The banner above prints on every run — there's no flag to suppress it.

**Results are saved as they're found, not just at the end.** Every hit is written immediately to `<output>.csv` and a `<output>.partial.json` snapshot — so a scan that gets interrupted, killed, or crashes partway through still leaves everything found up to that point safely on disk. On a clean finish, the partial file is replaced by the final `<output>.json` (which adds correlation on top).

## Install

```bash
pip install requests beautifulsoup4 --break-system-packages
```

Python 3.8+. No API keys required. `beautifulsoup4` is optional — without it, hits are still found, just without the bio/title snippet that feeds correlation.

## Usage

```bash
python3 userhunter.py -i seeds.txt -o case001
```

`seeds.txt` — one seed username per line. Blank lines and lines starting with `#` are ignored.

**Core**

| Flag | Default | Description |
|---|---|---|
| `-i, --input` | *required* | Seed username list (text file) |
| `-o, --output` | `userhunter_report` | Output file prefix (`<prefix>.json`, `<prefix>.csv`) |
| `--max-variants` | `150` | Max variants generated per seed |
| `--threads` | `30` | Concurrent HTTP workers |
| `--timeout` | `8` | Per-request timeout (seconds) |
| `-v, --verbose` | off | Verbose logging + periodic progress updates |

**Accuracy & reliability** — reduce false negatives/positives

| Flag | Default | Description |
|---|---|---|
| `--retries N` | `0` | Retry a check N times on timeout/connection failure before giving up. A single dropped connection no longer means a permanent miss. |
| `--min-title-length N` | `0` (off) | Discard a hit if its extracted page title is shorter than N characters — filters soft-404s (a page that returns 200 with no real profile content behind it). Only takes effect when profile fetching is on. |
| `--similarity-threshold` | `0.82` | Min ratio (0–1) for flagging username correlation |
| `--require-signal {1,2}` | `1` | `1` flags a correlation if either signal (username similarity *or* bio/title overlap) fires. `2` requires both — fewer but stronger leads. |

**Site control & coverage**

| Flag | Default | Description |
|---|---|---|
| `--use-sherlock` | off | Also run Sherlock (if installed) for extra site coverage, one seed at a time |
| `--exclude-sites a,b,c` | none | Comma-separated site names to skip (e.g. `Kik,VK,Ask.fm`) |
| `--sites-file FILE` | none | JSON file of additional/override site definitions — see format below |
| `--no-case-variants` | off | Skip case-mangled variants (`TiAn`, `TIAN`...) — frees variant budget for leet/delimiter/affix combos instead, useful since many platforms are case-insensitive on lookup anyway |
| `--no-profile-fetch` | off | Skip fetching title/bio snippets (faster, but weakens correlation and disables `--min-title-length`) |

### `--sites-file` format

Same shape as the built-in list — add new platforms or override an existing entry:

```json
{
  "MySite": {"url": "https://mysite.example/{}", "mode": "status_200"},
  "AnotherSite": {"url": "https://another.example/u/{}", "mode": "status_200_not_text", "error_text": "User not found"}
}
```

`mode` is either `status_200` (any HTTP 200 counts as a hit) or `status_200_not_text` (HTTP 200 *and* `error_text` absent from the page — use this whenever the site returns 200 for both real and missing profiles, which is common).

### Examples

```bash
# Wider net: more variants, more threads
python3 userhunter.py -i seeds.txt -o case001 --max-variants 250 --threads 40 -v

# Higher-confidence run: retry flaky checks, filter soft-404s, require both correlation signals
python3 userhunter.py -i seeds.txt -o case001 --retries 2 --min-title-length 5 --require-signal 2

# Merge in Sherlock, skip a couple of noisy/irrelevant sites
python3 userhunter.py -i seeds.txt -o case001 --use-sherlock --exclude-sites "Kik,VK"

# Fast pass, no content fetch
python3 userhunter.py -i seeds.txt -o case001 --no-profile-fetch
```

## How correlation works

Every page userhunter finds is checked against every *other* found page using two independent signals:

- **Username similarity** — edit-distance ratio between normalized handles (catches a suspect reusing a near-identical handle across platforms, e.g. `t1AN_hq` on one site and `_t1an_hq` on another).
- **Shared bio/title text** — overlapping meaningful words pulled from each page's title/meta description (catches the same person using consistent self-description across accounts, even with a completely different handle).

Pairs that trip either signal are grouped into a scored `correlation_groups` section in the JSON report — **leads for you to verify, never a conclusion on their own.**

## Site coverage

~45 built-in platforms including GitHub, GitLab, Reddit, X/Twitter, Instagram, TikTok, YouTube, Twitch, Steam, Telegram, Mastodon, Keybase, HackerOne, Spotify, Roblox, Chess.com, VK, and more (full list in `SITES` in the script). Pass `--use-sherlock` for Sherlock's much larger (400+) site list if it's installed on your machine.

## Notes for investigators

- Hits are **leads, not confirmations** — a matching handle or bio snippet is a starting point for manual verification, not proof of identity.
- Respect target platforms' rate limits and terms of service, and your engagement's scope/authorization, when tuning `--threads` and variant counts.
- The built-in detection logic includes a generic bot-challenge filter (Cloudflare interstitials, etc.) to reduce false positives, but spot-check a sample of "found" hits manually before relying on a large batch.

## Acceptable use

This tool is built for authorized OSINT, DFIR, and investigative work — penetration testing engagements, fraud/abuse investigations, missing-persons and threat-intel research, and similar lawful use cases. It queries only publicly available account-existence data; it does not access private data, bypass authentication, or exploit any platform. You're responsible for using it in compliance with the terms of service of any platform you query and the laws that apply to you. The author assumes no liability for misuse.

## License

MIT — see [LICENSE](LICENSE). Free to use, modify, and distribute, including commercially; just keep the copyright notice.

---
<p align="center"><sub>Built for authorized OSINT, DFIR, and investigative use.</sub></p>
