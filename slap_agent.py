#!/usr/bin/env python3
"""
MVP-3: SLAP Agent - HTML Snapshot, Network Traffic & DOM Diff Analyzer
Diagnostic scout to assess crawlability before coding.

This script captures:
1. TRUE RAW HTML from server (response.text(), not DOM)
2. Network traffic (XHR/Fetch/WebSocket) to detect API patterns
3. Status codes for Access Protection signals (401/403/429)
4. GraphQL usage via URL and POST body inspection
5. Time-series DOM snapshots (t0/t1/t2) to detect hydration/scroll patterns
6. Virtualization detection via scroll height vs node growth

Single-session efficiency: Everything captured in ONE page.goto() call.
"""

import sys
import json
from pathlib import Path
from datetime import datetime
from playwright.sync_api import sync_playwright, Response
from bs4 import BeautifulSoup


# Fix Windows console encoding for emoji support
import sys
import locale
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass  # Ignore if reconfigure not available


def create_run_directory(run_id: str) -> tuple[Path, Path]:
    """
    Create directory structure for this run.
    
    Returns:
        (raw_dir, result_dir) paths
    """
    base_dir = Path("runs") / run_id
    raw_dir = base_dir / "raw"
    result_dir = base_dir / "result"
    
    raw_dir.mkdir(parents=True, exist_ok=True)
    result_dir.mkdir(parents=True, exist_ok=True)
    
    return raw_dir, result_dir


def is_graphql_request(response: Response) -> bool:
    """
    Detect GraphQL requests via URL pattern and POST body inspection.
    
    Critical: URL-only detection misses ~50% of GraphQL usage.
    We must peek at POST body for "query" or "mutation" keywords.
    """
    url = response.url.lower()
    
    # Check URL patterns
    if 'graphql' in url:
        return True
    
    # Check Content-Type
    content_type = response.headers.get('content-type', '').lower()
    if 'application/graphql' in content_type:
        return True
    
    # Check POST body (first 200 chars) for query/mutation
    request = response.request
    if request.method == 'POST':
        try:
            post_data = request.post_data
            if post_data:
                # Check first 200 chars for GraphQL keywords
                preview = post_data[:200].lower()
                if '"query"' in preview or '"mutation"' in preview or "'query'" in preview or "'mutation'" in preview:
                    return True
        except Exception:
            # If we can't access post_data, skip it
            pass
    
    return False


def extract_html_stats(html_content: str) -> dict:
    """
    Parse HTML and extract statistics using BeautifulSoup4.
    
    Args:
        html_content: Raw HTML string from server response
        
    Returns:
        Dictionary containing HTML statistics
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Total size in bytes
    total_size = len(html_content.encode('utf-8'))
    
    # Tag count (all HTML tags)
    tag_count = len(soup.find_all())
    
    # Link count (strong SSR indicator)
    link_count = len(soup.find_all('a'))
    
    # Text content length (stripped of all tags)
    text_content = soup.get_text(separator=' ', strip=True)
    text_content_length = len(text_content)
    
    # Text ratio (how much actual content vs markup)
    text_ratio = text_content_length / total_size if total_size > 0 else 0.0
    
    # SPA framework indicators (id="root", "app", "__next")
    has_root_div = bool(
        soup.find(id='root') or 
        soup.find(id='app') or 
        soup.find(id='__next')
    )
    
    # Page title
    title_tag = soup.find('title')
    title = title_tag.get_text(strip=True) if title_tag else ""
    
    return {
        "total_size": total_size,
        "tag_count": tag_count,
        "link_count": link_count,
        "text_content_length": text_content_length,
        "text_ratio": round(text_ratio, 4),
        "has_root_div": has_root_div,
        "title": title
    }


def analyze_network_logs(network_logs: list) -> dict:
    """
    Analyze captured network logs to generate summary statistics.
    
    Critical: Focus on "smoking gun" signals - 401/403/429 status codes
    that indicate Access Protection or Rate Limiting.
    """
    total_captured = len(network_logs)
    xhr_fetch_count = sum(1 for log in network_logs if log['type'] in ['xhr', 'fetch'])
    
    # Track blocking signals (critical for AP detection)
    blocking_signals = {"401": 0, "403": 0, "429": 0}
    for log in network_logs:
        status = str(log['status'])
        if status in blocking_signals:
            blocking_signals[status] += 1
    
    # Classify data types
    data_types = {"json": 0, "html": 0, "graphql": 0}
    for log in network_logs:
        if log.get('is_graphql'):
            data_types['graphql'] += 1
        elif 'json' in log.get('content_type', '').lower():
            data_types['json'] += 1
        elif 'html' in log.get('content_type', '').lower():
            data_types['html'] += 1
    
    # Extract suspected API endpoints (non-document requests to different origins)
    suspected_apis = []
    seen_urls = set()
    for log in network_logs:
        if log['type'] in ['xhr', 'fetch'] and log['url'] not in seen_urls:
            # Simple heuristic: if it's an API call (JSON or GraphQL)
            if log.get('is_graphql') or 'json' in log.get('content_type', '').lower():
                suspected_apis.append(log['url'])
                seen_urls.add(log['url'])
    
    return {
        "total_captured": total_captured,
        "xhr_fetch_count": xhr_fetch_count,
        "blocking_signals": blocking_signals,
        "data_types": data_types,
        "suspected_apis": suspected_apis[:10]  # Limit to top 10
    }


def extract_dom_metrics_from_html(html_content: str) -> dict:
    """
    Extract DOM metrics from HTML string (for t0 - raw server response).
    
    CRITICAL: Used for t0 baseline to avoid race conditions with fast hydration.
    
    Args:
        html_content: Raw HTML string
        
    Returns:
        Dictionary with node_count, text_length, html (no scroll_height for raw HTML)
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    
    node_count = len(soup.find_all())
    text_content = soup.get_text(separator=' ', strip=True)
    text_length = len(text_content)
    
    return {
        "node_count": node_count,
        "text_length": text_length,
        "scroll_height": 0,  # Not available in raw HTML
        "html": html_content
    }


def extract_dom_metrics_from_page(page) -> dict:
    """
    Extract DOM metrics from live page (for t1/t2 - hydrated/scrolled states).
    
    Args:
        page: Playwright Page object
        
    Returns:
        Dictionary with node_count, text_length, scroll_height, html
    """
    html_content = page.content()
    soup = BeautifulSoup(html_content, 'html.parser')
    
    node_count = len(soup.find_all())
    text_content = soup.get_text(separator=' ', strip=True)
    text_length = len(text_content)
    
    # Get scroll height from document.documentElement (more reliable than body)
    try:
        scroll_height = page.evaluate('document.documentElement.scrollHeight')
    except Exception:
        scroll_height = 0
    
    return {
        "node_count": node_count,
        "text_length": text_length,
        "scroll_height": scroll_height,
        "html": html_content
    }


def perform_incremental_scroll(page):
    """
    Perform incremental scroll to trigger IntersectionObserver / lazy loading.
    
    CRITICAL: Don't jump to bottom - scroll in steps to wake up observers.
    Includes sanity check for nested scroll containers.
    """
    print("  ↓ Scrolling incrementally (4 steps)...")
    
    # Scroll down in 4 increments
    for i in range(4):
        page.mouse.wheel(0, 1000)  # Scroll down 1000px
        page.wait_for_timeout(500)  # Wait for lazy-load
    
    # Sanity check: did scroll actually work?
    try:
        scroll_y = page.evaluate('window.scrollY')
        if scroll_y == 0:
            print("  ⚠️  Warning: Body scroll ineffective (window.scrollY=0). Page may use nested scroll container.")
    except Exception:
        pass


def calculate_dom_diffs(t0: dict, t1: dict, t2: dict) -> dict:
    """
    Calculate growth ratios and detect patterns.
    
    Critical detection logic:
    - Hydration: (t1-t0)/t0 > 50% → S-CSR
    - Infinite Scroll: (t2-t1)/t1 > 20% → L-INTERACTIVE
    - Virtualization: height_growth > 50% AND node_growth < 5% → S-VIRTUALIZED
    
    Args:
        t0: Raw server DOM metrics
        t1: Hydrated DOM metrics
        t2: Scrolled DOM metrics
        
    Returns:
        Dictionary with diffs and classification
    """
    # Hydration growth (t0 -> t1)
    hydration_growth = (
        (t1['node_count'] - t0['node_count']) / t0['node_count'] 
        if t0['node_count'] > 0 else 0
    )
    
    # Scroll growth (t1 -> t2)
    scroll_growth = (
        (t2['node_count'] - t1['node_count']) / t1['node_count'] 
        if t1['node_count'] > 0 else 0
    )
    
    # Scroll height growth (t1 -> t2)
    # Use t1 scroll_height as baseline (t0 doesn't have it)
    scroll_height_growth = (
        (t2['scroll_height'] - t1['scroll_height']) / t1['scroll_height']
        if t1['scroll_height'] > 0 else 0
    )
    
    # Virtualization detection:
    # High scroll height growth (>50%) but low node growth (<5%)
    is_virtualized_suspected = (
        scroll_height_growth > 0.5 and scroll_growth < 0.05
    )
    
    interpretation = ""
    if is_virtualized_suspected:
        interpretation = f"Height grew {scroll_height_growth:.0%} but nodes only {scroll_growth:.0%} -> Virtualized rendering"
    elif scroll_growth > 0.2:
        interpretation = f"Nodes grew {scroll_growth:.0%} after scroll -> Infinite scroll"
    elif hydration_growth > 0.5:
        interpretation = f"Nodes grew {hydration_growth:.0%} during hydration -> Heavy CSR"
    else:
        interpretation = "Minimal DOM changes detected"
    
    return {
        "hydration_growth": round(hydration_growth, 4),
        "scroll_growth": round(scroll_growth, 4),
        "scroll_height_growth": round(scroll_height_growth, 4),
        "is_virtualized_suspected": is_virtualized_suspected,
        "interpretation": interpretation
    }


def analyze_ap_signals(
    url: str,
    status_code: int,
    html_stats: dict,
    network_summary: dict,
    raw_html: str,
    dom_diffs: dict
) -> list:
    """
    Synthesize all evidence to detect Access Protection signals.
    
    CRITICAL: Be strict with convictions.
    - Confirmed: Hard evidence (HTTP codes, explicit keywords)
    - Suspected: Circumstantial (empty pages + no hydration)
    
    Args:
        url: Target URL
        status_code: HTTP status code
        html_stats: HTML statistics from MVP-1
        network_summary: Network summary from MVP-2
        raw_html: Raw HTML content
        dom_diffs: DOM diff results from MVP-3
        
    Returns:
        List of AP signal dicts with label, state, confidence, evidence
    """
    signals = []
    
    # 1. AP-AUTH (401/403) - CONFIRMED
    auth_401 = network_summary.get('blocking_signals', {}).get('401', 0)
    auth_403 = network_summary.get('blocking_signals', {}).get('403', 0)
    
    if auth_401 > 0 or auth_403 > 0:
        evidence = []
        if auth_401 > 0:
            evidence.append({"source": "network", "key": "status_401", "value": auth_401})
        if auth_403 > 0:
            evidence.append({"source": "network", "key": "status_403", "value": auth_403})
        
        signals.append({
            "label": "AP-AUTH",
            "state": "confirmed",
            "confidence": 1.0,
            "evidence": evidence
        })
    
    # 2. AP-RATE (429) - CONFIRMED
    rate_429 = network_summary.get('blocking_signals', {}).get('429', 0)
    
    if rate_429 > 0:
        signals.append({
            "label": "AP-RATE",
            "state": "confirmed",
            "confidence": 1.0,
            "evidence": [
                {"source": "network", "key": "status_429", "value": rate_429}
            ]
        })
    
    # 3. AP-LOGIN (URL/title keywords) - CONFIRMED
    # CRITICAL: Removed 'auth' (too generic - matches "author", "authority")
    # Only keep explicit authentication terms
    login_keywords = ['login', 'signin', 'sign-in', 'sign_in', 'authenticate', 'authentication']
    url_lower = url.lower()
    title = html_stats.get('title', '')
    title_lower = title.lower()
    
    url_match = any(kw in url_lower for kw in login_keywords)
    title_match = any(kw in title_lower for kw in login_keywords)
    
    if url_match or title_match:
        # URL match = higher confidence (1.0) than title match (0.8)
        confidence = 1.0 if url_match else 0.8
        
        evidence = []
        if url_match:
            evidence.append({"source": "url", "key": "url", "value": url})
        if title_match:
            evidence.append({"source": "html", "key": "title", "value": title})
        
        signals.append({
            "label": "AP-LOGIN",
            "state": "confirmed",
            "confidence": confidence,
            "evidence": evidence
        })
    
    # 4. AP-BOT-SCORE (empty shell + no XHR + no hydration) - SUSPECTED
    # CRITICAL: Check hydration_growth to avoid false positives on Next.js apps
    text_ratio = html_stats.get('text_ratio', 0)
    xhr_fetch_count = network_summary.get('xhr_fetch_count', 0)
    hydration_growth = dom_diffs.get('diffs', {}).get('hydration_growth', 0)
    
    if (status_code == 200 and
        text_ratio < 0.02 and
        xhr_fetch_count == 0 and
        hydration_growth < 0.1):
        
        signals.append({
            "label": "AP-BOT-SCORE",
            "state": "suspected",
            "confidence": 0.8,
            "evidence": [
                {"source": "http", "key": "status_code", "value": status_code},
                {"source": "html", "key": "text_ratio", "value": round(text_ratio, 4)},
                {"source": "network", "key": "xhr_fetch_count", "value": xhr_fetch_count},
                {"source": "dom", "key": "hydration_growth", "value": round(hydration_growth, 4)}
            ]
        })
    
    # 5. AP-CAPTCHA (HTML text keywords) - CONFIRMED
    captcha_keywords = [
        'recaptcha', 'hcaptcha', 'turnstile',
        'pardon our interruption', 'verify you are human',
        'verify you\'re human', 'complete the captcha',
        'security check', 'cloudflare'
    ]
    
    html_text_lower = raw_html.lower()
    found_captcha = [kw for kw in captcha_keywords if kw in html_text_lower]
    
    if found_captcha:
        signals.append({
            "label": "AP-CAPTCHA",
            "state": "confirmed",
            "confidence": 0.95,
            "evidence": [
                {"source": "html", "key": "captcha_keywords", "value": found_captcha[:3]}  # Limit to first 3
            ]
        })
    
    return signals


def calculate_slap_score(
    html_stats: dict,
    network_summary: dict,
    dom_diff_result: dict,
    ap_signals: list
) -> tuple[dict, dict]:
    """
    Synthesize all signals into SLAP labels and difficulty score.
    
    CRITICAL: S-axis uses decoupled architecture (primary) + features (modifiers)
    to preserve both "what it is" (CSR/SSR) and "what it does" (VIRTUALIZED).
    
    Scoring Formula (Golden Rule): AP is 50% of difficulty
    Total = (AP * 0.5) + (S * 0.3) + (L * 0.2)
    
    Args:
        html_stats: HTML statistics from MVP-1
        network_summary: Network summary from MVP-2
        dom_diff_result: DOM diff results from MVP-3
        ap_signals: AP signals from MVP-4
        
    Returns:
        (labels_dict, score_dict)
    """
    # Extract key metrics
    text_ratio = html_stats.get('text_ratio', 0)
    has_root_div = html_stats.get('has_root_div', False)
    
    hydration_growth = dom_diff_result.get('diffs', {}).get('hydration_growth', 0)
    scroll_growth = dom_diff_result.get('diffs', {}).get('scroll_growth', 0)
    is_virtualized = dom_diff_result.get('classification', {}).get('is_virtualized_suspected', False)
    
    xhr_fetch_count = network_summary.get('xhr_fetch_count', 0)
    graphql_count = network_summary.get('data_types', {}).get('graphql', 0)
    json_count = network_summary.get('data_types', {}).get('json', 0)
    total_captured = network_summary.get('total_captured', 0)
    
    # Calculate json_ratio
    json_ratio = json_count / total_captured if total_captured > 0 else 0
    
    # === S-AXIS CLASSIFICATION (DECOUPLED) ===
    # Step 1: Determine Primary Architecture (What it IS)
    s_primary = None
    s_arch_score = 0
    
    # CRITICAL FIX: Hydration growth is the primary signal for CSR
    # Root div is a secondary indicator (some sites use different IDs)
    if hydration_growth > 0.5:
        # Strong CSR signal: DOM doubled or more during hydration
        s_primary = "S-CSR"
        s_arch_score = 60
    elif hydration_growth > 0.2 or has_root_div:
        # Moderate CSR signal: significant growth OR has SPA root
        s_primary = "S-CSR"
        s_arch_score = 60
    elif text_ratio > 0.05 and hydration_growth < 0.1:
        # SSR signal: good text ratio, minimal hydration
        s_primary = "S-SSR"
        s_arch_score = 20
    else:
        # Fallback: truly static or ambiguous
        s_primary = "S-STATIC"
        s_arch_score = 0
    
    # Step 2: Determine Modifiers (What it DOES)
    s_modifiers = []
    s_modifier_score = 0
    
    if is_virtualized:
        s_modifiers.append("S-VIRTUALIZED")
        s_modifier_score = 90
    
    # Step 3: Calculate Final S-Score
    s_score = max(s_arch_score, s_modifier_score)
    
    # === L-AXIS CLASSIFICATION ===
    l_label = None
    l_score = 0
    
    if graphql_count > 0:
        l_label = "L-GRAPHQL"
        l_score = 80
    elif scroll_growth > 0.1:
        l_label = "L-INTERACTIVE"
        l_score = 50
    elif xhr_fetch_count > 5 and json_ratio > 0.5:
        l_label = "L-API"
        l_score = 30
    else:
        l_label = "L-STATIC"
        l_score = 0
    
    # === AP-AXIS CLASSIFICATION ===
    ap_labels = []
    ap_score = 0
    
    ap_score_map = {
        'AP-CAPTCHA': 100,
        'AP-AUTH': 100,
        'AP-RATE': 80,
        'AP-BOT-SCORE': 60,
        'AP-LOGIN': 40
    }
    
    for signal in ap_signals:
        label = signal.get('label')
        ap_labels.append(label)
        signal_score = ap_score_map.get(label, 0)
        ap_score = max(ap_score, signal_score)  # Take highest AP score
    
    if not ap_labels:
        ap_labels = ["AP-OPEN"]
        ap_score = 0
    
    # === WEIGHTED SCORING ===
    # Golden Rule: AP is 50% of difficulty
    ap_weighted = ap_score * 0.5
    s_weighted = s_score * 0.3
    l_weighted = l_score * 0.2
    
    total_score = int(ap_weighted + s_weighted + l_weighted)
    
    # === TIER ASSIGNMENT ===
    if total_score >= 81:
        tier = "HELL"
    elif total_score >= 51:
        tier = "HARD"
    elif total_score >= 21:
        tier = "MEDIUM"
    else:
        tier = "EASY"
    
    # === IDENTIFY DRIVERS ===
    # Determine which S-label contributed most (highest score wins)
    s_driver_label = None
    if s_score > 0:
        if s_modifier_score > s_arch_score:
            s_driver_label = s_modifiers[0] if s_modifiers else None
        else:
            s_driver_label = s_primary
    
    drivers = []
    scored_items = [
        (ap_score, ap_labels[0] if ap_labels and ap_labels[0] != 'AP-OPEN' else None),
        (s_score, s_driver_label),
        (l_score, l_label if l_score > 0 else None)
    ]
    
    # Sort by score descending
    scored_items.sort(key=lambda x: x[0], reverse=True)
    
    for score, label in scored_items:
        if label and score > 0:
            drivers.append(label)
    
    # === PREPARE OUTPUTS ===
    labels = {
        "structure": {
            "primary": s_primary,
            "modifiers": s_modifiers
        },
        "loading": l_label,
        "access_protection": ap_labels
    }
    
    score = {
        "total_score": total_score,
        "tier": tier,
        "breakdown": {
            "AP": int(ap_weighted),
            "S": int(s_weighted),
            "L": int(l_weighted)
        },
        "drivers": drivers
    }
    
    return labels, score


# ==============================================================================
# MVP-6: HUMAN-READABLE REPORT GENERATOR
# ==============================================================================

# Traffic Light Color Themes
TIER_THEMES = {
    'EASY': {
        'bg': 'bg-green-50',
        'border': 'border-green-200',
        'badge': 'bg-green-500',
        'text': 'text-green-900',
        'icon': '✅'
    },
    'MEDIUM': {
        'bg': 'bg-yellow-50',
        'border': 'border-yellow-300',
        'badge': 'bg-yellow-500',
        'text': 'text-yellow-900',
        'icon': '⚠️'
    },
    'HARD': {
        'bg': 'bg-orange-50',
        'border': 'border-orange-300',
        'badge': 'bg-orange-600',
        'text': 'text-orange-900',
        'icon': '🔥'
    },
    'HELL': {
        'bg': 'bg-red-50',
        'border': 'border-red-400',
        'badge': 'bg-red-700',
        'text': 'text-red-900',
        'icon': '💀'
    }
}

STRATEGY_STYLES = {
    'abort': {'bg': 'bg-red-100', 'border': 'border-red-500', 'text': 'text-red-900', 'icon': '🚫'},
    'warn': {'bg': 'bg-orange-100', 'border': 'border-orange-500', 'text': 'text-orange-900', 'icon': '⚠️'},
    'caution': {'bg': 'bg-yellow-100', 'border': 'border-yellow-500', 'text': 'text-yellow-900', 'icon': '⚡'},
    'info': {'bg': 'bg-blue-100', 'border': 'border-blue-500', 'text': 'text-blue-900', 'icon': 'ℹ️'},
    'success': {'bg': 'bg-green-100', 'border': 'border-green-500', 'text': 'text-green-900', 'icon': '✅'}
}


def get_strategy_text(labels: dict, drivers: list) -> dict:
    """
    Generate actionable strategy based on detected patterns.
    
    CRITICAL: Deterministic priority-based rules.
    Returns the FIRST matching rule (highest priority wins).
    
    Args:
        labels: SLAP labels from MVP-5
        drivers: Top drivers from MVP-5
        
    Returns:
        dict with 'level' and 'message'
    """
    ap_labels = labels.get('access_protection', [])
    s_primary = labels.get('structure', {}).get('primary')
    s_modifiers = labels.get('structure', {}).get('modifiers', [])
    
    # Rule 1: CAPTCHA/AUTH (ABORT - highest priority)
    if 'AP-CAPTCHA' in ap_labels or 'AP-AUTH' in ap_labels:
        blocker_type = 'CAPTCHA Solver' if 'AP-CAPTCHA' in ap_labels else 'valid Credentials'
        return {
            'level': 'abort',
            'message': f'ABORT: Hard blocking detected. Requires commercial {blocker_type}. Standard automation will fail.'
        }
    
    # Rule 2: VIRTUALIZED (WARN - critical technical detail)
    if 'S-VIRTUALIZED' in s_modifiers:
        return {
            'level': 'warn',
            'message': 'WARN: DOM is virtualized (infinite scroll/fake rendering). Visual scraping will fail. You MUST reverse-engineer the internal JSON API.'
        }
    
    # Rule 3: RATE LIMIT / BOT-SCORE (CAUTION)
    if 'AP-RATE' in ap_labels or 'AP-BOT-SCORE' in ap_labels:
        issue = 'Throttling (429)' if 'AP-RATE' in ap_labels else 'Soft-blocking'
        return {
            'level': 'caution',
            'message': f'CAUTION: {issue} detected. Use exponential backoff, request rotation, and session management.'
        }
    
    # Rule 4: CSR (INFO - standard complexity)
    if s_primary == 'S-CSR':
        return {
            'level': 'info',
            'message': 'INFO: Client-Side Rendering detected. Headless browser required. Wait for hydration (network idle) before extracting data.'
        }
    
    # Rule 5: LOGIN (INFO)
    if 'AP-LOGIN' in ap_labels:
        return {
            'level': 'info',
            'message': 'INFO: Login page detected. You can POST credentials or use authenticated sessions to access protected content.'
        }
    
    return {
        'level': 'success',
        'message': 'SUCCESS: Standard HTTP requests with HTML parsing should work. No major obstacles detected.'
    }


def generate_ai_insight(
    url: str,
    tier: str,
    score: int,
    drivers: list,
    labels: dict,
    network_summary: dict
) -> str:
    """
    Generate AI-powered executive summary and Playwright code using GPT-4o-mini.
    
    Args:
        url: Target URL
        tier: Difficulty tier (EASY/MEDIUM/HARD/HELL)
        score: Total difficulty score (0-100)
        drivers: Top difficulty drivers
        labels: SLAP labels (structure, loading, protection)
        network_summary: Network statistics
        
    Returns:
        HTML string with AI insights, or empty string if API key not available
    """
    import os
    from pathlib import Path
    
    # Try to load from .env file as fallback
    env_file = Path(__file__).parent / '.env'
    if env_file.exists() and not os.getenv('OPENAI_API_KEY'):
        for line in env_file.read_text(encoding='utf-8').splitlines():
            if line.startswith('OPENAI_API_KEY='):
                os.environ['OPENAI_API_KEY'] = line.split('=', 1)[1].strip()
                break
    
    # Check for API key
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        return ""  # Fail gracefully if no key
    
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        
        # Build context for AI
        s_primary = labels['structure']['primary']
        s_modifiers = labels['structure']['modifiers']
        l_label = labels['loading']
        ap_labels = labels['access_protection']
        
        xhr_count = network_summary.get('xhr_fetch_count', 0)
        graphql_count = network_summary.get('data_types', {}).get('graphql', 0)
        
        # Build obstacle-specific hints for the AI
        hints = []
        if s_primary == 'S-CSR':
            hints.append("Site uses Client-Side Rendering. Code must use headless browser and wait for hydration.")
        if 'S-VIRTUALIZED' in s_modifiers:
            hints.append("DOM is virtualized. Visual scraping will fail. Must reverse-engineer the JSON API endpoints.")
        if graphql_count > 0:
            hints.append(f"Site uses GraphQL ({graphql_count} requests detected). Show how to intercept network responses.")
        if 'AP-RATE' in ap_labels:
            hints.append("Rate limiting detected (429 errors). Add random delays and exponential backoff.")
        if 'AP-CAPTCHA' in ap_labels or 'AP-AUTH' in ap_labels:
            hints.append("Hard blocking detected. Code should include error handling for CAPTCHA/Auth challenges.")
        if l_label == 'L-API' and xhr_count > 0:
            hints.append(f"Site makes {xhr_count} XHR/Fetch requests. Consider intercepting API calls instead of parsing HTML.")
        
        # Construct prompt
        prompt = f"""You are a Senior Web Scraping Engineer analyzing site: {url}

SLAP Analysis Results:
- Difficulty Tier: {tier} ({score}/100)
- Structure: {s_primary} {f"+ {', '.join(s_modifiers)}" if s_modifiers else ""}
- Loading Pattern: {l_label}
- Access Protection: {', '.join(ap_labels)}
- Top Challenges: {', '.join(drivers) if drivers else 'None'}
- Network: {xhr_count} XHR/Fetch, {graphql_count} GraphQL

Technical Constraints:
{chr(10).join(f'- {hint}' for hint in hints) if hints else '- No major obstacles detected'}

Task:
1. Write a brief Executive Summary (2-3 sentences) explaining the scraping approach
2. Generate a production-ready Python Playwright code snippet that:
   - Handles the specific obstacles detected
   - Includes proper wait strategies if CSR is detected
   - Shows API interception if GraphQL/API patterns found
   - Adds rate limiting protection if needed
   - Is copy-paste ready with minimal modifications

Format your response as HTML:
<div class="ai-summary">
<h4>Executive Summary</h4>
<p>Your summary here...</p>
</div>

<div class="ai-code">
<h4>Ready-to-Use Playwright Code</h4>
<pre><code class="language-python">
# Your Python code here
</code></pre>
</div>

Keep the code concise but functional. Focus on the detected obstacles."""

        # Call GPT-4o-mini
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are an expert web scraping engineer specializing in Playwright automation. Provide concise, actionable code snippets."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=1500
        )
        
        ai_content = response.choices[0].message.content
        return ai_content
        
    except Exception as e:
        # Fail gracefully if AI generation fails
        print(f"⚠️  AI insight generation failed: {e}")
        return ""


def generate_human_report(
    url: str,
    run_id: str,
    result_dir: Path,
    html_stats: dict,
    network_summary: dict,
    dom_diff_result: dict,
    ap_signals: list,
    labels: dict,
    score: dict
) -> Path:
    """
    Generate self-contained HTML report with traffic light themes.
    
    Args:
        url: Target URL
        run_id: Run timestamp ID
        result_dir: Path to result directory
        html_stats: HTML statistics from MVP-1
        network_summary: Network summary from MVP-2
        dom_diff_result: DOM diff results from MVP-3
        ap_signals: AP signals from MVP-4
        labels: SLAP labels from MVP-5
        score: Score breakdown from MVP-5
        
    Returns:
        Path to generated index.html
    """
    from datetime import datetime
    
    # Create report directory
    report_dir = result_dir.parent / "report"
    report_dir.mkdir(exist_ok=True)
    
    # Get strategy and themes
    strategy = get_strategy_text(labels, score['drivers'])
    tier = score['tier']
    theme = TIER_THEMES[tier]
    strategy_style = STRATEGY_STYLES[strategy['level']]
    
    # Extract data for display
    s_primary = labels['structure']['primary']
    s_modifiers = labels['structure']['modifiers']
    l_label = labels['loading']
    ap_labels = labels['access_protection']
    
    total_score = score['total_score']
    ap_breakdown = score['breakdown']['AP']
    s_breakdown = score['breakdown']['S']
    l_breakdown = score['breakdown']['L']
    drivers = score['drivers']
    
    # Calculate bar widths (max 100)
    ap_width = int((ap_breakdown / 50) * 100) if ap_breakdown > 0 else 0  # AP max is 50
    s_width = int((s_breakdown / 30) * 100) if s_breakdown > 0 else 0     # S max is 30
    l_width = int((l_breakdown / 20) * 100) if l_breakdown > 0 else 0     # L max is 20
    
    # Build modifier display
    modifiers_html = ""
    if s_modifiers:
        modifiers_html = f"<span class='text-orange-600 font-semibold'>+ {', '.join(s_modifiers)}</span>"
    
    # Build drivers list
    drivers_html = ""
    for i, driver in enumerate(drivers[:3], 1):
        drivers_html += f"<li class='text-gray-700'>{i}. <span class='font-semibold'>{driver}</span></li>"
    
    # Build AP signals list
    ap_signals_html = ""
    for signal in ap_signals:
        state_icon = "🔴" if signal['state'] == 'confirmed' else "🟠"
        ap_signals_html += f"""
        <div class='mb-2'>
            <span class='text-sm font-semibold'>{state_icon} {signal['label']}</span>
            <span class='text-xs text-gray-600'>({signal['state']}, {signal['confidence']})</span>
        </div>
        """
    
    # Generate AI insights (MVP-7)
    print("🤖 Generating AI insights...")
    ai_content = generate_ai_insight(
        url=url,
        tier=tier,
        score=total_score,
        drivers=drivers,
        labels=labels,
        network_summary=network_summary
    )
    
    # Build AI section HTML
    if ai_content:
        ai_section_html = f"""
        <section class="mb-8">
            <div class="bg-gradient-to-r from-purple-50 to-indigo-50 rounded-lg shadow-lg p-6 border-2 border-purple-200">
                <h2 class="text-2xl font-bold mb-4 text-purple-900">🤖 AI Blueprint</h2>
                <div class="prose prose-purple max-w-none">
                    {ai_content}
                </div>
            </div>
        </section>
        """
        print("✅ AI insights generated")
    else:
        ai_section_html = ""  # No AI key or generation failed
        print("⚠️  AI insights skipped (no API key)")
    
    # Generate HTML
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SLAP Report - {url}</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="{theme['bg']} min-h-screen p-8">
    <div class="max-w-6xl mx-auto">
        <!-- Header -->
        <header class="mb-8">
            <h1 class="text-4xl font-bold {theme['text']} mb-2">SLAP Crawlability Report</h1>
            <p class="text-xl text-gray-700 mb-1">{url}</p>
            <p class="text-sm text-gray-500">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | Run ID: {run_id}</p>
            
            <!-- Tier Badge -->
            <div class="mt-4">
                <span class="{theme['badge']} text-white px-6 py-3 rounded-full text-2xl font-bold shadow-lg">
                    {theme['icon']} {tier} TIER - {total_score}/100
                </span>
            </div>
            
            <!-- Strategy Alert Box -->
            <div class="mt-6 p-6 border-l-4 {strategy_style['bg']} {strategy_style['border']} {strategy_style['text']} rounded-lg shadow-md">
                <h2 class="text-2xl font-bold mb-3">{strategy_style['icon']} RECOMMENDED STRATEGY</h2>
                <p class="text-lg font-medium leading-relaxed">{strategy['message']}</p>
            </div>
        </header>
        
        <!-- AI Blueprint Section (MVP-7) -->
        {ai_section_html}
        
        <!-- Score Card -->
        <section class="bg-white rounded-lg shadow-lg p-6 mb-8">
            <h2 class="text-2xl font-bold mb-6 text-gray-800">Difficulty Breakdown</h2>
            
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <!-- Breakdown Bars -->
                <div>
                    <h3 class="font-semibold text-gray-700 mb-4">Score Components:</h3>
                    
                    <div class="mb-4">
                        <div class="flex justify-between mb-1">
                            <span class="text-sm font-medium text-red-700">Access Protection</span>
                            <span class="text-sm font-bold text-red-700">{ap_breakdown}/50</span>
                        </div>
                        <div class="w-full bg-gray-200 rounded-full h-4">
                            <div class="bg-red-500 h-4 rounded-full" style="width: {ap_width}%"></div>
                        </div>
                    </div>
                    
                    <div class="mb-4">
                        <div class="flex justify-between mb-1">
                            <span class="text-sm font-medium text-blue-700">Structure</span>
                            <span class="text-sm font-bold text-blue-700">{s_breakdown}/30</span>
                        </div>
                        <div class="w-full bg-gray-200 rounded-full h-4">
                            <div class="bg-blue-500 h-4 rounded-full" style="width: {s_width}%"></div>
                        </div>
                    </div>
                    
                    <div class="mb-4">
                        <div class="flex justify-between mb-1">
                            <span class="text-sm font-medium text-green-700">Loading</span>
                            <span class="text-sm font-bold text-green-700">{l_breakdown}/20</span>
                        </div>
                        <div class="w-full bg-gray-200 rounded-full h-4">
                            <div class="bg-green-500 h-4 rounded-full" style="width: {l_width}%"></div>
                        </div>
                    </div>
                </div>
                
                <!-- Top Drivers -->
                <div>
                    <h3 class="font-semibold text-gray-700 mb-4">Top Difficulty Drivers:</h3>
                    <ol class="space-y-2">
                        {drivers_html}
                    </ol>
                </div>
            </div>
        </section>
        
        <!-- SLAP Dashboard (3 Columns) -->
        <section class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <!-- Structure -->
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-xl font-bold text-blue-700 mb-4">📐 Structure</h3>
                <div class="mb-3">
                    <span class="text-sm text-gray-600">Primary:</span>
                    <p class="text-lg font-semibold text-gray-800">{s_primary}</p>
                    {modifiers_html}
                </div>
                <div class="text-sm text-gray-600 space-y-1">
                    <p>Text Ratio: <span class="font-medium">{html_stats.get('text_ratio', 0):.3f}</span></p>
                    <p>Hydration: <span class="font-medium">{dom_diff_result.get('diffs', {}).get('hydration_growth', 0):.2%}</span></p>
                    <p>Root Div: <span class="font-medium">{'Yes' if html_stats.get('has_root_div') else 'No'}</span></p>
                </div>
            </div>
            
            <!-- Loading -->
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-xl font-bold text-green-700 mb-4">📡 Loading</h3>
                <div class="mb-3">
                    <span class="text-sm text-gray-600">Pattern:</span>
                    <p class="text-lg font-semibold text-gray-800">{l_label}</p>
                </div>
                <div class="text-sm text-gray-600 space-y-1">
                    <p>XHR/Fetch: <span class="font-medium">{network_summary.get('xhr_fetch_count', 0)}</span></p>
                    <p>GraphQL: <span class="font-medium">{network_summary.get('data_types', {}).get('graphql', 0)}</span></p>
                    <p>Scroll Growth: <span class="font-medium">{dom_diff_result.get('diffs', {}).get('scroll_growth', 0):.2%}</span></p>
                </div>
            </div>
            
            <!-- Access Protection -->
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-xl font-bold text-red-700 mb-4">🛡️ Protection</h3>
                <div class="mb-3">
                    <span class="text-sm text-gray-600">Detected Signals:</span>
                    <div class="mt-2">
                        {ap_signals_html if ap_signals_html else '<p class="text-gray-500 italic">None detected</p>'}
                    </div>
                </div>
            </div>
        </section>
        
        <!-- Evidence Detail -->
        <section class="bg-white rounded-lg shadow p-6">
            <h2 class="text-2xl font-bold mb-4 text-gray-800">📊 Evidence Detail</h2>
            
            <details class="mb-4">
                <summary class="cursor-pointer font-semibold text-gray-700 hover:text-blue-600">Network Statistics</summary>
                <div class="mt-3 pl-4 text-sm text-gray-600">
                    <p>Total Requests Captured: <span class="font-medium">{network_summary.get('total_captured', 0)}</span></p>
                    <p>XHR/Fetch Count: <span class="font-medium">{network_summary.get('xhr_fetch_count', 0)}</span></p>
                    <p>JSON Responses: <span class="font-medium">{network_summary.get('data_types', {}).get('json', 0)}</span></p>
                    <p>GraphQL Detected: <span class="font-medium">{network_summary.get('data_types', {}).get('graphql', 0)}</span></p>
                </div>
            </details>
            
            <details class="mb-4">
                <summary class="cursor-pointer font-semibold text-gray-700 hover:text-blue-600">DOM Timeline</summary>
                <div class="mt-3 pl-4 text-sm text-gray-600">
                    <p>t0 (Server): <span class="font-medium">{dom_diff_result.get('t0_stats', {}).get('node_count', 0)} nodes</span></p>
                    <p>t1 (Hydrated): <span class="font-medium">{dom_diff_result.get('t1_stats', {}).get('node_count', 0)} nodes</span></p>
                    <p>t2 (Scrolled): <span class="font-medium">{dom_diff_result.get('t2_stats', {}).get('node_count', 0)} nodes</span></p>
                    <p>Hydration Growth: <span class="font-medium">{dom_diff_result.get('diffs', {}).get('hydration_growth', 0):.2%}</span></p>
                    <p>Scroll Growth: <span class="font-medium">{dom_diff_result.get('diffs', {}).get('scroll_growth', 0):.2%}</span></p>
                </div>
            </details>
            
            <details>
                <summary class="cursor-pointer font-semibold text-gray-700 hover:text-blue-600">HTML Statistics</summary>
                <div class="mt-3 pl-4 text-sm text-gray-600">
                    <p>Total Size: <span class="font-medium">{html_stats.get('total_size', 0):,} bytes</span></p>
                    <p>Tag Count: <span class="font-medium">{html_stats.get('tag_count', 0)}</span></p>
                    <p>Link Count: <span class="font-medium">{html_stats.get('link_count', 0)}</span></p>
                    <p>Text Ratio: <span class="font-medium">{html_stats.get('text_ratio', 0):.3f}</span></p>
                    <p>Status Code: <span class="font-medium">{html_stats.get('status_code', 0)}</span></p>
                </div>
            </details>
        </section>
        
        <!-- Footer -->
        <footer class="mt-8 text-center text-sm text-gray-500">
            <p>Generated by SLAP Agent v1.0 | All 6 MVPs Complete</p>
        </footer>
    </div>
</body>
</html>'''
    
    # Write file
    report_file = report_dir / "index.html"
    report_file.write_text(html, encoding='utf-8')
    
    return report_file


def inspect_site(url: str) -> dict:
    """
    Main inspection function - captures HTML + Network in single session.
    
    CRITICAL IMPLEMENTATION:
    1. Attach network listener BEFORE navigation
    2. Use response.text() for true raw HTML
    3. Wait 3s after load to catch lazy-loading
    4. Analyze and save both HTML + Network data
    
    Args:
        url: Target URL to inspect
        
    Returns:
        Dictionary with combined results
    """
    # Generate run ID using timestamp
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    timestamp = datetime.now().isoformat()
    
    # Create directory structure
    raw_dir, result_dir = create_run_directory(run_id)
    
    print(f"🔍 Inspecting: {url}")
    print(f"📁 Run ID: {run_id}")
    
    # Network logs storage (in-memory during capture)
    network_logs = []
    
    with sync_playwright() as p:
        # Launch browser with anti-blocking configuration
        browser = p.chromium.launch(headless=True)
        
        # Create context with custom User-Agent and headers
        # CRITICAL: Avoid default "HeadlessChrome" UA that triggers 403s
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            extra_http_headers={
                "Accept-Language": "en-US,en;q=0.9"
            }
        )
        
        page = context.new_page()
        
        # Attach network response listener BEFORE navigation
        def handle_response(response: Response):
            """
            Capture network responses, filtering out noise (images/fonts/css).
            
            Keep: xhr, fetch, websocket, eventsource, document
            Ignore: image, media, font, stylesheet, script, other
            """
            resource_type = response.request.resource_type
            
            # Filter: only capture data requests, not assets
            if resource_type not in ['xhr', 'fetch', 'websocket', 'eventsource', 'document']:
                return
            
            try:
                # Extract data
                is_graphql = is_graphql_request(response)
                content_type = response.headers.get('content-type', '')
                
                log_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "method": response.request.method,
                    "url": response.url,
                    "status": response.status,
                    "type": resource_type,
                    "content_type": content_type,
                    "is_graphql": is_graphql
                }
                
                network_logs.append(log_entry)
            except Exception as e:
                # Silently skip errors in logging (don't break the capture)
                pass
        
        page.on("response", handle_response)
        
        try:
            # Navigate and capture Response object
            # CRITICAL: Must use response.text() to get TRUE RAW HTML
            print("⏳ Navigating to URL...")
            response = page.goto(url, wait_until='domcontentloaded', timeout=30000)
            
            if response is None:
                raise Exception("Navigation failed: no response received")
            
            # Wait for lazy-loading requests (3 seconds)
            print("⏳ Waiting for lazy-loading requests...")
            page.wait_for_timeout(3000)
            
            # Extract true raw HTML from response object
            print("📥 Capturing raw HTML from server response...")
            raw_html = response.text()
            status_code = response.status
            
            # Save raw HTML to file
            raw_file = raw_dir / "initial.html"
            raw_file.write_text(raw_html, encoding='utf-8')
            print(f"✅ Saved raw HTML: {raw_file}")
            
            # Extract HTML statistics
            print("📊 Analyzing HTML structure...")
            html_stats = extract_html_stats(raw_html)
            
            # Save HTML stats JSON
            html_result = {
                "url": url,
                "timestamp": timestamp,
                "status_code": status_code,
                "stats": html_stats
            }
            html_result_file = result_dir / "html_stats.json"
            html_result_file.write_text(json.dumps(html_result, indent=2), encoding='utf-8')
            print(f"✅ Saved HTML statistics: {html_result_file}")
            
            # ==================================================================
            # MVP-3: DOM DIFF & SCROLL SIMULATION
            # ==================================================================
            print("\n" + "=" * 60)
            print("🔄 DOM DIFF ANALYSIS (MVP-3)")
            print("=" * 60)
            
            # Create dom_snapshots directory
            snapshots_dir = raw_dir / "dom_snapshots"
            snapshots_dir.mkdir(exist_ok=True)
            
            # t0: Extract metrics from RAW server HTML (CRITICAL FIX!)
            print("📸 Capturing t0 (raw server HTML)...")
            t0_metrics = extract_dom_metrics_from_html(raw_html)
            t0_file = snapshots_dir / "t0.html"
            t0_file.write_text(t0_metrics['html'], encoding='utf-8')
            print(f"   Nodes: {t0_metrics['node_count']}, Text: {t0_metrics['text_length']}")
            
            # Wait for hydration (2 seconds)
            print("⏳ Waiting for hydration (2 seconds)...")
            page.wait_for_timeout(2000)
            
            # t1: Extract metrics from HYDRATED DOM
            print("📸 Capturing t1 (hydrated DOM)...")
            t1_metrics = extract_dom_metrics_from_page(page)
            t1_file = snapshots_dir / "t1.html"
            t1_file.write_text(t1_metrics['html'], encoding='utf-8')
            print(f"   Nodes: {t1_metrics['node_count']}, Text: {t1_metrics['text_length']}, Height: {t1_metrics['scroll_height']}")
            
            # Perform incremental scroll
            print("📜 Performing incremental scroll...")
            perform_incremental_scroll(page)
            
            # t2: Extract metrics from SCROLLED DOM
            print("📸 Capturing t2 (scrolled DOM)...")
            t2_metrics = extract_dom_metrics_from_page(page)
            t2_file = snapshots_dir / "t2.html"
            t2_file.write_text(t2_metrics['html'], encoding='utf-8')
            print(f"   Nodes: {t2_metrics['node_count']}, Text: {t2_metrics['text_length']}, Height: {t2_metrics['scroll_height']}")
            
            # Calculate diffs and detect patterns
            print("📐 Calculating DOM diffs...")
            dom_diffs = calculate_dom_diffs(t0_metrics, t1_metrics, t2_metrics)
            
            # Prepare DOM diff result
            dom_diff_result = {
                "t0_stats": {
                    "node_count": t0_metrics['node_count'],
                    "text_length": t0_metrics['text_length'],
                    "scroll_height": t0_metrics['scroll_height']
                },
                "t1_stats": {
                    "node_count": t1_metrics['node_count'],
                    "text_length": t1_metrics['text_length'],
                    "scroll_height": t1_metrics['scroll_height']
                },
                "t2_stats": {
                    "node_count": t2_metrics['node_count'],
                    "text_length": t2_metrics['text_length'],
                    "scroll_height": t2_metrics['scroll_height']
                },
                "diffs": {
                    "hydration_growth": dom_diffs['hydration_growth'],
                    "scroll_growth": dom_diffs['scroll_growth'],
                    "scroll_height_growth": dom_diffs['scroll_height_growth']
                },
                "classification": {
                    "is_virtualized_suspected": dom_diffs['is_virtualized_suspected'],
                    "interpretation": dom_diffs['interpretation']
                }
            }
            
            # Save DOM diff result
            dom_diff_file = result_dir / "dom_diff.json"
            dom_diff_file.write_text(json.dumps(dom_diff_result, indent=2), encoding='utf-8')
            print(f"✅ Saved DOM diff analysis: {dom_diff_file}")
            print(f"   {dom_diffs['interpretation']}")
            print("=" * 60)
            
            # Save network logs (JSONL format)
            print(f"\n📡 Processing {len(network_logs)} network requests...")
            network_file = raw_dir / "network_requests.jsonl"
            with network_file.open('w', encoding='utf-8') as f:
                for log in network_logs:
                    f.write(json.dumps(log) + '\n')
            print(f"✅ Saved network logs: {network_file}")
            
            # Analyze network traffic
            network_summary = analyze_network_logs(network_logs)
            network_summary_file = result_dir / "network_summary.json"
            network_summary_file.write_text(json.dumps(network_summary, indent=2), encoding='utf-8')
            print(f"✅ Saved network summary: {network_summary_file}")
            
            # ==================================================================
            # MVP-4: ACCESS PROTECTION ANALYSIS
            # ==================================================================
            print("\n" + "=" * 60)
            print("🛡️  ACCESS PROTECTION ANALYSIS (MVP-4)")
            print("=" * 60)
            
            # Analyze AP signals using all collected evidence
            ap_signals = analyze_ap_signals(
                url=url,
                status_code=status_code,
                html_stats=html_stats,
                network_summary=network_summary,
                raw_html=raw_html,
                dom_diffs=dom_diff_result
            )
            
            # Save AP signals
            ap_signals_file = result_dir / "ap_signals.json"
            ap_signals_file.write_text(json.dumps(ap_signals, indent=2), encoding='utf-8')
            
            if ap_signals:
                print(f"⚠️  Detected {len(ap_signals)} AP signal(s):")
                for signal in ap_signals:
                    state_icon = "🔴" if signal['state'] == 'confirmed' else "🟠"
                    print(f"   {state_icon} {signal['label']} ({signal['state']}, confidence={signal['confidence']})")
            else:
                print("✅ No access protection detected")
            
            print(f"✅ Saved AP signals: {ap_signals_file}")
            print("=" * 60)
            
            # ==================================================================
            # MVP-5: SLAP SCORING & LABELING
            # ==================================================================
            print("\n" + "=" * 60)
            print("🎯 SLAP SCORING & LABELING (MVP-5)")
            print("=" * 60)
            
            # Calculate SLAP score and labels
            labels, score = calculate_slap_score(
                html_stats=html_stats,
                network_summary=network_summary,
                dom_diff_result=dom_diff_result,
                ap_signals=ap_signals
            )
            
            # Save labels
            labels_file = result_dir / "labels.json"
            labels_file.write_text(json.dumps(labels, indent=2), encoding='utf-8')
            print(f"✅ Saved SLAP labels: {labels_file}")
            
            # Save score
            score_file = result_dir / "score.json"
            score_file.write_text(json.dumps(score, indent=2), encoding='utf-8')
            print(f"✅ Saved difficulty score: {score_file}")
            
            # Print summary
            print(f"\n📊 SLAP Classification:")
            print(f"   Structure: {labels['structure']['primary']}", end="")
            if labels['structure']['modifiers']:
                print(f" + {', '.join(labels['structure']['modifiers'])}")
            else:
                print()
            print(f"   Loading: {labels['loading']}")
            print(f"   Protection: {', '.join(labels['access_protection'])}")
            print(f"\n💯 Difficulty Score: {score['total_score']}/100 ({score['tier']} Tier)")
            if score['drivers']:
                print(f"   Top Drivers: {', '.join(score['drivers'])}")
            print(f"   Breakdown: AP={score['breakdown']['AP']}, S={score['breakdown']['S']}, L={score['breakdown']['L']}")
            print("=" * 60)
            
            # ==================================================================
            # MVP-6: HUMAN-READABLE REPORT
            # ==================================================================
            print("\n" + "=" * 60)
            print("📄 GENERATING HUMAN REPORT (MVP-6)")
            print("=" * 60)
            
            report_file = generate_human_report(
                url=url,
                run_id=run_id,
                result_dir=result_dir,
                html_stats=html_stats,
                network_summary=network_summary,
                dom_diff_result=dom_diff_result,
                ap_signals=ap_signals,
                labels=labels,
                score=score
            )
            
            print(f"✅ Report generated: {report_file}")
            print(f"🌐 Open in browser: file:///{report_file.as_posix()}")
            print("=" * 60)
            
            # Save network logs (JSONL format)
            print(f"📡 Processing {len(network_logs)} network requests...")
            network_file = raw_dir / "network_requests.jsonl"
            with network_file.open('w', encoding='utf-8') as f:
                for log in network_logs:
                    f.write(json.dumps(log) + '\n')
            print(f"✅ Saved network logs: {network_file}")
            
            # Analyze network traffic
            network_summary = analyze_network_logs(network_logs)
            network_summary_file = result_dir / "network_summary.json"
            network_summary_file.write_text(json.dumps(network_summary, indent=2), encoding='utf-8')
            print(f"✅ Saved network summary: {network_summary_file}")
            
            # Print combined summary
            print("\n" + "=" * 60)
            print("📋 HTML ANALYSIS")
            print("=" * 60)
            print(f"Status Code:    {status_code}")
            print(f"Total Size:     {html_stats['total_size']:,} bytes")
            print(f"Tag Count:      {html_stats['tag_count']}")
            print(f"Link Count:     {html_stats['link_count']}")
            print(f"Text Ratio:     {html_stats['text_ratio']:.2%}")
            print(f"Has Root Div:   {html_stats['has_root_div']}")
            
            print("\n" + "=" * 60)
            print("📡 NETWORK ANALYSIS")
            print("=" * 60)
            print(f"Total Captured: {network_summary['total_captured']}")
            print(f"XHR/Fetch:      {network_summary['xhr_fetch_count']}")
            print(f"JSON Requests:  {network_summary['data_types']['json']}")
            print(f"GraphQL:        {network_summary['data_types']['graphql']}")
            print(f"Blocking (401): {network_summary['blocking_signals']['401']}")
            print(f"Blocking (403): {network_summary['blocking_signals']['403']}")
            print(f"Rate Limit(429):{network_summary['blocking_signals']['429']}")
            
            print("\n" + "=" * 60)
            print("🎯 CLASSIFICATION")
            print("=" * 60)
            
            # Structure classification (S-axis)
            if html_stats['text_ratio'] < 0.01 and html_stats['has_root_div']:
                print("S-AXIS: 🔴 S-CSR (Client-Side Rendering)")
            elif html_stats['text_ratio'] > 0.05 and html_stats['link_count'] > 20:
                print("S-AXIS: 🟢 S-SSR (Server-Side Rendering)")
            else:
                print("S-AXIS: 🟡 S-AMBIGUOUS")
            
            # Loading classification (L-axis)
            if network_summary['data_types']['graphql'] > 0:
                print("L-AXIS: 🔵 L-GRAPHQL (GraphQL API)")
            elif network_summary['xhr_fetch_count'] > 5:
                print("L-AXIS: 🔵 L-API (REST/JSON API)")
            else:
                print("L-AXIS: 🟢 L-STATIC")
            
            # Access Protection (AP-axis)
            if network_summary['blocking_signals']['429'] > 0:
                print("AP-AXIS: 🔴 AP-RATE (Rate Limited)")
            elif network_summary['blocking_signals']['401'] > 0 or network_summary['blocking_signals']['403'] > 0:
                print("AP-AXIS: 🔴 AP-AUTH (Auth Required/Blocked)")
            else:
                print("AP-AXIS: 🟢 AP-OPEN")
            
            print("=" * 60 + "\n")
            
            # Return data for batch processing
            strategy = get_strategy_text(labels, score['drivers'])
            
            return {
                "timestamp": timestamp,
                "status": "success",
                "score": score['total_score'],
                "tier": score['tier'],
                "strategy": strategy['message'],
                "drivers": score['drivers'],
                "labels": labels,
                "full_score": score,
                "html_stats": html_stats,
                "network_summary": network_summary,
                "dom_diff_result": dom_diff_result,
                "ap_signals": ap_signals
            }
            
        except Exception as e:
            print(f"❌ Error during inspection: {e}")
            raise
        finally:
            browser.close()


def main():
    """Command-line entry point."""
    if len(sys.argv) < 2:
        print("Usage: python slap_agent.py <URL>")
        print("\nExamples:")
        print("  python slap_agent.py https://news.ycombinator.com  # SSR, minimal API")
        print("  python slap_agent.py https://twitter.com           # CSR, heavy API")
        print("  python slap_agent.py https://github.com            # GraphQL test")
        sys.exit(1)
    
    url = sys.argv[1]
    
    try:
        inspect_site(url)
    except KeyboardInterrupt:
        print("\n⚠️  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
