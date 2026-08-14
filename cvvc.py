#!/usr/bin/env python
# coding: utf-8

"""
HP Community – Full Sign‑up with Playwright + Proxy Rotation
- Uses installed Chrome (channel="chrome")
- Rotates proxies from proxies.txt
- Robust verification with domain cookie debug
- Auth cookies (LithiumUserInfo, LithiumUserSecure) detection
- Retry logic for session handoff
- Prints email & password on success
"""

import json
import random
import re
import time
from pathlib import Path
from urllib.parse import urlparse

import requests
from playwright.sync_api import sync_playwright, Error as PlaywrightError
from faker import Faker
from dotenv import load_dotenv

load_dotenv()

# ============================================================
# CONFIGURATION
# ============================================================
TARGET_URL = "https://h30434.www3.hp.com/t5/Printer-Wireless-Networking-Internet/Printer-not-connecting-to-wifi/td-p/9529101"
PROXY_FILE = Path("proxies.txt")
REGISTRATION_EMAIL = "hatit55049@joystill.com"   # CHANGE THIS
HP_CONFIRM_URL = (
    "https://h30434.www3.hp.com/t5/user/ssoregistrationpage"
    "?dest_url=https%3A%2F%2Fh30434.www3.hp.com%2Ft5%2FPrinter-Wireless-Networking-Internet"
    "%2FPrinter-not-connecting-to-wifi%2Ftd-p%2F9529101"
)

TEST_PROXY_BEFORE_USE = True
TEST_TIMEOUT = 15
PROXY_TEST_URL = "https://httpbin.org/ip"
MAX_RETRIES_PER_PROXY = 2
PAGE_LOAD_WAIT = 15

# ============================================================
# PROXY LOADING & PARSING
# ============================================================
def build_proxy_config(proxy_str):
    proxy_str = proxy_str.strip()
    if not proxy_str:
        return None
    parts = proxy_str.split(":", 3)
    if len(parts) >= 2:
        host = parts[0].strip()
        port_str = parts[1].strip()
        if host and port_str.isdigit():
            port = int(port_str)
            if 1 <= port <= 65535:
                username = parts[2].strip() if len(parts) >= 3 and parts[2] else None
                password = parts[3].strip() if len(parts) >= 4 and parts[3] else None
                return {"host": host, "port": port, "username": username, "password": password, "label": f"{host}:{port}"}
    normalized = proxy_str if "://" in proxy_str else f"http://{proxy_str}"
    parsed = urlparse(normalized)
    if not parsed.hostname or not parsed.port:
        return None
    return {
        "host": parsed.hostname,
        "port": parsed.port,
        "username": parsed.username,
        "password": parsed.password,
        "label": f"{parsed.hostname}:{parsed.port}",
    }

def get_proxy_candidates(limit=20):
    proxies = []
    if PROXY_FILE.exists():
        with open(PROXY_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    proxies.append(line)
    if not proxies:
        print("⚠️ No proxies found – using direct connection.")
        return [None]
    random.shuffle(proxies)
    candidates = []
    for p in proxies[:limit]:
        cfg = build_proxy_config(p)
        if cfg:
            candidates.append(cfg)
    if not candidates:
        return [None]
    print(f"✅ Found {len(candidates)} valid proxy candidates.")
    return candidates

def test_proxy(proxy_cfg):
    if not proxy_cfg:
        return {"status": "ok"}
    host = proxy_cfg["host"]
    port = proxy_cfg["port"]
    username = proxy_cfg.get("username")
    password = proxy_cfg.get("password")
    proxy_url = f"http://{host}:{port}"
    if username and password:
        proxy_url = f"http://{username}:{password}@{host}:{port}"
    elif username:
        proxy_url = f"http://{username}@{host}:{port}"
    proxies = {"http": proxy_url, "https": proxy_url}
    try:
        r = requests.get(PROXY_TEST_URL, proxies=proxies, timeout=TEST_TIMEOUT)
        if r.status_code == 200:
            ip = r.json().get("origin", "unknown")
            print(f"✅ Proxy test PASSED – IP: {ip}")
            return {"status": "ok", "ip": ip}
        elif r.status_code == 407:
            print(f"❌ Proxy auth required (407) – check credentials")
            return {"status": "auth_failed"}
        elif r.status_code in (502, 503, 504):
            print(f"⚠️ Proxy temporary error ({r.status_code}) – may retry")
            return {"status": "temporary"}
        else:
            print(f"❌ Proxy test failed (status {r.status_code})")
            return {"status": "failed"}
    except requests.exceptions.Timeout:
        print(f"❌ Proxy test TIMEOUT ({TEST_TIMEOUT}s)")
        return {"status": "temporary"}
    except Exception as e:
        print(f"❌ Proxy test ERROR: {e}")
        return {"status": "error"}

# ============================================================
# HP PAGE CONTENT CHECK
# ============================================================
def is_actual_hp_page(page):
    try:
        title = page.title().lower()
        body = page.locator("body").inner_text(timeout=3000).lower()
        return (
            "hp support community" in title
            and "printer not connecting to wifi" in body
        )
    except Exception:
        return False

# ============================================================
# BROWSER IP CHECK
# ============================================================
def check_browser_ip(context):
    page = context.new_page()
    try:
        page.goto("https://api.ipify.org?format=json", wait_until="domcontentloaded", timeout=15000)
        ip = page.locator("body").inner_text().strip()
        print(f"🌐 Browser public IP: {ip}")
        return ip
    except Exception as e:
        print(f"❌ IP check failed: {e}")
        return None
    finally:
        page.close()

# ============================================================
# COOKIE DEBUGGING (with domain/path)
# ============================================================
def get_hp_cookies(context):
    return {
        c["name"]: c["value"]
        for c in context.cookies()
        if "hp.com" in c["domain"] or "h30434" in c["domain"]
    }

def print_auth_cookies(context, label):
    cookies = context.cookies()
    auth_cookies = []
    for c in cookies:
        if c["name"] in ("LithiumUserInfo", "LithiumUserSecure"):
            auth_cookies.append(c)
    print(f"\n🍪 {label} AUTH COOKIES:")
    if not auth_cookies:
        print("   (none)")
    for c in auth_cookies:
        print(f"   {c['name']} domain={c['domain']} path={c['path']} secure={c['secure']} httpOnly={c['httpOnly']}")

# ============================================================
# LOGIN CHECK (cookie + UI)
# ============================================================
def confirm_logged_in(page, context):
    cookies = context.cookies()
    cookie_names = {c["name"] for c in cookies}
    has_session_cookie = "LithiumUserSecure" in cookie_names and "LithiumUserInfo" in cookie_names
    if has_session_cookie:
        print("✅ HP authentication cookies detected.")
        # Also print domain/path of those cookies
        for c in cookies:
            if c["name"] in ("LithiumUserInfo", "LithiumUserSecure"):
                print(f"   {c['name']}: domain={c['domain']}, path={c['path']}")
    else:
        print("❌ HP authentication cookies NOT detected.")
    
    try:
        body = page.locator("body").inner_text(timeout=10000)
        if "Sign in / Create an account" not in body and "Sign up / Sign in" not in body:
            print("✅ HP page no longer shows anonymous sign-in.")
            return True
    except Exception as e:
        print(f"⚠️ UI login check failed: {e}")
    
    return has_session_cookie

# ============================================================
# ROBUST CLICKS
# ============================================================
def click_account_link(page):
    print("🔘 Clicking 'Sign in / Create an account'...")
    selectors = [
        "a:has-text('Sign in / Create an account')",
        "a:has-text('Sign in')",
        "a:has-text('Create an account')",
        "text=Sign in / Create an account",
        "a[href*='oauth2sso_v2/sso_login_redirect']",
        "a:has-text('Sign up / Sign in')",
        "button:has-text('Sign in')",
        "button:has-text('Create an account')",
    ]
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if locator.count() == 0:
                continue
            print(f"🔎 Trying: {selector}")
            locator.scroll_into_view_if_needed(timeout=5000)
            locator.click(timeout=10000)
            print(f"✅ Clicked: {selector}")
            return True
        except Exception as e:
            print(f"⚠️ Failed {selector}: {e}")
    print("❌ All selectors failed. Dumping debug info...")
    page.screenshot(path="account_click_debug.png", full_page=True)
    with open("account_click_debug.html", "w", encoding="utf-8") as f:
        f.write(page.content())
    return False

def wait_and_click_create_account(page):
    print("⏳ Waiting for 'Create account' on login page...")
    selectors = [
        "a:has-text('Create account')",
        "button:has-text('Create account')",
        "text=Create account",
    ]
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            locator.wait_for(state="visible", timeout=30000)
            locator.scroll_into_view_if_needed()
            print(f"🔎 Found: {selector}")
            locator.click(timeout=10000)
            print("✅ 'Create account' clicked.")
            return True
        except Exception as e:
            print(f"⚠️ {selector} not ready: {e}")
    return False

# ============================================================
# SIGN‑UP FLOW
# ============================================================
def generate_user_data():
    fake = Faker()
    first_name = fake.first_name()
    last_name = fake.last_name()
    password = fake.password(length=12, special_chars=True, digits=True, upper_case=True, lower_case=True)
    return {"first_name": first_name, "last_name": last_name, "password": password}

def handle_cookie_consent(page):
    print("🍪 Accepting cookies...")
    selectors = [
        "button:has-text('Accept All')",
        "button:has-text('Accept')",
        "#onetrust-accept-btn-handler",
        "button[class*='accept']",
    ]
    for sel in selectors:
        try:
            btn = page.locator(sel).first
            if btn.is_visible():
                btn.click()
                print("✅ Cookies accepted.")
                time.sleep(2)
                return True
        except:
            continue
    print("ℹ️ No cookie banner.")
    return False

def fill_signup_form(page, first_name, last_name, email, password):
    print("✍️ Filling sign-up form...")
    fields = {
        "firstName": first_name,
        "lastName": last_name,
        "email": email,
        "password": password,
    }
    for field_id, value in fields.items():
        try:
            inp = page.locator(f"#{field_id}").first
            inp.scroll_into_view_if_needed()
            inp.fill(value)
            print(f"   ✅ Filled {field_id}")
        except Exception as e:
            print(f"   ❌ Could not fill {field_id}: {e}")
            return False
    return True

def check_terms_checkbox(page):
    print("🔘 Looking for checkbox...")
    try:
        checkbox = page.locator("input[type='checkbox']").first
        if checkbox.is_visible() and not checkbox.is_checked():
            checkbox.click()
            print("✅ Checkbox checked.")
            return True
    except:
        pass
    try:
        span = page.locator("span.vn-checkbox__span").first
        if span.is_visible():
            span.click()
            print("✅ Checkbox clicked via span.")
            return True
    except:
        pass
    try:
        label = page.locator("label[for='terms']").first
        if label.is_visible():
            label.click()
            print("✅ Checkbox clicked via label.")
            return True
    except:
        pass
    print("⚠️ Checkbox not found – proceeding.")
    return False

def click_create_button(page):
    print("🔘 Looking for Create button...")
    selectors = [
        "button:has-text('Create')",
        "button[type='submit']",
        "button.css-1q5f153",
    ]
    for sel in selectors:
        try:
            btn = page.locator(sel).first
            if btn.is_visible():
                btn.scroll_into_view_if_needed()
                btn.click()
                print("✅ Create button clicked.")
                return True
        except:
            continue
    print("❌ Could not click Create button.")
    return False

# ============================================================
# VERIFICATION & LOGIN CONFIRMATION (with domain cookie debug)
# ============================================================
def confirm_verification_and_login(context, verification_link):
    if not verification_link:
        return False

    print_auth_cookies(context, "BEFORE VERIFICATION")

    print("\n🌐 Opening verification link in same context...")
    verification_page = context.new_page()
    try:
        verification_page.goto(verification_link, wait_until="domcontentloaded", timeout=60000)
        print("✅ Verification page loaded.")
    except Exception as e:
        print(f"⚠️ Verification page error: {e}")
        verification_page.close()
        return False

    # Wait for the verification success message
    try:
        verification_page.wait_for_selector(
            "text=Your email address has been verified",
            timeout=30000
        )
        print("✅ Email verification confirmed!")
    except:
        print("⚠️ Verification success message not found, but continuing...")

    # Let the redirects finish (wait for final URL)
    try:
        # Wait for URL to become something like /verification/confirmed or /confirmed
        verification_page.wait_for_url(
            lambda url: "confirmed" in url or "verification/confirmed" in url or "login3.id.hp.com" in url,
            timeout=30000
        )
        print(f"📍 Final verification URL: {verification_page.url}")
    except:
        print("⚠️ Could not detect final verification URL, continuing...")

    # Wait a bit more for cookies to be set
    verification_page.wait_for_timeout(5000)
    verification_page.close()
    time.sleep(2)

    print_auth_cookies(context, "AFTER VERIFICATION")

    # If auth cookies are still missing, try to reload HP page (may trigger SSO)
    cookies = context.cookies()
    has_auth = any(c["name"] in ("LithiumUserInfo", "LithiumUserSecure") for c in cookies)
    if not has_auth:
        print("⚠️ Auth cookies not found after verification. Attempting to reload HP page to trigger SSO...")
        # Open a new page and load the target URL (with cache bust)
        reload_page = context.new_page()
        reload_page.goto(TARGET_URL + "?nocache=" + str(int(time.time())), wait_until="domcontentloaded", timeout=60000)
        reload_page.wait_for_timeout(5000)
        reload_page.close()
        print("🔄 HP page reloaded. Checking cookies again...")
        print_auth_cookies(context, "AFTER HP RELOAD")

    # Final check
    main_page = context.new_page()
    main_page.goto(TARGET_URL, wait_until="domcontentloaded", timeout=60000)
    main_page.wait_for_timeout(3000)

    login_ok = confirm_logged_in(main_page, context)
    main_page.screenshot(path="final_login_check.png")
    main_page.close()

    if login_ok:
        print("🎉 LOGIN CONFIRMED SUCCESSFULLY!")
        return True
    else:
        print("❌ Login could not be confirmed.")
        return False

# ============================================================
# MAIN AUTOMATION
# ============================================================
def run_signup_flow(proxy_cfg, retry_count=0):
    with sync_playwright() as p:
        launch_options = {
            "headless": False,
            "channel": "chrome",
            "args": ["--start-maximized", "--disable-blink-features=AutomationControlled"],
        }
        if proxy_cfg:
            launch_options["proxy"] = {"server": f"http://{proxy_cfg['host']}:{proxy_cfg['port']}"}
            if proxy_cfg.get("username"):
                launch_options["proxy"]["username"] = proxy_cfg["username"]
                launch_options["proxy"]["password"] = proxy_cfg.get("password", "")
            print(f"🔁 Proxy: {proxy_cfg['label']}")
        else:
            print("🔁 Direct connection.")

        browser = p.chromium.launch(**launch_options)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            locale="en-US",
            no_viewport=True,
        )

        check_browser_ip(context)

        page = context.new_page()
        print(f"🌐 Opening {TARGET_URL}")
        try:
            page.goto(TARGET_URL, wait_until="domcontentloaded", timeout=60000)
        except PlaywrightError as e:
            print(f"❌ Page load error: {e}")
            browser.close()
            return {"success": False, "error": str(e)}

        print(f"⏳ Waiting {PAGE_LOAD_WAIT} seconds for page to settle...")
        time.sleep(PAGE_LOAD_WAIT)

        if not is_actual_hp_page(page):
            print("⚠️ HP content not detected.")
            page.screenshot(path="hp_debug.png")
            if retry_count < MAX_RETRIES_PER_PROXY:
                print(f"🔄 Retrying ({retry_count+1}/{MAX_RETRIES_PER_PROXY})...")
                time.sleep(3)
                browser.close()
                return run_signup_flow(proxy_cfg, retry_count+1)
            else:
                browser.close()
                return {"success": False, "error": "Content not detected"}

        print("✅ HP page loaded successfully.")

        handle_cookie_consent(page)

        if not click_account_link(page):
            browser.close()
            return {"success": False, "error": "Account link failed"}

        print("⏳ Waiting for HP login page...")
        try:
            page.wait_for_url(lambda url: "login3.id.hp.com" in url or "sso_login" in url, timeout=30000)
            print(f"✅ Login page loaded: {page.url}")
        except:
            print("⚠️ URL did not match expected pattern, but continuing with UI wait...")

        if not wait_and_click_create_account(page):
            browser.close()
            return {"success": False, "error": "Create account failed"}

        page.wait_for_load_state("domcontentloaded", timeout=15000)
        time.sleep(2)

        user = generate_user_data()
        email = REGISTRATION_EMAIL
        password = user["password"]
        if not fill_signup_form(page, user["first_name"], user["last_name"], email, password):
            browser.close()
            return {"success": False, "error": "Form fill failed"}

        check_terms_checkbox(page)

        if not click_create_button(page):
            browser.close()
            return {"success": False, "error": "Create button failed"}

        time.sleep(5)
        page.screenshot(path="signup_submitted.png")
        print("📸 Screenshot saved: signup_submitted.png")

        print("\n" + "="*60)
        print("📧 Verification email sent. Please paste the verification link:")
        verification_link = input("🔗 Paste link: ").strip()
        if not verification_link:
            browser.close()
            return {"success": False, "error": "No link provided"}

        login_ok = confirm_verification_and_login(context, verification_link)

        browser.close()
        if login_ok:
            return {
                "success": True,
                "email": email,
                "password": password,
            }
        else:
            return {"success": False, "error": "Login not confirmed"}

# ============================================================
# MAIN LOOP (Proxy Rotation)
# ============================================================
def main():
    print("\n" + "="*70)
    print("🚀 HP Sign-up with Playwright + Proxy Rotation")
    print("="*70)
    print(f"📧 Using email: {REGISTRATION_EMAIL}")

    candidates = get_proxy_candidates(limit=20)
    good = []
    temp = []
    for proxy_cfg in candidates:
        if proxy_cfg is None:
            good.append(None)
            continue
        if TEST_PROXY_BEFORE_USE:
            result = test_proxy(proxy_cfg)
            if result["status"] == "ok":
                good.append(proxy_cfg)
            elif result["status"] in ("temporary", "timeout"):
                temp.append(proxy_cfg)
            else:
                continue
        else:
            good.append(proxy_cfg)

    ordered = good + temp
    if not ordered:
        ordered = [None]

    for i, proxy_cfg in enumerate(ordered):
        label = proxy_cfg["label"] if proxy_cfg else "Direct"
        print(f"\n🔁 Attempt {i+1} using {label}")
        result = run_signup_flow(proxy_cfg)
        if result and result.get("success"):
            print("\n" + "="*60)
            print("🎉 SIGN-UP AND LOGIN COMPLETED SUCCESSFULLY!")
            print("="*60)
            print(f"📧 Email    : {result['email']}")
            print(f"🔑 Password : {result['password']}")
            print("="*60)
            return
        else:
            err = result.get("error", "Unknown error") if result else "No result"
            print(f"❌ Attempt failed: {err}")

    print("\n❌ All attempts failed.")

if __name__ == "__main__":
    main()