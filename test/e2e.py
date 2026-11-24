import json, os, subprocess, sys, tempfile, time
from playwright.sync_api import sync_playwright

SHOTS = os.environ.get("E2E_SCREENSHOTS", tempfile.gettempdir())
proc = subprocess.Popen(["node", "test/e2e-harness.js"], cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))), stdout=subprocess.PIPE, text=True)
info = json.loads(proc.stdout.readline())
base = info["base"].replace("127.0.0.1", "localhost")
webhook = info["webhook"]
problems = []

def wait(page, js, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if page.evaluate(js):
                return True
        except Exception:
            pass
        time.sleep(0.1)
    raise AssertionError("timeout waiting for " + js)

def check(cond, msg):
    if not cond:
        problems.append(msg)
    print(("PASS " if cond else "FAIL ") + msg)

try:
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=os.environ.get("CHROME_PATH") or None)
        ctx = browser.new_context(viewport={"width": 1280, "height": 860}, color_scheme="dark")
        ctx.grant_permissions(["clipboard-read", "clipboard-write"], origin=base)
        page = ctx.new_page()
        console_errors = []
        page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: console_errors.append("pageerror: " + str(e)))
        page.add_init_script("window.__csp=[];document.addEventListener('securitypolicyviolation',e=>window.__csp.push(e.violatedDirective+' '+e.blockedURI));")
        page.goto(base + "/")
        page.wait_for_selector("#connect_view:not(.hidden)")
        page.screenshot(path=os.path.join(SHOTS, "01-connect.png"))
        check(page.is_disabled("#connect_button"), "connect disabled when empty")
        page.fill("#input_webhook", "https://evil.com/api/webhooks/1/2")
        check(page.is_disabled("#connect_button"), "connect disabled for bad url")
        check("Expected" in page.text_content("#connect_error"), "inline validation message")
        page.fill("#input_webhook", webhook[:-3] + "zzz")
        page.click("#connect_button")
        wait(page, "document.getElementById('connect_error').textContent.includes('Discord did not accept')")
        check(True, "dead webhook rejected via server verify")
        page.fill("#input_webhook", webhook)
        page.uncheck("#remember")
        page.click("#connect_button")
        page.wait_for_selector("#app_view:not(.hidden)")
        page.wait_for_selector(".note")
        check(page.text_content("#identity_name") == "Research Vault", "webhook name shown")
        check(webhook.split("/")[-1] not in page.content(), "token never rendered in DOM")
        check(page.evaluate("localStorage.getItem('cipherhook_webhook')") is None and page.evaluate("sessionStorage.getItem('cipherhook_webhook')") == webhook, "remember off uses sessionStorage")
        first = page.locator(".note").first
        check(first.locator("a").get_attribute("href") == "https://example.com/docs?x=1", "url linkified")
        check(first.locator("a").get_attribute("rel") == "noopener noreferrer nofollow", "safe link rel")
        check("<script>" in first.locator(".note-body").text_content() and first.locator("script").count() == 0, "html rendered as text")
        page.screenshot(path=os.path.join(SHOTS, "02-feed.png"))
        for _ in range(20):
            page.mouse.wheel(0, 4000)
            page.wait_for_timeout(150)
            if page.locator(".note").count() >= 23:
                break
        wait(page, "document.querySelectorAll('.note').length === 23")
        check(page.locator(".note").count() == 23, "infinite scroll loaded all 23 notes")
        check("first note" in page.text_content("#feed_status"), "end-of-feed status")
        check(page.text_content("#notes_count") == "23 notes", "count badge")
        page.evaluate("window.scrollTo(0,0)")
        page.fill("#input_note", "Hello from E2E ✓\nline two")
        page.keyboard.press("End")
        page.press("#input_note", "Enter")
        wait(page, "document.querySelector('.note .note-body').textContent.startsWith('Hello from E2E')")
        check(page.input_value("#input_note") == "", "composer cleared after send")
        check(page.text_content("#notes_count") == "24 notes", "count incremented")
        page.fill("#search", "seed note #1")
        page.wait_for_timeout(100)
        visible = page.locator(".note:not(.hidden-by-filter)").count()
        check(visible == 11, f"filter matches 11 (got {visible})")
        page.fill("#search", "")
        page.locator(".note").first.hover()
        page.locator(".note").first.locator("[data-action=copy]").click()
        page.wait_for_timeout(200)
        clip = page.evaluate("navigator.clipboard.readText()")
        check(clip.startswith("Hello from E2E"), "copy to clipboard")
        page.locator(".note").first.locator("[data-action=delete]").click()
        page.wait_for_selector("#confirm_dialog[open]")
        page.screenshot(path=os.path.join(SHOTS, "03-confirm.png"))
        page.click("#confirm_ok")
        wait(page, "!document.querySelector('.note .note-body').textContent.startsWith('Hello from E2E')")
        check(page.text_content("#notes_count") == "23 notes", "delete updates count")
        page.click("#settings_button")
        page.wait_for_selector("#settings_dialog[open]")
        wait(page, "document.getElementById('input_username').value === 'CipherHook'")
        page.fill("#input_username", "Discord Helper")
        page.click("#settings_save")
        check("discord" in page.text_content("#settings_error"), "client-side username validation")
        page.fill("#input_username", "Jhon Notes")
        page.fill("#input_pfp", "")
        page.screenshot(path=os.path.join(SHOTS, "04-settings.png"))
        page.click("#settings_save")
        wait(page, "!document.getElementById('settings_dialog').open")
        wait(page, "document.querySelector('.note-author').textContent === 'Jhon Notes'")
        check(True, "settings saved and author updated")
        page.set_viewport_size({"width": 390, "height": 800})
        page.wait_for_timeout(200)
        page.screenshot(path=os.path.join(SHOTS, "05-mobile.png"))
        page.reload()
        page.wait_for_selector(".note")
        check(page.text_content("#identity_name") == "Research Vault", "session survives reload in same tab")
        page.click("#logout_button")
        page.wait_for_selector("#confirm_dialog[open]")
        page.click("#confirm_ok")
        page.wait_for_selector("#connect_view:not(.hidden)")
        check(page.evaluate("sessionStorage.length + localStorage.length") == 0, "disconnect clears storage")
        csp = page.evaluate("window.__csp")
        check(csp == [], f"no CSP / Trusted Types violations {csp}")
        relevant = [e for e in console_errors if "Failed to load resource" not in e]
        check(relevant == [], f"no console errors {relevant}")
        light = browser.new_context(viewport={"width": 1280, "height": 860}, color_scheme="light")
        lp = light.new_page()
        lp.goto(base + "/")
        lp.fill("#input_webhook", webhook)
        lp.click("#connect_button")
        lp.wait_for_selector(".note")
        lp.wait_for_timeout(300)
        lp.screenshot(path=os.path.join(SHOTS, "06-light.png"))
        browser.close()
finally:
    proc.terminate()
    proc.wait(5)

print("PROBLEMS:", problems)
sys.exit(1 if problems else 0)
