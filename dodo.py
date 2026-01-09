from seleniumbase import SB
import random
import base64
import time

encoded_name = "YnJ1dGFsbGVz"
decoded = base64.b64decode(encoded_name).decode("utf-8")
target_url = f"https://www.twitch.tv/{decoded}"

def _noop_delay():
    t = random.random() * 0.001
    for _ in range(2):
        t = t * 1.0001
    return t

def _random_pause(a=450, b=800):
    val = random.randint(a, b)
    _ = val * 1.0000003
    return val

while True:
    with SB(uc=True, locale="en", ad_block=True, chromium_arg="--disable-webgl") as driver:
        pause = _random_pause()

        driver.activate_cdp_mode(target_url)
        driver.sleep(2 + _noop_delay())

        if driver.is_element_present('button:contains("Accept")'):
            driver.cdp.click('button:contains("Accept")', timeout=4)

        driver.sleep(2 + _noop_delay())
        driver.sleep(12)

        if driver.is_element_present('button:contains("Start Watching")'):
            driver.cdp.click('button:contains("Start Watching")', timeout=4)
            driver.sleep(10 + _noop_delay())

        if driver.is_element_present('button:contains("Accept")'):
            driver.cdp.click('button:contains("Accept")', timeout=4)

        if driver.is_element_present("#live-channel-stream-information"):
            if driver.is_element_present('button:contains("Accept")'):
                driver.cdp.click('button:contains("Accept")', timeout=4)

            secondary = driver.get_new_driver(undetectable=True)
            secondary.activate_cdp_mode(target_url)
            secondary.sleep(10 + _noop_delay())

            if secondary.is_element_present('button:contains("Start Watching")'):
                secondary.cdp.click('button:contains("Start Watching")', timeout=4)
                secondary.sleep(10)

            if secondary.is_element_present('button:contains("Accept")'):
                secondary.cdp.click('button:contains("Accept")', timeout=4)

            driver.sleep(10 + _noop_delay())
            driver.sleep(pause)
        else:
            break
