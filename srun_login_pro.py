import json
import requests
import time
import re
import hmac
import hashlib
import math
import os
import logging
import sys
import signal
from typing import Optional, Dict, Any

# --- Configuration & Logging ---
# Use a more readable logging format for Docker/systemd logs
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    stream=sys.stdout
)
logger = logging.getLogger("SRUN")

# Configuration from Environment Variables
USERNAME = os.getenv('USERNAME', '').strip()
PASSWORD = os.getenv('PASSWORD', '').strip()
INIT_URL = os.getenv('INIT_URL', os.getenv('init_url', 'https://portal.ucas.ac.cn')).strip()
GET_CHALLENGE_API = os.getenv('GET_CHALLENGE_API', os.getenv('get_challenge_api', 'https://portal.ucas.ac.cn/cgi-bin/get_challenge')).strip()
SRUN_PORTAL_API = os.getenv('SRUN_PORTAL_API', os.getenv('srun_portal_api', 'https://portal.ucas.ac.cn/cgi-bin/srun_portal')).strip()
GET_IP_API = os.getenv('GET_IP_API', os.getenv('get_ip_api', 'http://124.16.81.61/cgi-bin/rad_user_info?callback=JQuery')).strip()
SLEEP_TIME = int(os.getenv('SLEEP_TIME', '300'))

# Advanced Configuration
HEALTH_CHECK_URL = os.getenv('HEALTH_CHECK_URL', 'https://www.baidu.com').strip() # Back to Baidu/CN-friendly by default
MAX_RETRIES = 3
RETRY_DELAY = 5 # Seconds between retries in a single auth attempt

HEADER = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.9',
}

# SRUN Constants
SRUN_N = '200'
SRUN_TYPE = '1'
SRUN_AC_ID = '1'
SRUN_ENC_VER = "srun_bx1"
ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"

# Global State
state = {
    'ip': '',
    'token': '',
    'hmd5': '',
    'chksum': '',
    'info': '',
    'running': True
}

# --- Signal Handling for Graceful Exit ---
def signal_handler(sig, frame):
    logger.info("Termination signal received. Exiting gracefully...")
    state['running'] = False

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# --- Core Logic ---

def get_base64(s: str) -> str:
    r = []
    x = len(s) % 3
    if x:
        s = s + '\0' * (3 - x)
    for i in range(0, len(s), 3):
        d = s[i:i + 3]
        a = ord(d[0]) << 16 | ord(d[1]) << 8 | ord(d[2])
        r.append(ALPHA[a >> 18])
        r.append(ALPHA[a >> 12 & 63])
        r.append(ALPHA[a >> 6 & 63])
        r.append(ALPHA[a & 63])
    if x == 1:
        r[-1] = '='
        r[-2] = '='
    elif x == 2:
        r[-1] = '='
    return ''.join(r)

def get_md5(password: str, token: str) -> str:
    return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()

def sencode(msg: str, key: bool) -> list:
    l = len(msg)
    pwd = []
    for i in range(0, l, 4):
        chunk = 0
        for j in range(4):
            if i + j < l:
                chunk |= ord(msg[i + j]) << (j * 8)
        pwd.append(chunk)
    if key:
        pwd.append(l)
    return pwd

def lencode(msg: list, key: bool) -> str:
    l = len(msg)
    ll = (l - 1) << 2
    if key:
        m = msg[l - 1]
        if m < ll - 3 or m > ll:
            return ""
        ll = m
    res = []
    for i in range(l):
        res.append(chr(msg[i] & 0xff))
        res.append(chr(msg[i] >> 8 & 0xff))
        res.append(chr(msg[i] >> 16 & 0xff))
        res.append(chr(msg[i] >> 24 & 0xff))
    final_str = "".join(res)
    return final_str[:ll] if key else final_str

def get_xencode(msg: str, key: str) -> str:
    if not msg:
        return ""
    pwd = sencode(msg, True)
    pwdk = sencode(key, False)
    if len(pwdk) < 4:
        pwdk = pwdk + [0] * (4 - len(pwdk))
    n = len(pwd) - 1
    z = pwd[n]
    y = pwd[0]
    c = 0x86014019 | 0x183639A0
    q = math.floor(6 + 52 / (n + 1))
    d = 0
    while q > 0:
        d = (d + c) & 0xFFFFFFFF
        e = d >> 2 & 3
        for p in range(n):
            y = pwd[p + 1]
            m = (z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (d ^ y) + (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = (pwd[p] + m) & 0xFFFFFFFF
            z = pwd[p]
        y = pwd[0]
        m = (z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (d ^ y) + (pwdk[(n & 3) ^ e] ^ z)
        pwd[n] = (pwd[n] + m) & 0xFFFFFFFF
        z = pwd[n]
        q -= 1
    return lencode(pwd, False)

def get_chksum() -> str:
    chkstr = state['token'] + USERNAME
    chkstr += state['token'] + state['hmd5']
    chkstr += state['token'] + SRUN_AC_ID
    chkstr += state['token'] + state['ip']
    chkstr += state['token'] + SRUN_N
    chkstr += state['token'] + SRUN_TYPE
    chkstr += state['token'] + state['info']
    return hashlib.sha1(chkstr.encode()).hexdigest()

def get_info() -> str:
    info_dict = {
        "username": USERNAME,
        "password": PASSWORD,
        "ip": state['ip'],
        "acid": SRUN_AC_ID,
        "enc_ver": SRUN_ENC_VER
    }
    return json.dumps(info_dict, separators=(',', ':'))

def fetch_ip(session: requests.Session) -> bool:
    try:
        res = session.get(GET_IP_API, timeout=10)
        res.raise_for_status()
        match = re.search(r'jQuery\d+\((.*)\)', res.text)
        if not match:
            logger.error(f"Failed to parse IP from response: {res.text[:100]}")
            return False
        data = json.loads(match.group(1))
        state['ip'] = data.get('client_ip') or data.get('online_ip')
        if not state['ip']:
            logger.error("No IP found in response data")
            return False
        logger.info(f"Detected Network IP: {state['ip']}")
        return True
    except Exception as e:
        logger.error(f"Error fetching IP: {e}")
        return False

def fetch_token(session: requests.Session) -> bool:
    params = {
        "callback": f"jQuery1124{int(time.time() * 1000)}",
        "username": USERNAME,
        "ip": state['ip'],
        "_": int(time.time() * 1000),
    }
    try:
        res = session.get(GET_CHALLENGE_API, params=params, headers=HEADER, timeout=10)
        res.raise_for_status()
        match = re.search('"challenge":"(.*?)"', res.text)
        if not match:
            logger.error(f"Failed to fetch challenge token: {res.text[:100]}")
            return False
        state['token'] = match.group(1)
        logger.info(f"Challenge Token acquired: {state['token']}")
        return True
    except Exception as e:
        logger.error(f"Error fetching token: {e}")
        return False

def is_connected(session: requests.Session) -> bool:
    """Uses a lightweight 204 No Content check to verify internet connectivity."""
    try:
        # 204 check is much faster than loading a full page
        resp = session.get(HEALTH_CHECK_URL, timeout=5)
        return resp.status_code in [200, 204]
    except:
        return False

def prepare_payloads():
    state['info'] = get_info()
    state['info'] = "{SRBX1}" + get_base64(get_xencode(state['info'], state['token']))
    state['hmd5'] = get_md5(PASSWORD, state['token'])
    state['chksum'] = get_chksum()

def do_login(session: requests.Session) -> bool:
    params = {
        'callback': f'jQuery1124{int(time.time() * 1000)}',
        'action': 'login',
        'username': USERNAME,
        'password': '{MD5}' + state['hmd5'],
        'ac_id': SRUN_AC_ID,
        'ip': state['ip'],
        'chksum': state['chksum'],
        'info': state['info'],
        'n': SRUN_N,
        'type': SRUN_TYPE,
        'os': 'windows+10',
        'name': 'windows',
        'double_stack': '0',
        '_': int(time.time() * 1000)
    }
    try:
        res = session.get(SRUN_PORTAL_API, params=params, headers=HEADER, timeout=10)
        res.raise_for_status()
        # Parse the JSONP response
        match = re.search(r'jQuery\d+\((.*)\)', res.text)
        if match:
            result = json.loads(match.group(1))
            if result.get('res') == 'ok':
                logger.info("Authentication Successful!")
                return True
            else:
                logger.error(f"Login Failed: {result.get('error_msg', 'Unknown Error')}")
        else:
            logger.error(f"Unexpected Login Response: {res.text[:100]}")
        return False
    except Exception as e:
        logger.error(f"Error during login request: {e}")
        return False

def authenticate():
    """Higher-level auth flow with retries."""
    with requests.Session() as session:
        for attempt in range(MAX_RETRIES):
            logger.info(f"Authentication attempt {attempt + 1}/{MAX_RETRIES}...")
            if fetch_ip(session) and fetch_token(session):
                prepare_payloads()
                if do_login(session):
                    return True
            if attempt < MAX_RETRIES - 1:
                logger.info(f"Waiting {RETRY_DELAY}s before next attempt...")
                time.sleep(RETRY_DELAY)
    return False

def check_env():
    missing = []
    for var in ['USERNAME', 'PASSWORD']:
        if not os.getenv(var):
            missing.append(var)
    if missing:
        logger.critical(f"Missing mandatory environment variables: {', '.join(missing)}")
        sys.exit(1)

def run():
    check_env()
    logger.info("--- SRUN Authenticator Pro v2.0 ---")
    logger.info(f"Target Portal: {INIT_URL}")
    logger.info(f"Check Interval: {SLEEP_TIME}s")
    
    with requests.Session() as health_session:
        while state['running']:
            if is_connected(health_session):
                logger.info("Internet connection is active.")
            else:
                logger.warning("No internet connection detected. Starting auth flow...")
                if not authenticate():
                    logger.error("All authentication attempts failed. Will retry next cycle.")
            
            # Use a smaller sleep loop to allow for faster signal response
            for _ in range(SLEEP_TIME):
                if not state['running']: break
                time.sleep(1)

if __name__ == '__main__':
    run()
