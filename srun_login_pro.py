#!/usr/bin/env python3
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
from typing import Optional, Dict, Any

# --- Configuration & Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    stream=sys.stdout
)

# Configuration from Environment Variables (preferred)
USERNAME = os.getenv('USERNAME', '').strip()
PASSWORD = os.getenv('PASSWORD', '').strip()
INIT_URL = os.getenv('INIT_URL', os.getenv('init_url', '')).strip()
GET_CHALLENGE_API = os.getenv('GET_CHALLENGE_API', os.getenv('get_challenge_api', '')).strip()
SRUN_PORTAL_API = os.getenv('SRUN_PORTAL_API', os.getenv('srun_portal_api', '')).strip()
GET_IP_API = os.getenv('GET_IP_API', os.getenv('get_ip_api', '')).strip()
SLEEP_TIME = int(os.getenv('SLEEP_TIME', '300'))

HEADER = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

# SRUN Constants
SRUN_N = '200'
SRUN_TYPE = '1'
SRUN_AC_ID = '1'
SRUN_ENC_VER = "srun_bx1"
ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"

# Global State (will be updated during execution)
state = {
    'ip': '',
    'token': '',
    'hmd5': '',
    'chksum': '',
    'info': ''
}

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

def fetch_ip() -> bool:
    try:
        res = requests.get(GET_IP_API, timeout=10)
        res.raise_for_status()
        match = re.search(r'jQuery\d+\((.*)\)', res.text)
        if not match:
            logging.error(f"Failed to parse IP from response: {res.text[:100]}")
            return False
        data = json.loads(match.group(1))
        state['ip'] = data.get('client_ip') or data.get('online_ip')
        if not state['ip']:
            logging.error("No IP found in response data")
            return False
        logging.info(f"Detected IP: {state['ip']}")
        return True
    except Exception as e:
        logging.error(f"Error fetching IP: {e}")
        return False

def fetch_token() -> bool:
    params = {
        "callback": f"jQuery1124{int(time.time() * 1000)}",
        "username": USERNAME,
        "ip": state['ip'],
        "_": int(time.time() * 1000),
    }
    try:
        res = requests.get(GET_CHALLENGE_API, params=params, headers=HEADER, timeout=10)
        res.raise_for_status()
        match = re.search('"challenge":"(.*?)"', res.text)
        if not match:
            logging.error(f"Failed to fetch challenge token: {res.text[:100]}")
            return False
        state['token'] = match.group(1)
        logging.info(f"Token acquired: {state['token']}")
        return True
    except Exception as e:
        logging.error(f"Error fetching token: {e}")
        return False

def is_connected() -> bool:
    try:
        # Baidu is reliable for testing connectivity in CN
        requests.get("https://www.baidu.com", timeout=3)
        return True
    except:
        return False

def prepare_payloads():
    state['info'] = get_info()
    state['info'] = "{SRBX1}" + get_base64(get_xencode(state['info'], state['token']))
    state['hmd5'] = get_md5(PASSWORD, state['token'])
    state['chksum'] = get_chksum()

def do_login() -> bool:
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
        res = requests.get(SRUN_PORTAL_API, params=params, headers=HEADER, timeout=10)
        res.raise_for_status()
        logging.info(f"Login Response: {res.text}")
        return "login_ok" in res.text.lower()
    except Exception as e:
        logging.error(f"Error during login request: {e}")
        return False

def check_env():
    missing = []
    for var in ['USERNAME', 'PASSWORD', 'GET_CHALLENGE_API', 'SRUN_PORTAL_API', 'GET_IP_API']:
        if not os.getenv(var) and not globals().get(var):
            missing.append(var)
    if missing:
        logging.critical(f"Missing required configuration: {', '.join(missing)}")
        sys.exit(1)

def run():
    check_env()
    logging.info("SRUN Authenticator started.")
    while True:
        if is_connected():
            logging.info("Network is connected. Staying quiet.")
        else:
            logging.info("Network disconnected. Attempting authentication...")
            if fetch_ip() and fetch_token():
                prepare_payloads()
                if do_login():
                    logging.info("Authentication successful.")
                else:
                    logging.info("Authentication failed. Will retry later.")
        time.sleep(SLEEP_TIME)

if __name__ == '__main__':
    run()
