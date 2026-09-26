#!/usr/bin/env python3
"""
anticheat_client.py  (rebuilt source of DTA Broom v3.5)

This file is a reconstruction of the Python source packed into
DTA Broom v3_5.exe (PyInstaller 6.19.0 / Python 3.12.0).  ~90% of the code
was produced by a patched pycdc build; 6 functions with generator-expression
control flow that defeated pycdc were rewritten by hand from bytecode and are
marked with `# --- HAND-REBUILT FROM BYTECODE ---` above each `def`.

SHA-256 of the exe: 8062BB8484A29788FC11E40E5B5975C373DE9D279C436C0CD4A01D5A7C3DB4EE
Author (per docstring): O_Xenom
Backend: https://dta-backend-lf3q.onrender.com/anticheat
"""

# whole-module decompile failed
# --- HAND-REBUILT FROM BYTECODE ---
def _xor_deobfuscate_fb(data_b64, mask_b64):
    data = base64.b64decode(data_b64)
    mask = base64.b64decode(mask_b64)
    return bytes(d ^ mask[i % len(mask)] for i, d in enumerate(data))

def init_secrets():
    _FALLBACK_HMAC_KEY = _xor_deobfuscate_fb(_FALLBACK_KEY_DATA, _FALLBACK_KEY_MASK)
    _FALLBACK_ENDPOINT = _xor_deobfuscate_fb(_FALLBACK_EP_DATA, _FALLBACK_EP_MASK).decode('utf-8')

def get_endpoint():
    return _FALLBACK_ENDPOINT

def sign_payload(payload_json):
    sig = hmac.new(_FALLBACK_HMAC_KEY, payload_json.encode('utf-8'), hashlib.sha256).digest()
    return base64.b64encode(sig).decode('ascii')

def generate_nonce():
    return f'''{int(time.time() * 1000)}-{secrets.token_hex(16)}'''

# --- HAND-REBUILT FROM BYTECODE ---
def rate_limit_wait():
    """Bloqueia até que uma chamada seja permitida pelo rate limiter."""
    while True:
        with _fb_rate_lock:
            now = time.monotonic()
            _fb_rate_calls = [t for t in _fb_rate_calls if now - t < 30]
            if len(_fb_rate_calls) < 4:
                _fb_rate_calls.append(now)
                return
        time.sleep(0.5)

# --- HAND-REBUILT FROM BYTECODE ---
def _fb_json_default(obj):
    """Fallback para tipos que o json nao sabe serializar nativamente."""
    try:
        if isinstance(obj, (bytes, bytearray)):
            try:
                return obj.decode('utf-8', errors='replace')
            except Exception:
                return base64.b64encode(bytes(obj)).decode('ascii')
        if isinstance(obj, set):
            return list(obj)
        return str(obj)
    except Exception:
        return None

# --- HAND-REBUILT FROM BYTECODE ---
def _fb_sanitize_for_json(obj):
    """
    Percorre o payload garantindo que:
    - Chaves de dict são strings (JSON exige string keys).
    - Floats não-finitos (NaN, Infinity) viram None.
    - Tipos exóticos passam pelo _fb_json_default e viram string.
    """
    if isinstance(obj, dict):
        clean = {}
        for k, v in obj.items():
            key = k if isinstance(k, str) else str(k)
            clean[key] = _fb_sanitize_for_json(v)
        return clean
    if isinstance(obj, (list, tuple)):
        return [_fb_sanitize_for_json(v) for v in obj]
    if isinstance(obj, float):
        if obj != obj or obj in (float('inf'), float('-inf')):
            return None
        return obj
    if isinstance(obj, (str, int, bool)) or obj is None:
        return obj
    return _fb_json_default(obj)

# --- HAND-REBUILT FROM BYTECODE ---
def secure_post(url, payload, timeout=15):
    """Envia POST assinado com HMAC, nonce anti-replay e rate limiting."""
    global _fb_http_session
    if _fb_http_session is None:
        _fb_http_session = requests.Session()
        _fb_http_session.headers.update({
            'User-Agent': f'DTABroom/2.0 ({platform.system()} {platform.release()})',
        })
    rate_limit_wait()
    safe_payload = _fb_sanitize_for_json(payload)
    safe_payload['_nonce'] = generate_nonce()
    safe_payload['_ts'] = int(time.time())
    payload_json = json.dumps(
        safe_payload,
        ensure_ascii=False,
        sort_keys=True,
        allow_nan=False,
        default=_fb_json_default,
    )
    signature = sign_payload(payload_json)
    headers = {
        'Content-Type': 'application/json; charset=utf-8',
        'X-Anticheat-Signature': signature,
        'X-Anticheat-Nonce': safe_payload['_nonce'],
        'X-Anticheat-Timestamp': str(safe_payload['_ts']),
    }
    body = payload_json.encode('utf-8')
    return _fb_http_session.post(url, data=body, headers=headers, timeout=timeout, verify=True)

# --- HAND-REBUILT FROM BYTECODE ---
def sha256_of_file(path, block_size=65536):
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for block in iter(lambda: f.read(block_size), b''):
                h.update(block)
        return h.hexdigest()
    except Exception:
        return None

# --- HAND-REBUILT FROM BYTECODE ---
def _normalize(s):
    return (s or '').lower()

def _ps_query(command):
    try:
        out = subprocess.check_output([
            'powershell',
            '-NoProfile',
            '-Command',
            command], text = True, encoding = 'utf-8', stderr = subprocess.DEVNULL)
        return out.strip()
    except Exception:
        return None

# --- HAND-REBUILT FROM BYTECODE ---
def collect_process_metadata(proc):
    try:
        info = proc.as_dict(attrs=['pid', 'name', 'exe', 'cmdline', 'cwd',
                                    'username', 'num_threads', 'create_time'])
        proc_name = (info.get('name') or '').lower()
        if proc_name in _WHITELIST_LOWER:
            return None
        meta = {
            'pid': info.get('pid'),
            'name': info.get('name'),
            'exe': info.get('exe'),
            'cwd': info.get('cwd'),
            'username': info.get('username'),
            'num_threads': info.get('num_threads'),
            'create_time': None,
            'file_size': None,
            'sha256': None,
            'suspicious_reasons': [],
        }
        try:
            ct = info.get('create_time')
            if ct:
                meta['create_time'] = datetime.fromtimestamp(ct, timezone.utc).isoformat()
        except Exception:
            pass
        exe = meta.get('exe') or ''
        if exe and os.path.isfile(exe):
            meta['file_size'] = os.path.getsize(exe)
            meta['sha256'] = sha256_of_file(exe)
        lname = _normalize(meta.get('name'))
        lex = exe.lower()
        cmdline = info.get('cmdline') or []
        cmdline_str = str(cmdline).lower()
        for pat in NAME_BLACKLIST_PATTERNS:
            if pat in lname or pat in lex or pat in cmdline_str:
                meta['suspicious_reasons'].append(f'name_match:{pat}')
                break
        if any(k in lex for k in ('\\temp\\', '\\appdata\\', '\\local\\temp\\')):
            meta['suspicious_reasons'].append('exe_in_temp_or_appdata')
        if meta.get('sha256') in HASH_BLACKLIST:
            meta['suspicious_reasons'].append('hash_blacklist:' + HASH_BLACKLIST[meta['sha256']])
        return meta
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

def collect_process_evidence():
    evidence = {
        'timestamp': int(time.time()),
        'processes': [] }
    for proc in psutil.process_iter([
        'pid',
        'name',
        'exe',
        'cmdline',
        'cwd',
        'username',
        'num_threads',
        'create_time']):
        meta = collect_process_metadata(proc)
        if not meta:
            continue
        if not meta['suspicious_reasons']:
            continue
        evidence['processes'].append(meta)
    return evidence

# --- HAND-REBUILT FROM BYTECODE ---
def detect_vpn():
    result = {'vpn_processes': [], 'vpn_interfaces': [], 'raw_ipconfig_matches': []}
    try:
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                name = proc.info.get('name') or ''
                exe = proc.info.get('exe') or ''
                if (any(v in _normalize(name) for v in VPN_PROCESS_NAMES)
                        or any(v in _normalize(exe) for v in VPN_PROCESS_NAMES)):
                    result['vpn_processes'].append({
                        'pid': proc.info.get('pid'),
                        'name': name,
                        'exe': exe,
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        try:
            for ifname, addrs in psutil.net_if_addrs().items():
                if any(_normalize(pat) in _normalize(ifname) for pat in VPN_INTERFACE_PATTERNS):
                    result['vpn_interfaces'].append({
                        'ifname': ifname,
                        'addrs': [str(a.address) for a in addrs],
                    })
        except Exception:
            pass
        if platform.system().lower() == 'windows':
            try:
                out = subprocess.check_output(
                    ['ipconfig', '/all'],
                    stderr=subprocess.DEVNULL,
                    text=True,
                    encoding='utf-8',
                    errors='ignore',
                )
                lines = out.splitlines()
                suspicious_lines = [
                    ln.strip() for ln in lines
                    if any(k in ln.lower() for k in (
                        'tunnel adapter', 'tap-windows', 'ppp adapter',
                        'wireguard', 'wire guard', 'virtual', 'vpn',
                    ))
                ]
                result['raw_ipconfig_matches'] = suspicious_lines
            except Exception:
                pass
    except Exception:
        pass
    return result

# --- HAND-REBUILT FROM BYTECODE ---
def _get_primary_mac_prefix():
    try:
        for ifname, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if not hasattr(a, 'address') or not a.address:
                    continue
                if ':' not in a.address:
                    continue
                mac = a.address.replace(':', '').lower()
                return mac[:6]
        import uuid
        mac = f'{uuid.getnode():012x}'
        return mac[:6]
    except Exception:
        return None

# --- HAND-REBUILT FROM BYTECODE ---
def detect_vm():
    result = {'vm_processes': [], 'wmic_flags': [], 'mac_match': False, 'wmic_raw': None}
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            name = proc.info.get('name') or ''
            exe = proc.info.get('exe') or ''
            if (any(v in _normalize(name) for v in VM_PROCESS_NAMES)
                    or any(v in _normalize(exe) for v in VM_PROCESS_NAMES)):
                result['vm_processes'].append({
                    'pid': proc.info.get('pid'),
                    'name': name,
                    'exe': exe,
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if platform.system().lower() == 'windows':
        try:
            out = _ps_query('$cs = Get-CimInstance Win32_ComputerSystem; "$($cs.Manufacturer) $($cs.Model)"')
            if out:
                result['wmic_raw'] = out
                if any(k in out.lower() for k in ('vmware', 'virtualbox', 'vbox',
                                                  'qemu', 'xen', 'hyper-v',
                                                  'microsoft corporation')):
                    result['wmic_flags'].append(out)
        except Exception:
            pass
    prefix = _get_primary_mac_prefix()
    if prefix and prefix.lower() in VM_MAC_PREFIXES:
        result['mac_match'] = True
        result['mac_prefix'] = prefix
    return result

# --- HAND-REBUILT FROM BYTECODE ---
def is_self_running_in_vm():
    reasons = []
    is_vm = False
    wmic_raw = None
    if platform.system().lower() == 'windows':
        try:
            out = _ps_query('$cs = Get-CimInstance Win32_ComputerSystem; "$($cs.Manufacturer) $($cs.Model)"')
            if out:
                wmic_raw = out
                if any(k in out.lower() for k in ('vmware', 'virtualbox', 'vbox',
                                                  'qemu', 'xen', 'hyper-v',
                                                  'microsoft corporation')):
                    is_vm = True
                    reasons.append('wmic_match')
        except Exception:
            pass
    try:
        prefix = _get_primary_mac_prefix()
        if prefix and prefix.lower() in VM_MAC_PREFIXES:
            is_vm = True
            reasons.append('mac_match')
    except Exception:
        pass
    try:
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                name = proc.info.get('name') or ''
                exe = proc.info.get('exe') or ''
                if (any(v in _normalize(name) for v in VM_PROCESS_NAMES)
                        or any(v in _normalize(exe) for v in VM_PROCESS_NAMES)):
                    is_vm = True
                    reasons.append('vm_process')
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass
    return {'wmic': wmic_raw, 'is_vm': bool(is_vm), 'reasons': reasons}

def build_report(username, match_id, team_id):
    evidence = collect_process_evidence()
    vpn = detect_vpn()
    vm = detect_vm()
    self_vm = is_self_running_in_vm()
    report = {
        'username': username,
        'match_id': match_id,
        'team': team_id,
        'evidence': evidence,
        'vpn': vpn,
        'vm': vm,
        'self_vm': self_vm,
        'client_timestamp': int(time.time()),
        'client_time_iso': datetime.now(timezone.utc).isoformat() }
    return report

# --- HAND-REBUILT FROM BYTECODE ---
def _map_http_error(status_code, attempt=1):
    """Converte um status HTTP em codigo opaco. Nunca retorna o status real."""
    if status_code is None:
        return _ERR_REPORT_NETWORK
    if status_code == 200:
        return _ERR_OK
    if status_code == 400:
        return _ERR_REPORT_400_TRY1 if attempt == 1 else _ERR_REPORT_400_TRY2
    if status_code in (401, 403):
        return _ERR_REPORT_AUTH
    if status_code == 429:
        return _ERR_REPORT_RATE
    if 500 <= status_code < 600:
        return _ERR_REPORT_5XX
    return _ERR_REPORT_OTHER

# --- HAND-REBUILT FROM BYTECODE ---
def send_report(payload):
    """
    Envia o relatório para /insert_log com 1 retry em caso de 400.
    Retorna (status_code, response_text) para o main_loop, mas os logs
    contêm apenas códigos opacos - nada de body do servidor ou payload.
    """
    last_status, last_text = None, None
    for attempt in (1, 2):
        try:
            resp = secure_post(SERVER_ENDPOINT + '/insert_log', payload)
            last_status, last_text = resp.status_code, resp.text
            if resp.status_code == 200:
                logger.info('Report %s', _ERR_OK)
                return last_status, last_text
            code = _map_http_error(resp.status_code, attempt)
            logger.warning('Report %s', code)
            if resp.status_code != 400 or attempt == 2:
                return last_status, last_text
        except Exception:
            logger.warning('Report %s', _ERR_REPORT_NETWORK)
            last_status, last_text = None, None
            if attempt == 2:
                return last_status, last_text
    return last_status, last_text

# --- HAND-REBUILT FROM BYTECODE ---
def get_dbd_metadata():
    """
    Retorna informacoes sobre o processo do Dead by Daylight.
    Inclui se o jogo esta aberto e metadados do processo, se encontrado.
    """
    dbd_info = {
        'is_open': False, 'pid': None, 'name': None, 'exe': None,
        'cmdline': None, 'cwd': None, 'username': None,
        'num_threads': None, 'create_time': None, 'memory_rss': None,
    }
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cwd',
                                      'username', 'num_threads', 'create_time']):
        try:
            name = proc.info.get('name') or ''
            if 'deadbydaylight' in name.lower().strip().replace(' ', ''):
                dbd_info['is_open'] = True
                dbd_info['pid'] = proc.info.get('pid')
                dbd_info['name'] = name
                dbd_info['exe'] = proc.info.get('exe')
                dbd_info['cmdline'] = proc.info.get('cmdline')
                dbd_info['cwd'] = proc.info.get('cwd')
                dbd_info['username'] = proc.info.get('username')
                dbd_info['num_threads'] = proc.info.get('num_threads')
                dbd_info['create_time'] = proc.info.get('create_time')
                try:
                    dbd_info['memory_rss'] = getattr(proc.memory_info(), 'rss', None)
                except Exception:
                    pass
                return dbd_info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return dbd_info

# --- HAND-REBUILT FROM BYTECODE ---
def _drive_letter_iter():
    mask = GetLogicalDrives()
    if mask == 0:
        return
    for i in range(26):
        if mask & (1 << i):
            yield chr(ord('A') + i) + ':\\'

# --- HAND-REBUILT FROM BYTECODE ---
def get_removable_drives_basic():
    """
    Retorna lista de dicionarios com drives do tipo REMOVABLE (pendrives).
    Campos: drive, label, fs_type, serial, max_component_len, file_flags
    Windows-only.
    """
    drives = []
    try:
        for root in _drive_letter_iter():
            dtype = GetDriveTypeW(root)
            if dtype not in (DRIVE_REMOVABLE, DRIVE_FIXED):
                continue
            vol_name_buf = ctypes.create_unicode_buffer(261)
            fs_buf = ctypes.create_unicode_buffer(261)
            serial = wintypes.DWORD()
            max_comp_len = wintypes.DWORD()
            flags = wintypes.DWORD()
            success = GetVolumeInformationW(
                root, vol_name_buf, ctypes.sizeof(vol_name_buf),
                ctypes.byref(serial), ctypes.byref(max_comp_len),
                ctypes.byref(flags), fs_buf, ctypes.sizeof(fs_buf),
            )
            drives.append({
                'drive': root,
                'type': int(dtype),
                'label': vol_name_buf.value if success else None,
                'fs_type': fs_buf.value if success else None,
                'serial': f'{serial.value:08X}' if success else None,
                'max_component_len': max_comp_len.value if success else None,
                'file_flags': flags.value if success else None,
            })
    except Exception:
        pass
    return drives

# --- HAND-REBUILT FROM BYTECODE ---
def get_dbd_loaded_dlls():
    """
    Lista DLLs carregadas pelo processo do Dead by Daylight.
    Separa em whitelisted e unknown (nao reconhecidas).
    """
    result = {'dbd_found': False, 'unknown_dlls': [], 'total_dlls': 0, 'grouped': {}}
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info.get('name') or ''
            if 'deadbydaylight' in name.lower().strip().replace(' ', ''):
                result['dbd_found'] = True
                all_dlls = []
                try:
                    for mmap in proc.memory_maps(grouped=True):
                        path = mmap.path if hasattr(mmap, 'path') else str(mmap)
                        if not path or not path.lower().endswith('.dll'):
                            continue
                        all_dlls.append(path)
                except psutil.AccessDenied:
                    return {'dbd_found': True, 'unknown_dlls': ['[ACCESS_DENIED]'],
                            'total_dlls': 0, 'grouped': {}}
                result['total_dlls'] = len(all_dlls)
                for dll_path in all_dlls:
                    dll_name = os.path.basename(dll_path).lower()
                    if dll_name not in DBD_DLL_WHITELIST:
                        result['unknown_dlls'].append({'path': dll_path})
                return result
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return result

# --- HAND-REBUILT FROM BYTECODE ---
def detect_suspicious_windows():
    """
    Enumera janelas visiveis via EnumWindows e detecta:
    - Janelas com titulos suspeitos (cheats conhecidos)
    - Janelas com estilo overlay (TOPMOST + TRANSPARENT)
    """
    suspicious_titles = ('inject', 'overlay', 'cheat engine', 'ce main',
                         'ducts', 'imgui', 'd3d', 'directx overlay')
    result = {'suspicious_windows': [], 'overlay_windows': []}

    def enum_callback(hwnd, _lparam):
        try:
            length = user32.GetWindowTextLengthW(hwnd)
            if not user32.IsWindowVisible(hwnd) or length <= 0:
                return True
            buf = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buf, length + 1)
            title = buf.value or ''
            cls_buf = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, cls_buf, 256)
            cls_name = cls_buf.value or ''
            ex_style = user32.GetWindowLongW(hwnd, -20)  # GWL_EXSTYLE
            lower = title.lower()
            for pattern in suspicious_titles:
                if pattern in lower:
                    result['suspicious_windows'].append({
                        'pattern': f'pattern:{pattern}',
                        'title': title,
                        'class': cls_name,
                        'reason': 'title_match',
                    })
                    break
            if (ex_style & 0x00000008) and (ex_style & 0x00000020):  # TOPMOST | TRANSPARENT
                result['overlay_windows'].append({
                    'title': title,
                    'class': cls_name,
                    'ex_style': hex(ex_style),
                })
        except Exception:
            pass
        return True

    try:
        WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        user32.EnumWindows(WNDENUMPROC(enum_callback), 0)
    except Exception:
        pass
    return result

# --- HAND-REBUILT FROM BYTECODE ---
def get_hardware_fingerprint():
    """Coleta identificadores de hardware e nome do computador."""
    fp = {
        'computer_name': None, 'bios_uuid': None, 'motherboard_serial': None,
        'disk_serials': [], 'cpu_name': None, 'ram_total_gb': None, 'os_version': None,
    }
    try:
        fp['computer_name'] = platform.node()
    except Exception:
        pass
    try:
        fp['ram_total_gb'] = round(psutil.virtual_memory().total / (1024 ** 3))
    except Exception:
        pass
    try:
        fp['os_version'] = platform.version()
    except Exception:
        pass
    try:
        fp['bios_uuid'] = _ps_query('(Get-CimInstance Win32_ComputerSystemProduct).UUID')
    except Exception:
        pass
    try:
        fp['motherboard_serial'] = _ps_query('(Get-CimInstance Win32_BaseBoard).SerialNumber')
    except Exception:
        pass
    try:
        out = _ps_query('Get-CimInstance Win32_DiskDrive | ForEach-Object { "$($_.SerialNumber)|$($_.Model)" }')
        if out:
            for line in out.splitlines():
                if line.strip():
                    fp['disk_serials'].append(line.strip())
    except Exception:
        pass
    try:
        fp['cpu_name'] = _ps_query('(Get-CimInstance Win32_Processor).Name')
    except Exception:
        pass
    return fp

# --- HAND-REBUILT FROM BYTECODE ---
def detect_debuggers():
    """Detecta processos de debuggers/reverse engineering ativos."""
    result = {'debugger_attached': False, 'debugger_processes': []}
    try:
        result['debugger_attached'] = bool(ctypes.windll.kernel32.IsDebuggerPresent())
    except Exception:
        pass
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            name = proc.info.get('name') or ''
            exe = proc.info.get('exe') or ''
            lname = _normalize(name).replace('.exe', '')
            lexe = _normalize(exe)
            for dbg in DEBUGGER_PROCESS_NAMES:
                if dbg in lname or dbg in lexe:
                    result['debugger_processes'].append({
                        'pid': proc.info.get('pid'),
                        'name': name,
                        'exe': exe,
                    })
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return result

# --- HAND-REBUILT FROM BYTECODE ---
def detect_network_suspicious():
    """
    Analisa conexões de rede ativas e busca por:
    - Portas conhecidas de cheat/remote access
    - Processos de acesso remoto
    """
    result = {
        'suspicious_connections': [],
        'remote_access_processes': [],
        'total_established': 0,
    }
    try:
        connections = psutil.net_connections(kind='inet')
        established = [c for c in connections if c.status == 'ESTABLISHED']
        result['total_established'] = len(established)
        for conn in established:
            raddr = conn.raddr
            if not raddr:
                continue
            rport = raddr.port
            if rport not in SUSPICIOUS_REMOTE_PORTS:
                continue
            local = f'{conn.laddr.ip}:{conn.laddr.port}' if conn.laddr else None
            result['suspicious_connections'].append({
                'pid': conn.pid,
                'local': local,
                'remote': f'{raddr.ip}:{raddr.port}',
                'reason': f'suspicious_port:{rport}',
            })
    except (psutil.AccessDenied, Exception):
        pass
    try:
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                name = proc.info.get('name') or ''
                exe = proc.info.get('exe') or ''
                lname = _normalize(name).replace('.exe', '')
                lexe = _normalize(exe)
                for ra in REMOTE_ACCESS_PROCESS_NAMES:
                    if ra in lname or ra in lexe:
                        result['remote_access_processes'].append({
                            'pid': proc.info.get('pid'),
                            'name': name,
                            'exe': exe,
                        })
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass
    return result

def get_monitor_count():
    try:
        count = user32.GetSystemMetrics(80)
        return {
            'monitor_count': count }
    except Exception:
        return

# --- HAND-REBUILT FROM BYTECODE ---
def check_clock_sync():
    """Verifica se o relogio do PC esta sincronizado com o servidor.
    Compara time.time() com o header Date da resposta HTTP.
    """
    try:
        before = time.time()
        resp = requests.head('https://dta-backend-lf3q.onrender.com/', timeout=10)
        after = time.time()
        server_date = resp.headers.get('Date')
        if not server_date:
            return None
        try:
            from email.utils import parsedate_to_datetime
            server_time = parsedate_to_datetime(server_date).timestamp()
            client_time = (before + after) / 2
            skew = abs(client_time - server_time)
            if skew > 90:
                print(f'\n[AVISO] Seu relogio esta dessincronizado em {skew:.0f} segundos!')
                print('Isso impedira o funcionamento do anticheat.')
                print('Corrija em: Configuracoes > Hora e Idioma > Data e Hora > Sincronizar agora')
                print(f'Hora do servidor (UTC): {datetime.fromtimestamp(server_time, timezone.utc).strftime("%H:%M:%S")}')
                print(f'Hora do seu PC (UTC):   {datetime.fromtimestamp(client_time, timezone.utc).strftime("%H:%M:%S")}\n')
                logger.warning('CLOCK SKEW: %.1fs - usuario avisado', skew)
        except Exception:
            logger.debug('Clock ERR_CLK_101')
    except Exception:
        logger.debug('Clock ERR_CLK_101')
    return None

# --- HAND-REBUILT FROM BYTECODE ---
def request_credentials():
    while True:
        entrada = str(input('Insert the MATCH PASSWORD: ')).strip()
        if not re.match('.*[AB]$', entrada):
            print('Invalid format. Please try again.')
            logger.info('Invalid user entry format')
            continue
        logger.info('Valid user entry')
        team_letter = entrada[-1]
        match_pass = entrada[:-1]
        match_response = validate_match(match_pass)
        if not match_response or not match_response.get('success'):
            print('Invalid match password. Please try again.')
            logger.warning('Validate %s', _ERR_VALIDATE_REJECTED)
            continue
        match_data = match_response.get('response')
        if not match_data:
            print('Invalid match password. Please try again.')
            logger.warning('Validate %s', _ERR_VALIDATE_REJECTED)
            continue
        match_id = match_data.get('match_id')
        if team_letter == 'A':
            team_id = match_data.get('team1_id')
        else:
            team_id = match_data.get('team2_id')
        logger.info('Password validated')
        return match_id, team_id, match_pass

# --- HAND-REBUILT FROM BYTECODE ---
def validate_match(match_pass):
    """Valida match na API.  Retorna o dict completo (com 'success', 'response')
    na primeira chamada; nas chamadas subsequentes do loop principal retorna True/False.
    """
    logger.info('Validating match...')
    try:
        resp = secure_post(SERVER_ENDPOINT + '/validate', {'match_pass': match_pass})
        try:
            return resp.json()
        except Exception:
            logger.warning('Validate %s', _ERR_VALIDATE_REJECTED)
            return None
    except Exception:
        logger.warning('Validate %s', _ERR_VALIDATE_NETWORK)
        return None

# --- HAND-REBUILT FROM BYTECODE ---
def send_info_data(payload):
    try:
        resp = secure_post(SERVER_ENDPOINT, payload)
        try:
            match_response = resp.json()
        except Exception:
            logger.warning('Info %s', _ERR_INFO_REJECTED)
            return False
        if not match_response.get('success'):
            logger.warning('Info %s', _ERR_INFO_REJECTED)
            return False
        return True
    except Exception:
        logger.warning('Info %s', _ERR_INFO_NETWORK)
        return False

# --- HAND-REBUILT FROM BYTECODE ---
def request_username():
    username = ''
    while username == '':
        username = str(input('WebSite Username: '))
        pattern = re.compile('[a-zA-Z0-9_-]+')
        username = ''.join(re.findall(pattern, username))
        username = username.strip().replace(' ', '').lower()
    return username

def main_loop():
    check_clock_sync()
    (match_id, team_id, match_pass) = request_credentials()
    # WARNING: Decompyle incomplete

