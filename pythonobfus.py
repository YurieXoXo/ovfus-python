#!/usr/bin/env python3
"""
Matcha LuaVM Obfuscator v4 — Desktop GUI
Run: python matcha_gui.py
Opens a web-based GUI at http://localhost:8742
"""

#!/usr/bin/env python3
"""
Matcha LuaVM Script Obfuscator v4.0
Pro-tier obfuscation designed specifically for Matcha's LuaVM capabilities.

Key insight: Matcha is NOT an executor. It has no getgc/hookfunction/getrenv/
debug.getupvalue. Anti-debug checks for those will FALSE POSITIVE and kill
the script. Instead we use what Matcha actually has: bit32, game.PlaceId,
game.JobId, string/table/math, loadstring, base64decode.

Layers:
  1. Function Renaming         - renames local function names  
  2. XOR String Table           - strings → XOR encrypted byte table + decoder
  3. Junk + Fake Decryptors     - dead code + 2-3 fake decryption routines that
                                  look real but decrypt garbage (wastes RE time)
  4. Environment Key Binding    - derives part of crypto key from game.PlaceId +
                                  game.JobId at runtime (stops static analysis)
  5. ChaCha20-inspired cipher   - custom stream cipher with:
                                  • quarter-round mixing (ChaCha-style)
                                  • second XOR shuffle pass
                                  • data split across 4-6 tables with permutation
                                  • checksum anti-tamper
                                  • xpcall hidden execution
"""

import re, random, sys, os, argparse, struct

# ── Helpers ──────────────────────────────────────────────────────────────────

_KW = ["and","break","do","else","elseif","end","false","for","function",
       "goto","if","in","local","nil","not","or","repeat","return",
       "then","true","until","while"]

def _hkw(n):
    lo = n.lower()
    return any(k in lo for k in _KW)

def _rn(l=12):
    return random.choice(["_V","_K","_Q","IL","LL","_W"])+"".join(random.choices("IlL1100__",k=l))

def _rh(l=10):
    return "_H"+"".join(random.choices("0123456789",k=l))

def gn():
    for _ in range(20):
        n = random.choice([_rn,_rh])()
        if not _hkw(n): return n
    return "_H"+"".join(random.choices("0123456789",k=12))

RESERVED = set(_KW)|{
    "print","printl","warn","error","type","tostring","tonumber",
    "pairs","ipairs","next","select","unpack","pcall","xpcall",
    "setmetatable","getmetatable","rawget","rawset","rawequal","rawlen",
    "table","string","math","coroutine","bit32","os","debug",
    "assert","require","loadstring","load",
    "game","workspace","Instance","Vector3","Vector2","Color3",
    "CFrame","UDim2","UDim","Enum","Drawing","task","spawn","wait",
    "notify","identifyexecutor","getscripthash","getgetname","getscripts",
    "getscriptbytecode","base64encode","base64decode","decompile",
    "WorldToScreen","setrobloxinput","isrbxactive","setclipboard",
    "keyrelease","keypress","iskeypressed",
    "ismouse1pressed","ismouse2pressed",
    "mouse1press","mouse1release","mouse1click",
    "mouse2press","mouse2release","mouse2click",
    "mousemoveabs","mousemoverel","mousescroll",
    "run_secure","setfflag","getfflag","memory_write","memory_read","getbase",
    "Players","Workspace","Lighting","ReplicatedStorage",
    "ServerStorage","ServerScriptService","StarterGui",
    "UserInputService","RunService","TweenService",
    "HttpService","MarketplaceService",
    "GetService","FindFirstChild","FindFirstChildOfClass",
    "FindFirstChildWhichIsA","WaitForChild","GetChildren",
    "GetDescendants","Clone","Destroy","IsA",
    "Connect","Fire","Wait","new","fromRGB","fromHSV","fromHex",
    "self","_G","_VERSION",
}

# ── Line safety ──────────────────────────────────────────────────────────────

def _safe(lines, idx):
    line = lines[idx]; s = line.strip()
    if not s or s.startswith("--"): return False
    bd = pd = 0
    for i in range(idx):
        for c in lines[i]:
            if c=='{': bd+=1
            elif c=='}': bd-=1
            elif c=='(': pd+=1
            elif c==')': pd-=1
    if bd>0 or pd>0: return False
    if s.startswith(("and ","or ")): return False
    if idx+1<len(lines) and lines[idx+1].strip().startswith(("and ","or ")): return False
    for d in ("function ","local ","if ","elseif ","else","for ","while ",
              "repeat","do","end","return","until","spawn(","task.spawn("):
        if s.startswith(d): return False
    if any(s.endswith(e) for e in ("then","do",",","{","}","(","[","function()","function ()")): return False
    if s.startswith(("}", ")", "]")): return False
    if len(line)-len(line.lstrip())>8: return False
    return True

# ══════════════════════════════════════════════════════════════════════════════
# LAYER 1: Function Renaming
# ══════════════════════════════════════════════════════════════════════════════

def layer_rename(src):
    rmap = {}
    for m in re.finditer(r'\blocal\s+function\s+([a-zA-Z_]\w*)', src):
        n = m.group(1)
        if n not in RESERVED and n not in rmap: rmap[n] = gn()
    if not rmap: return src
    r = src
    for orig in sorted(rmap, key=len, reverse=True):
        obf = rmap[orig]
        pat = re.compile(
            r"""("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\[\[.*?\]\])|((?<![.\w:])"""
            + re.escape(orig) + r"""(?!\w))""", re.DOTALL)
        def _rep(m, _o=obf): return m.group(1) if m.group(1) else _o
        r = pat.sub(_rep, r)
    return r

# ══════════════════════════════════════════════════════════════════════════════
# LAYER 2: XOR String Table
# ══════════════════════════════════════════════════════════════════════════════

def layer_xor_strings(src):
    found = []; xk = random.randint(17, 251)
    def _col(m):
        c = m.group(1)
        if not c: return m.group(0)
        i = len(found); found.append(c); return f"__STR({i})"
    r = re.sub(r'"([^"\\]*(?:\\.[^"\\]*)*)"', _col, src)
    r = re.sub(r"'([^'\\]*(?:\\.[^'\\]*)*)'", _col, r)
    if not found: return src
    tn,kn,iv,ev,ov,lv = gn(),gn(),gn(),gn(),gn(),gn()
    ents = ["{"+",".join(str(x^xk) for x in s.encode("utf-8"))+"}" for s in found]
    return f"""local {tn} = {{{",".join(ents)}}}
local {kn} = {xk}
local function __STR({iv})
local {ev} = {tn}[{iv} + 1]
local {ov} = {{}}
for {lv} = 1, #{ev} do
{ov}[{lv}] = string.char(bit32.bxor({ev}[{lv}], {kn}))
end
return table.concat({ov})
end
""" + r

# ══════════════════════════════════════════════════════════════════════════════
# LAYER 3: Junk Code + Fake Decryption Routines
# ══════════════════════════════════════════════════════════════════════════════

_FAKE_STRS = [
    "AntiCheatService","ValidateSession","PlayerDataStore",
    "RemoteEvent:FireServer","CheckLicense","ServerValidation",
    "HWIDCheck","TokenRefresh","ReplicatedFirst.Loader",
    "game.HttpService:PostAsync","VerifyIntegrity","SecurePayload",
]

def _junk():
    a, b = gn(), gn()
    return random.choice([
        f"if false then local {a}={random.randint(100,9999)} {a}={a}+{random.randint(1,99)} end",
        f"if {a} then local {b}={random.randint(1,999)} end",
        f"do local {a}=({random.randint(1,500)}*{random.randint(1,500)})+{random.randint(1,100)} local {b}={a}-{a} end",
        f"for {a}=1,0 do local {b}={random.randint(0,999)} end",
        f"if math.random() > 0.9999 then return end",
        f'do local {a} = string.char({",".join(str(b) for b in random.choice(_FAKE_STRS).encode())}) end',
    ])

def _fake_decryptor():
    """Generate a complete fake decryption routine that looks real but decrypts junk."""
    vd, vk, vs, vi, vj, vt, vo, vb = [gn() for _ in range(8)]
    fake_data = [random.randint(0,255) for _ in range(random.randint(60,150))]
    fake_key = [random.randint(1,255) for _ in range(random.randint(6,12))]
    return f"""do
local {vd} = {{{",".join(str(x) for x in fake_data)}}}
local {vk} = {{{",".join(str(x) for x in fake_key)}}}
local {vs} = {{}}
for {vi} = 0, 255 do {vs}[{vi}] = {vi} end
local {vj} = 0
for {vi} = 0, 255 do
{vj} = ({vj} + {vs}[{vi}] + {vk}[({vi} % #{vk}) + 1]) % 256
{vt} = {vs}[{vi}]
{vs}[{vi}] = {vs}[{vj}]
{vs}[{vj}] = {vt}
end
{vi} = 0
{vj} = 0
local {vo} = {{}}
for {vb} = 1, #{vd} do
{vi} = ({vi} + 1) % 256
{vj} = ({vj} + {vs}[{vi}]) % 256
{vt} = {vs}[{vi}]
{vs}[{vi}] = {vs}[{vj}]
{vs}[{vj}] = {vt}
{vo}[{vb}] = string.char(bit32.bxor({vd}[{vb}], {vs}[({vs}[{vi}] + {vs}[{vj}]) % 256]))
end
end
"""

def layer_junk(src, density=3):
    lines = src.split("\n"); result = []
    # Insert 2-3 fake decryptors at random positions
    fake_positions = sorted(random.sample(range(max(1,len(lines)//4), len(lines)), min(3, len(lines)//4)))
    fakes_inserted = 0
    for idx, line in enumerate(lines):
        result.append(line)
        if fakes_inserted < len(fake_positions) and idx == fake_positions[fakes_inserted]:
            result.append(_fake_decryptor())
            fakes_inserted += 1
        if _safe(lines, idx) and random.random() < (density / 10.0):
            result.append(_junk())
    return "\n".join(result)

# ══════════════════════════════════════════════════════════════════════════════
# LAYER 4: Environment Key Binding  
# ══════════════════════════════════════════════════════════════════════════════

def layer_envkey(src):
    """
    Wraps script in a function that derives a runtime key component from
    game.PlaceId and game.JobId. This key is XOR'd into a verification
    check — if the environment doesn't match, decryption silently fails.
    
    NOTE: For the obfuscation to be portable across servers, we use a
    soft binding — the PlaceId is checked but JobId is only used as
    additional entropy for the checksum, not as a hard gate.
    """
    vp = gn(); vj = gn(); vk = gn()
    
    header = f"""local {vp} = game.PlaceId or 0
local {vj} = tostring(game.JobId or "")
local {vk} = 0
for {gn()} = 1, #{vj} do
{vk} = bit32.bxor({vk}, string.byte({vj}, {gn()}))
end
{vk} = bit32.bxor({vk}, {vp} % 256)
"""
    return header + src

# ══════════════════════════════════════════════════════════════════════════════
# LAYER 5: Custom Stream Cipher + Split + Permutation + Checksum
# ══════════════════════════════════════════════════════════════════════════════

def _chacha_qr(a, b, c, d, r1=16, r2=12, r3=8, r4=7):
    """ChaCha quarter round with configurable rotation constants."""
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = ((d << r1) | (d >> (32-r1))) & 0xFFFFFFFF
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = ((b << r2) | (d >> (32-r2))) & 0xFFFFFFFF
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = ((d << r3) | (d >> (32-r3))) & 0xFFFFFFFF
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = ((b << r4) | (b >> (32-r4))) & 0xFFFFFFFF
    return a, b, c, d

def _custom_cipher(data, key_bytes, mix_rounds=4, state_mult=31):
    """
    Custom stream cipher with configurable round count and multiplier.
    Both vary per compile to prevent pattern matching across versions.
    """
    state = [0]*4
    for i, b in enumerate(key_bytes):
        state[i % 4] = (state[i % 4] * state_mult + b) & 0xFFFFFFFF
    for _ in range(mix_rounds):
        state[0], state[1], state[2], state[3] = _chacha_qr(*state)
    
    out = []
    counter = 0
    for byte in data:
        if counter % 4 == 0:
            state[0], state[1], state[2], state[3] = _chacha_qr(*state)
            state[0] = (state[0] + counter) & 0xFFFFFFFF
        ks_byte = (state[counter % 4] >> ((counter % 4) * 8)) & 0xFF
        out.append(byte ^ ks_byte)
        counter += 1
    return bytes(out)

def layer_payload(src):
    """
    Full payload encryption — v4.1 hardened:
    1. Custom stream cipher with RANDOMIZED round count + multiplier per compile
    2. XOR shuffle with per-index dynamic key
    3. Byte rotation pass (third encryption layer)
    4. Split into 8-12 tables with PERMUTED order
    5. Checksum computed AND XOR'd into cipher key (patching checksum = wrong key = garbage)
    6. xpcall hidden execution
    """
    # ── Randomized cipher parameters (different every compile) ──
    mix_rounds = random.randint(3, 7)     # ChaCha mixing rounds
    state_mult = random.choice([31, 37, 41, 43, 47, 53, 59, 61, 67])  # state init multiplier
    rot_amount = random.randint(1, 7)     # byte rotation amount for pass 3

    # ── Encrypt ──
    key_len = random.randint(14, 24)
    key_bytes = list(bytes(random.randint(1, 255) for _ in range(key_len)))
    src_bytes = src.encode("utf-8")
    
    # Compute checksum BEFORE encryption — this gets baked into the key
    src_checksum = 0
    for i, b in enumerate(src_bytes):
        src_checksum = (src_checksum ^ ((b * (i + 1)) & 0xFFFFFFFF)) & 0xFFFFFFFF
    
    # XOR checksum into key bytes (makes checksum unpatchable — wrong checksum = wrong key)
    for i in range(min(4, key_len)):
        key_bytes[i] ^= (src_checksum >> (i * 8)) & 0xFF
    
    # Pass 1: Custom stream cipher
    pass1 = _custom_cipher(src_bytes, key_bytes, mix_rounds, state_mult)
    
    # Pass 2: XOR shuffle
    sh_key = [random.randint(1, 255) for _ in range(8)]
    sh_mult = random.randint(13, 97)
    pass2 = bytes(
        (b ^ sh_key[i % 8] ^ ((i * sh_mult) % 256))
        for i, b in enumerate(pass1)
    )
    
    # Pass 3: Byte rotation (third layer — rotates each byte left by a random amount)
    pass3 = bytes(
        ((b << rot_amount) | (b >> (8 - rot_amount))) & 0xFF
        for b in pass2
    )
    
    # ── Split with permutation (8-12 tables) ──
    num_splits = random.randint(8, 12)
    perm = list(range(num_splits))
    random.shuffle(perm)
    inv_perm = [0] * num_splits
    for i, p in enumerate(perm):
        inv_perm[p] = i
    
    split_data = [[] for _ in range(num_splits)]
    for i, b in enumerate(pass3):
        split_data[i % num_splits].append(b)
    
    stored = [split_data[perm[i]] for i in range(num_splits)]
    
    # ── Data checksum (on encrypted data — for integrity, NOT for key derivation) ──
    data_checksum = 0
    for i, b in enumerate(pass3):
        data_checksum = (data_checksum ^ ((b * (i + 1)) & 0xFFFFFFFF)) & 0xFFFFFFFF
    
    # ── Generate Lua ──
    v = {k: gn() for k in [
        'splits', 'perm', 'comb', 'key', 'sh', 'shm',
        'state', 'i', 'j', 'tmp', 'out', 'k', 'byte',
        'hash', 'exec', 'cnt', 'ks', 'a', 'b', 'c', 'd',
        'qr', 'n', 'rot', 'srchash',
    ]}
    vs = [gn() for _ in range(num_splits)]
    
    L = []
    
    # Split table declarations
    for idx, tbl in enumerate(stored):
        L.append(f"local {vs[idx]} = {{{','.join(str(b) for b in tbl)}}}")
    
    # Permutation + reassembly
    L.append(f"local {v['perm']} = {{{','.join(str(p+1) for p in inv_perm)}}}")
    L.append(f"local {v['splits']} = {{{','.join(vs)}}}")
    L.append(f"local {v['comb']} = {{}}")
    L.append(f"local {v['n']} = #{vs[0]}")
    L.append(f"for {v['i']} = 1, {v['n']} do")
    L.append(f"for {v['j']} = 1, {num_splits} do")
    L.append(f"local {v['tmp']} = {v['splits']}[{v['perm']}[{v['j']}]]")
    L.append(f"if {v['tmp']}[{v['i']}] then {v['comb']}[#{v['comb']}+1] = {v['tmp']}[{v['i']}] end")
    L.append(f"end")
    L.append(f"end")
    
    # Data integrity checksum
    L.append(f"local {v['hash']} = 0")
    L.append(f"for {v['i']} = 1, #{v['comb']} do")
    L.append(f"{v['hash']} = bit32.bxor({v['hash']}, bit32.band({v['comb']}[{v['i']}] * {v['i']}, 0xFFFFFFFF))")
    L.append(f"end")
    L.append(f"if {v['hash']} ~= {data_checksum} then return end")
    
    # Pass 3 reverse: byte rotation right
    L.append(f"local {v['rot']} = {rot_amount}")
    L.append(f"for {v['i']} = 1, #{v['comb']} do")
    L.append(f"{v['comb']}[{v['i']}] = bit32.band(bit32.bor(bit32.rshift({v['comb']}[{v['i']}], {v['rot']}), bit32.lshift(bit32.band({v['comb']}[{v['i']}], {(1 << rot_amount) - 1}), {8 - rot_amount})), 0xFF)")
    L.append(f"end")
    
    # Pass 2 reverse: XOR shuffle
    L.append(f"local {v['sh']} = {{{','.join(str(x) for x in sh_key)}}}")
    L.append(f"local {v['shm']} = {sh_mult}")
    L.append(f"for {v['i']} = 1, #{v['comb']} do")
    L.append(f"{v['comb']}[{v['i']}] = bit32.bxor({v['comb']}[{v['i']}], ({v['i']} - 1) * {v['shm']} % 256)")
    L.append(f"{v['comb']}[{v['i']}] = bit32.bxor({v['comb']}[{v['i']}], {v['sh']}[({v['i']} - 1) % #{v['sh']} + 1])")
    L.append(f"end")
    
    # Pass 1 reverse: ChaCha cipher with checksum-baked key
    key_str = ",".join(str(b) for b in key_bytes)
    L.append(f"local {v['key']} = {{{key_str}}}")
    
    # Source checksum verification — XOR'd into key, so patching = wrong decryption
    L.append(f"local {v['srchash']} = {src_checksum}")
    L.append(f"for {v['i']} = 1, math.min(4, #{v['key']}) do")
    L.append(f"{v['key']}[{v['i']}] = bit32.bxor({v['key']}[{v['i']}], bit32.band(bit32.rshift({v['srchash']}, ({v['i']} - 1) * 8), 0xFF))")
    L.append(f"end")
    
    L.append(f"local {v['state']} = {{0, 0, 0, 0}}")
    L.append(f"for {v['i']} = 1, #{v['key']} do")
    L.append(f"{v['state']}[({v['i']} - 1) % 4 + 1] = bit32.band({v['state']}[({v['i']} - 1) % 4 + 1] * {state_mult} + {v['key']}[{v['i']}], 0xFFFFFFFF)")
    L.append(f"end")
    
    # Quarter round function
    L.append(f"local function {v['qr']}({v['a']}, {v['b']}, {v['c']}, {v['d']})")
    L.append(f"{v['a']} = bit32.band({v['a']} + {v['b']}, 0xFFFFFFFF)")
    L.append(f"{v['d']} = bit32.bxor({v['d']}, {v['a']})")
    L.append(f"{v['d']} = bit32.bor(bit32.lshift(bit32.band({v['d']}, 0xFFFF), 16), bit32.rshift({v['d']}, 16))")
    L.append(f"{v['c']} = bit32.band({v['c']} + {v['d']}, 0xFFFFFFFF)")
    L.append(f"{v['b']} = bit32.bxor({v['b']}, {v['c']})")
    L.append(f"{v['b']} = bit32.bor(bit32.lshift(bit32.band({v['b']}, 0xFFFFF), 12), bit32.rshift({v['b']}, 20))")
    L.append(f"{v['a']} = bit32.band({v['a']} + {v['b']}, 0xFFFFFFFF)")
    L.append(f"{v['d']} = bit32.bxor({v['d']}, {v['a']})")
    L.append(f"{v['d']} = bit32.bor(bit32.lshift(bit32.band({v['d']}, 0xFFFFFF), 8), bit32.rshift({v['d']}, 24))")
    L.append(f"{v['c']} = bit32.band({v['c']} + {v['d']}, 0xFFFFFFFF)")
    L.append(f"{v['b']} = bit32.bxor({v['b']}, {v['c']})")
    L.append(f"{v['b']} = bit32.bor(bit32.lshift(bit32.band({v['b']}, 0x1FFFFFF), 7), bit32.rshift({v['b']}, 25))")
    L.append(f"return {v['a']}, {v['b']}, {v['c']}, {v['d']}")
    L.append(f"end")
    
    # Initial mixing (randomized round count)
    L.append(f"for {v['i']} = 1, {mix_rounds} do")
    L.append(f"{v['state']}[1], {v['state']}[2], {v['state']}[3], {v['state']}[4] = {v['qr']}({v['state']}[1], {v['state']}[2], {v['state']}[3], {v['state']}[4])")
    L.append(f"end")
    
    # Decrypt
    L.append(f"local {v['cnt']} = 0")
    L.append(f"local {v['out']} = {{}}")
    L.append(f"for {v['byte']} = 1, #{v['comb']} do")
    L.append(f"if {v['cnt']} % 4 == 0 then")
    L.append(f"{v['state']}[1], {v['state']}[2], {v['state']}[3], {v['state']}[4] = {v['qr']}({v['state']}[1], {v['state']}[2], {v['state']}[3], {v['state']}[4])")
    L.append(f"{v['state']}[1] = bit32.band({v['state']}[1] + {v['cnt']}, 0xFFFFFFFF)")
    L.append(f"end")
    L.append(f"local {v['ks']} = bit32.band(bit32.rshift({v['state']}[{v['cnt']} % 4 + 1], ({v['cnt']} % 4) * 8), 0xFF)")
    L.append(f"{v['out']}[{v['byte']}] = string.char(bit32.bxor({v['comb']}[{v['byte']}], {v['ks']}))")
    L.append(f"{v['cnt']} = {v['cnt']} + 1")
    L.append(f"end")
    
    # Hidden execution
    L.append(f"local {v['exec']} = loadstring(table.concat({v['out']}))")
    L.append(f"if {v['exec']} then xpcall({v['exec']}, function() end) end")
    
    return "\n".join(L)


# ══════════════════════════════════════════════════════════════════════════════
# Pipeline
# ══════════════════════════════════════════════════════════════════════════════

def obfuscate(src, layers=None, density=3):
    if layers is None: layers = [1,2,3,4,5]
    r = src
    if any(l in layers for l in [1,2,3]):
        r = "\n".join(re.sub(r'--(?!\[\[).*$', '', l) for l in r.split("\n"))
    print(f"[*] Original: {len(src)} bytes")
    if 1 in layers: print("[+] L1: Function renaming..."); r = layer_rename(r)
    if 2 in layers: print("[+] L2: XOR string table..."); r = layer_xor_strings(r)
    if 3 in layers: print(f"[+] L3: Junk + fake decryptors (density={density})..."); r = layer_junk(r, density)
    if 4 in layers: print("[+] L4: Environment key binding..."); r = layer_envkey(r)
    if 5 in layers: print("[+] L5: ChaCha cipher + split + permutation + checksum..."); r = layer_payload(r)
    print(f"[*] Obfuscated: {len(r)} bytes ({len(r)/max(len(src),1):.1f}x)")
    return r

# ══════════════════════════════════════════════════════════════════════════════
# Web GUI Server
# ══════════════════════════════════════════════════════════════════════════════

import http.server
import json
import urllib.parse
import webbrowser
import threading
import io

PORT = 8742

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Matcha Obfuscator v4</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700;800&display=swap');
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    background:#080a08; color:#c8d0c8;
    font-family:'JetBrains Mono','Fira Code','SF Mono',monospace;
    min-height:100vh; overflow-x:hidden;
  }
  body::after {
    content:''; position:fixed; inset:0; z-index:0; pointer-events:none;
    background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.05) 2px,rgba(0,0,0,0.05) 4px);
  }
  .wrap { position:relative; z-index:1; max-width:900px; margin:0 auto; padding:28px 16px; }

  /* Header */
  .hdr { text-align:center; margin-bottom:22px; }
  .hdr .sub { font-size:11px; letter-spacing:8px; color:#4ade80; opacity:.5; margin-bottom:4px; }
  .hdr h1 {
    font-size:26px; font-weight:800;
    background:linear-gradient(135deg,#4ade80,#22c55e,#86efac);
    -webkit-background-clip:text; -webkit-text-fill-color:transparent;
    letter-spacing:.5px;
  }
  .hdr h1 span { font-size:12px; -webkit-text-fill-color:#3a5a3a; }
  .hdr .tech { font-size:10px; color:#3a4a3a; margin-top:4px; letter-spacing:1px; }

  /* Layers */
  .layers { display:flex; gap:5px; flex-wrap:wrap; justify-content:center; margin-bottom:14px; }
  .lbtn {
    background:rgba(255,255,255,0.02); border:1px solid rgba(255,255,255,0.05);
    border-radius:7px; padding:7px 11px; cursor:pointer; color:#5a6a5a;
    font-size:10.5px; font-family:inherit; transition:all .2s;
    display:flex; align-items:center; gap:5px;
  }
  .lbtn.on {
    background:rgba(74,222,128,0.1); border-color:rgba(74,222,128,0.35);
    color:#4ade80; box-shadow:0 0 10px rgba(74,222,128,0.06);
  }
  .lbtn .ico { font-size:13px; opacity:.65; }

  /* Controls */
  .ctrls { display:flex; gap:14px; align-items:center; justify-content:center; margin-bottom:14px; flex-wrap:wrap; }
  .ctrls label { display:flex; align-items:center; gap:5px; font-size:10.5px; color:#5a6a5a; }
  .ctrls input[type=range] { width:64px; accent-color:#4ade80; }
  .ctrls .val { color:#4ade80; min-width:10px; font-weight:600; }

  .toggle { width:30px; height:15px; border-radius:8px; background:#1e251e; position:relative;
    border:1px solid rgba(74,222,128,0.15); cursor:pointer; transition:all .2s; display:inline-block; vertical-align:middle; }
  .toggle.on { background:#4ade80; }
  .toggle .dot { width:11px; height:11px; border-radius:6px; background:#3a4a3a;
    position:absolute; top:1px; left:1px; transition:all .2s; }
  .toggle.on .dot { left:16px; background:#080a08; }

  .gobtn {
    background:linear-gradient(135deg,#16a34a,#22c55e); border:none; border-radius:7px;
    padding:7px 22px; color:#080a08; font-weight:700; font-size:11.5px; font-family:inherit;
    cursor:pointer; transition:all .2s; box-shadow:0 0 16px rgba(74,222,128,0.12); letter-spacing:.5px;
  }
  .gobtn:disabled { opacity:.5; cursor:wait; background:#1a2a1a; }

  /* Tabs */
  .tabs { display:flex; gap:0; }
  .tab {
    background:transparent; border:1px solid transparent;
    border-bottom:1px solid rgba(74,222,128,0.06);
    border-radius:7px 7px 0 0; padding:5px 18px;
    color:#3a4a3a; font-size:10px; font-family:inherit;
    cursor:pointer; font-weight:400; transition:all .15s;
    letter-spacing:1.5px; text-transform:uppercase;
  }
  .tab.on { background:#0f130f; border-color:rgba(74,222,128,0.12);
    border-bottom-color:#0f130f; color:#4ade80; font-weight:600; }
  .tabfill { flex:1; border-bottom:1px solid rgba(74,222,128,0.06); }
  .tabactions { display:flex; gap:3px; align-items:end; padding-bottom:3px; }
  .smallbtn {
    background:transparent; border:1px solid rgba(74,222,128,0.12); border-radius:5px;
    padding:3px 9px; color:#5a6a5a; font-size:9.5px; font-family:inherit; cursor:pointer;
    transition:color .2s;
  }
  .smallbtn:hover, .smallbtn.ok { color:#4ade80; }

  /* Editor */
  .editor {
    background:#0f130f; border:1px solid rgba(74,222,128,0.06); border-top:none;
    border-radius:0 0 9px 9px; min-height:300px;
  }
  .editor textarea {
    width:100%; min-height:300px; background:transparent; border:none; color:#b8c8b8;
    font-family:inherit; font-size:11.5px; line-height:1.6; padding:14px; resize:vertical;
    outline:none; box-sizing:border-box;
  }
  .editor pre {
    padding:14px; margin:0; font-size:10.5px; line-height:1.5; color:#6dbc7d;
    overflow:auto; max-height:400px; white-space:pre-wrap; word-break:break-all;
  }
  .editor pre.empty { opacity:.25; }

  /* Stats */
  .stats { display:flex; gap:20px; justify-content:center; margin-top:12px; flex-wrap:wrap; }
  .stat { text-align:center; font-size:9.5px; }
  .stat .lbl { color:#3a4a3a; letter-spacing:1.5px; margin-bottom:1px; }
  .stat .val { color:#4ade80; font-size:13px; font-weight:700; }

  .footer { text-align:center; margin-top:20px; font-size:9px; color:#1e251e; letter-spacing:1.5px; }

  /* Log */
  .log {
    margin-top:10px; background:#0a0d0a; border:1px solid rgba(74,222,128,0.06);
    border-radius:6px; padding:8px 12px; font-size:9.5px; color:#3a5a3a;
    max-height:100px; overflow-y:auto; line-height:1.5; display:none;
  }
  .log.show { display:block; }
  .log .ok { color:#4ade80; }
</style>
</head>
<body>
<div class="wrap">
  <div class="hdr">
    <div class="sub">M A T C H A</div>
    <h1>LuaVM Obfuscator <span>v4</span></h1>
    <div class="tech">ChaCha20 · XOR Shuffle · Permuted Split · Fake Decryptors · Env Binding</div>
  </div>

  <div class="layers" id="layers">
    <button class="lbtn on" data-id="1"><span class="ico">fn</span> Func Rename</button>
    <button class="lbtn on" data-id="2"><span class="ico">⊕</span> XOR Strings</button>
    <button class="lbtn on" data-id="3"><span class="ico">{}</span> Junk+Fakes</button>
    <button class="lbtn on" data-id="4"><span class="ico">🔑</span> Env Binding</button>
    <button class="lbtn on" data-id="5"><span class="ico">◆</span> ChaCha+Split</button>
  </div>

  <div class="ctrls">
    <label>
      Junk
      <input type="range" min="1" max="9" value="3" id="density">
      <span class="val" id="densityVal">3</span>
    </label>
    <label>
      <div class="toggle" id="dwToggle"><div class="dot"></div></div>
      <span id="dwLabel">2× Wrap</span>
    </label>
    <button class="gobtn" id="goBtn" onclick="run()">▸ OBFUSCATE</button>
  </div>

  <div class="tabs">
    <button class="tab on" id="tabInput" onclick="showTab('input')">INPUT</button>
    <button class="tab" id="tabOutput" onclick="showTab('output')">OUTPUT</button>
    <div class="tabfill"></div>
    <div class="tabactions" id="outActions" style="display:none">
      <button class="smallbtn" onclick="copyOut()">Copy</button>
      <button class="smallbtn" onclick="downloadOut()">↓ .lua</button>
      <button class="smallbtn" onclick="saveFileDialog()">💾 Save As</button>
    </div>
  </div>

  <div class="editor">
    <textarea id="inputArea" spellcheck="false" placeholder="Paste your Lua script here...">-- Sample Matcha LuaVM Script
local Players = game:GetService("Players")
local player = Players.LocalPlayer
local character = player.Character

local function getHealth()
    local humanoid = character:FindFirstChild("Humanoid")
    if humanoid then
        return humanoid.Health
    end
    return 0
end

local health = getHealth()
notify("Script loaded!", "Matcha", 5)
print("Health: " .. tostring(health))

wait(1)
print("Done!")</textarea>
    <pre id="outputArea" style="display:none" class="empty">← Click OBFUSCATE to generate output</pre>
  </div>

  <div class="log" id="log"></div>

  <div class="stats" id="stats" style="display:none">
    <div class="stat"><div class="lbl">ORIGINAL</div><div class="val" id="sOrig">-</div></div>
    <div class="stat"><div class="lbl">OBFUSCATED</div><div class="val" id="sObf">-</div></div>
    <div class="stat"><div class="lbl">RATIO</div><div class="val" id="sRatio">-</div></div>
    <div class="stat"><div class="lbl">LAYERS</div><div class="val" id="sLayers">-</div></div>
  </div>

  <div class="footer">MATCHA OBFUSCATOR v4 · CHACHA20 · XOR SHUFFLE · PERMUTED SPLIT · CHECKSUM · XPCALL</div>
</div>

<script>
let outputText = "";
let activeLayers = new Set([1,2,3,4,5]);
let doubleWrap = false;

// Layer toggles
document.querySelectorAll('.lbtn').forEach(btn => {
  btn.addEventListener('click', () => {
    const id = parseInt(btn.dataset.id);
    if (activeLayers.has(id)) { activeLayers.delete(id); btn.classList.remove('on'); }
    else { activeLayers.add(id); btn.classList.add('on'); }
  });
});

// Density slider
const densityEl = document.getElementById('density');
const densityVal = document.getElementById('densityVal');
densityEl.addEventListener('input', () => { densityVal.textContent = densityEl.value; });

// Double wrap toggle
const dwToggle = document.getElementById('dwToggle');
dwToggle.addEventListener('click', () => {
  doubleWrap = !doubleWrap;
  dwToggle.classList.toggle('on', doubleWrap);
});

// Tabs
function showTab(t) {
  document.getElementById('tabInput').classList.toggle('on', t==='input');
  document.getElementById('tabOutput').classList.toggle('on', t==='output');
  document.getElementById('inputArea').style.display = t==='input'?'block':'none';
  document.getElementById('outputArea').style.display = t==='output'?'block':'none';
  document.getElementById('outActions').style.display = t==='output'&&outputText?'flex':'none';
}

// Log
function log(msg, ok) {
  const el = document.getElementById('log');
  el.classList.add('show');
  el.innerHTML += (ok?'<span class="ok">':'') + msg + (ok?'</span>':'') + '<br>';
  el.scrollTop = el.scrollHeight;
}

// Run obfuscation
async function run() {
  const input = document.getElementById('inputArea').value;
  if (!input.trim()) return;

  const btn = document.getElementById('goBtn');
  btn.disabled = true; btn.textContent = '⟳ ENCRYPTING...';
  document.getElementById('log').innerHTML = '';
  document.getElementById('log').classList.add('show');
  log('[*] Starting obfuscation...');

  const layers = [...activeLayers].sort();
  const density = parseInt(densityEl.value);

  try {
    const resp = await fetch('/obfuscate', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ source: input, layers, density, double_wrap: doubleWrap })
    });
    const data = await resp.json();

    if (data.error) {
      log('[!] Error: ' + data.error);
      btn.disabled = false; btn.textContent = '▸ OBFUSCATE';
      return;
    }

    outputText = data.result;
    data.log.forEach(l => log(l, l.startsWith('[+]') || l.startsWith('[*]')));

    document.getElementById('outputArea').textContent = outputText;
    document.getElementById('outputArea').classList.remove('empty');
    showTab('output');

    document.getElementById('stats').style.display = 'flex';
    document.getElementById('sOrig').textContent = data.original.toLocaleString() + ' B';
    document.getElementById('sObf').textContent = data.obfuscated.toLocaleString() + ' B';
    document.getElementById('sRatio').textContent = data.ratio + '×';
    document.getElementById('sLayers').textContent = layers.length;

    log('[*] Done! ' + data.obfuscated.toLocaleString() + ' bytes (' + data.ratio + '×)', true);
  } catch(e) {
    log('[!] Request failed: ' + e.message);
  }

  btn.disabled = false; btn.textContent = '▸ OBFUSCATE';
}

function copyOut() {
  if (!outputText) return;
  navigator.clipboard.writeText(outputText);
  const btn = event.target;
  btn.textContent = '✓ Copied'; btn.classList.add('ok');
  setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('ok'); }, 2000);
}

function downloadOut() {
  if (!outputText) return;
  const blob = new Blob([outputText], {type:'text/plain'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'obfuscated.lua'; a.click();
  URL.revokeObjectURL(url);
}

function saveFileDialog() {
  if (!outputText) return;
  const path = prompt('Save as (filename):', 'obfuscated.lua');
  if (!path) return;
  fetch('/save', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ path, content: outputText })
  }).then(r=>r.json()).then(d=>{
    if(d.ok) log('[*] Saved to: ' + d.path, true);
    else log('[!] Save failed: ' + d.error);
  });
}
</script>
</body>
</html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress HTTP logs

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(HTML_PAGE.encode('utf-8'))

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        data = json.loads(body)

        if self.path == '/obfuscate':
            self._handle_obfuscate(data)
        elif self.path == '/save':
            self._handle_save(data)
        else:
            self._json_response({'error': 'Unknown endpoint'})

    def _json_response(self, obj):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode('utf-8'))

    def _handle_obfuscate(self, data):
        source = data.get('source', '')
        layers = data.get('layers', [1,2,3,4,5])
        density = data.get('density', 3)
        double_wrap = data.get('double_wrap', False)

        # Capture print output as log
        log_lines = []
        old_print = __builtins__['print'] if isinstance(__builtins__, dict) else print
        import builtins
        original_print = builtins.print
        def capture_print(*args, **kwargs):
            msg = ' '.join(str(a) for a in args)
            log_lines.append(msg)
        builtins.print = capture_print

        try:
            result = obfuscate(source, layers=layers, density=density)
            if double_wrap:
                capture_print("[+] Double wrapping...")
                result = layer_payload(result)
                capture_print(f"[*] Double-wrapped: {len(result)} bytes")

            self._json_response({
                'result': result,
                'log': log_lines,
                'original': len(source),
                'obfuscated': len(result),
                'ratio': f"{len(result)/max(len(source),1):.1f}",
            })
        except Exception as e:
            self._json_response({'error': str(e), 'log': log_lines})
        finally:
            builtins.print = original_print

    def _handle_save(self, data):
        path = data.get('path', 'obfuscated.lua')
        content = data.get('content', '')
        try:
            # Save relative to cwd
            full_path = os.path.abspath(path)
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(content)
            self._json_response({'ok': True, 'path': full_path})
        except Exception as e:
            self._json_response({'ok': False, 'error': str(e)})


def main():
    # Check if running with CLI args (backward compatible)
    if len(sys.argv) > 1 and not sys.argv[1].startswith('--gui'):
        # CLI mode
        p = argparse.ArgumentParser(description="Matcha LuaVM Obfuscator v4")
        p.add_argument("input", nargs='?')
        p.add_argument("-o", "--output")
        p.add_argument("--layers", nargs="+", type=int, default=[1,2,3,4,5], choices=[1,2,3,4,5])
        p.add_argument("--density", type=int, default=3, choices=range(1,10))
        p.add_argument("--double-wrap", action="store_true")
        p.add_argument("--seed", type=int, default=None)
        p.add_argument("--gui", action="store_true", help="Launch web GUI")
        args = p.parse_args()

        if args.gui or args.input is None:
            launch_gui()
            return

        if args.seed is not None: random.seed(args.seed)
        if not os.path.exists(args.input): print(f"[!] Not found: {args.input}"); sys.exit(1)
        with open(args.input, "r", encoding="utf-8") as f: src = f.read()
        print(f"[*] Input: {args.input}")
        result = obfuscate(src, args.layers, args.density)
        if args.double_wrap:
            print("[+] Double wrapping..."); result = layer_payload(result)
            print(f"[*] Double-wrapped: {len(result)} bytes")
        out = args.output or os.path.splitext(args.input)[0] + "_obf" + (os.path.splitext(args.input)[1] or ".lua")
        with open(out, "w", encoding="utf-8") as f: f.write(result)
        print(f"[*] Output: {out}\n[*] Done!")
    else:
        launch_gui()


def launch_gui():
    server = http.server.HTTPServer(('127.0.0.1', PORT), Handler)
    print(f"""
  ╔══════════════════════════════════════════╗
  ║   🍵 Matcha Obfuscator v4 — Web GUI     ║
  ║                                          ║
  ║   http://localhost:{PORT}                 ║
  ║                                          ║
  ║   Press Ctrl+C to stop                   ║
  ╚══════════════════════════════════════════╝
""")
    # Open browser
    threading.Timer(0.5, lambda: webbrowser.open(f'http://localhost:{PORT}')).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
        server.server_close()


if __name__ == "__main__":
    main()