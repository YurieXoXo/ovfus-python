import random
import re


class ObfuscationError(Exception):
    pass


_KW = [
    "and",
    "break",
    "do",
    "else",
    "elseif",
    "end",
    "false",
    "for",
    "function",
    "goto",
    "if",
    "in",
    "local",
    "nil",
    "not",
    "or",
    "repeat",
    "return",
    "then",
    "true",
    "until",
    "while",
]


def _has_keyword_fragment(name: str) -> bool:
    low = name.lower()
    return any(keyword in low for keyword in _KW)


def _rand_name_long(length: int = 12) -> str:
    return random.choice(["_V", "_K", "_Q", "IL", "LL", "_W"]) + "".join(
        random.choices("IlL1100__", k=length)
    )


def _rand_name_hash(length: int = 10) -> str:
    return "_H" + "".join(random.choices("0123456789", k=length))


def gen_name() -> str:
    for _ in range(20):
        name = random.choice([_rand_name_long, _rand_name_hash])()
        if not _has_keyword_fragment(name):
            return name
    return "_H" + "".join(random.choices("0123456789", k=12))


RESERVED = set(_KW) | {
    "print",
    "printl",
    "warn",
    "error",
    "type",
    "tostring",
    "tonumber",
    "pairs",
    "ipairs",
    "next",
    "select",
    "unpack",
    "pcall",
    "xpcall",
    "setmetatable",
    "getmetatable",
    "rawget",
    "rawset",
    "rawequal",
    "rawlen",
    "table",
    "string",
    "math",
    "coroutine",
    "bit32",
    "os",
    "debug",
    "assert",
    "require",
    "loadstring",
    "load",
    "game",
    "workspace",
    "Instance",
    "Vector3",
    "Vector2",
    "Color3",
    "CFrame",
    "UDim2",
    "UDim",
    "Enum",
    "Drawing",
    "task",
    "spawn",
    "wait",
    "notify",
    "identifyexecutor",
    "getscripthash",
    "getgetname",
    "getscripts",
    "getscriptbytecode",
    "base64encode",
    "base64decode",
    "decompile",
    "WorldToScreen",
    "setrobloxinput",
    "isrbxactive",
    "setclipboard",
    "keyrelease",
    "keypress",
    "iskeypressed",
    "ismouse1pressed",
    "ismouse2pressed",
    "mouse1press",
    "mouse1release",
    "mouse1click",
    "mouse2press",
    "mouse2release",
    "mouse2click",
    "mousemoveabs",
    "mousemoverel",
    "mousescroll",
    "run_secure",
    "setfflag",
    "getfflag",
    "memory_write",
    "memory_read",
    "getbase",
    "Players",
    "Workspace",
    "Lighting",
    "ReplicatedStorage",
    "ServerStorage",
    "ServerScriptService",
    "StarterGui",
    "UserInputService",
    "RunService",
    "TweenService",
    "HttpService",
    "MarketplaceService",
    "GetService",
    "FindFirstChild",
    "FindFirstChildOfClass",
    "FindFirstChildWhichIsA",
    "WaitForChild",
    "GetChildren",
    "GetDescendants",
    "Clone",
    "Destroy",
    "IsA",
    "Connect",
    "Fire",
    "Wait",
    "new",
    "fromRGB",
    "fromHSV",
    "fromHex",
    "self",
    "_G",
    "_VERSION",
}


def _is_safe_for_insertion(lines: list[str], idx: int) -> bool:
    line = lines[idx]
    stripped = line.strip()
    if not stripped or stripped.startswith("--"):
        return False

    brace_depth = 0
    paren_depth = 0
    for i in range(idx):
        for char in lines[i]:
            if char == "{":
                brace_depth += 1
            elif char == "}":
                brace_depth -= 1
            elif char == "(":
                paren_depth += 1
            elif char == ")":
                paren_depth -= 1
    if brace_depth > 0 or paren_depth > 0:
        return False

    if stripped.startswith(("and ", "or ")):
        return False
    if idx + 1 < len(lines) and lines[idx + 1].strip().startswith(("and ", "or ")):
        return False

    forbidden_prefixes = (
        "function ",
        "local ",
        "if ",
        "elseif ",
        "else",
        "for ",
        "while ",
        "repeat",
        "do",
        "end",
        "return",
        "until",
        "spawn(",
        "task.spawn(",
    )
    if stripped.startswith(forbidden_prefixes):
        return False

    forbidden_suffixes = ("then", "do", ",", "{", "}", "(", "[", "function()", "function ()")
    if any(stripped.endswith(suffix) for suffix in forbidden_suffixes):
        return False

    if stripped.startswith(("}", ")", "]")):
        return False

    if len(line) - len(line.lstrip()) > 8:
        return False

    return True


def layer_rename(src: str) -> str:
    rename_map: dict[str, str] = {}
    for match in re.finditer(r"\blocal\s+function\s+([a-zA-Z_]\w*)", src):
        name = match.group(1)
        if name not in RESERVED and name not in rename_map:
            rename_map[name] = gen_name()

    if not rename_map:
        return src

    result = src
    for original in sorted(rename_map, key=len, reverse=True):
        obfuscated = rename_map[original]
        pattern = re.compile(
            r"""("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\[\[.*?\]\])|((?<![.\w:])"""
            + re.escape(original)
            + r"""(?!\w))""",
            re.DOTALL,
        )

        def _replace(match, replacement=obfuscated):
            return match.group(1) if match.group(1) else replacement

        result = pattern.sub(_replace, result)
    return result


def layer_xor_strings(src: str) -> str:
    found: list[str] = []
    xor_key = random.randint(17, 251)

    def _collect(match):
        content = match.group(1)
        if not content:
            return match.group(0)
        index = len(found)
        found.append(content)
        return f"__STR({index})"

    result = re.sub(r'"([^"\\]*(?:\\.[^"\\]*)*)"', _collect, src)
    result = re.sub(r"'([^'\\]*(?:\\.[^'\\]*)*)'", _collect, result)

    if not found:
        return src

    table_name = gen_name()
    key_name = gen_name()
    index_var = gen_name()
    encrypted_var = gen_name()
    out_var = gen_name()
    loop_var = gen_name()
    entries = ["{" + ",".join(str(chunk ^ xor_key) for chunk in item.encode("utf-8")) + "}" for item in found]

    return (
        f"local {table_name} = {{{','.join(entries)}}}\n"
        f"local {key_name} = {xor_key}\n"
        f"local function __STR({index_var})\n"
        f"local {encrypted_var} = {table_name}[{index_var} + 1]\n"
        f"local {out_var} = {{}}\n"
        f"for {loop_var} = 1, #{encrypted_var} do\n"
        f"{out_var}[{loop_var}] = string.char(bit32.bxor({encrypted_var}[{loop_var}], {key_name}))\n"
        f"end\n"
        f"return table.concat({out_var})\n"
        f"end\n"
        + result
    )


_FAKE_STRS = [
    "AntiCheatService",
    "ValidateSession",
    "PlayerDataStore",
    "RemoteEvent:FireServer",
    "CheckLicense",
    "ServerValidation",
    "HWIDCheck",
    "TokenRefresh",
    "ReplicatedFirst.Loader",
    "game.HttpService:PostAsync",
    "VerifyIntegrity",
    "SecurePayload",
]


def _junk_snippet() -> str:
    var_a, var_b = gen_name(), gen_name()
    return random.choice(
        [
            f"if false then local {var_a}={random.randint(100,9999)} {var_a}={var_a}+{random.randint(1,99)} end",
            f"if {var_a} then local {var_b}={random.randint(1,999)} end",
            f"do local {var_a}=({random.randint(1,500)}*{random.randint(1,500)})+{random.randint(1,100)} local {var_b}={var_a}-{var_a} end",
            f"for {var_a}=1,0 do local {var_b}={random.randint(0,999)} end",
            "if math.random() > 0.9999 then return end",
            f'do local {var_a} = string.char({",".join(str(b) for b in random.choice(_FAKE_STRS).encode())}) end',
        ]
    )


def _fake_decryptor() -> str:
    var_d, var_k, var_s, var_i, var_j, var_t, var_o, var_b = [gen_name() for _ in range(8)]
    fake_data = [random.randint(0, 255) for _ in range(random.randint(60, 150))]
    fake_key = [random.randint(1, 255) for _ in range(random.randint(6, 12))]
    return (
        "do\n"
        f"local {var_d} = {{{','.join(str(x) for x in fake_data)}}}\n"
        f"local {var_k} = {{{','.join(str(x) for x in fake_key)}}}\n"
        f"local {var_s} = {{}}\n"
        f"for {var_i} = 0, 255 do {var_s}[{var_i}] = {var_i} end\n"
        f"local {var_j} = 0\n"
        f"for {var_i} = 0, 255 do\n"
        f"{var_j} = ({var_j} + {var_s}[{var_i}] + {var_k}[({var_i} % #{var_k}) + 1]) % 256\n"
        f"{var_t} = {var_s}[{var_i}]\n"
        f"{var_s}[{var_i}] = {var_s}[{var_j}]\n"
        f"{var_s}[{var_j}] = {var_t}\n"
        "end\n"
        f"{var_i} = 0\n"
        f"{var_j} = 0\n"
        f"local {var_o} = {{}}\n"
        f"for {var_b} = 1, #{var_d} do\n"
        f"{var_i} = ({var_i} + 1) % 256\n"
        f"{var_j} = ({var_j} + {var_s}[{var_i}]) % 256\n"
        f"{var_t} = {var_s}[{var_i}]\n"
        f"{var_s}[{var_i}] = {var_s}[{var_j}]\n"
        f"{var_s}[{var_j}] = {var_t}\n"
        f"{var_o}[{var_b}] = string.char(bit32.bxor({var_d}[{var_b}], {var_s}[({var_s}[{var_i}] + {var_s}[{var_j}]) % 256]))\n"
        "end\n"
        "end\n"
    )


def layer_junk(src: str, density: int = 3) -> str:
    lines = src.split("\n")
    result: list[str] = []

    available = list(range(max(1, len(lines) // 4), len(lines)))
    fake_count = min(3, len(lines) // 4)
    fake_positions = sorted(random.sample(available, fake_count)) if fake_count and available else []

    fake_idx = 0
    for idx, line in enumerate(lines):
        result.append(line)
        if fake_idx < len(fake_positions) and idx == fake_positions[fake_idx]:
            result.append(_fake_decryptor())
            fake_idx += 1
        if _is_safe_for_insertion(lines, idx) and random.random() < (density / 10.0):
            result.append(_junk_snippet())

    return "\n".join(result)


def layer_envkey(src: str) -> str:
    place_var = gen_name()
    job_var = gen_name()
    key_var = gen_name()
    loop_var = gen_name()
    return (
        f"local {place_var} = game.PlaceId or 0\n"
        f"local {job_var} = tostring(game.JobId or \"\")\n"
        f"local {key_var} = 0\n"
        f"for {loop_var} = 1, #{job_var} do\n"
        f"{key_var} = bit32.bxor({key_var}, string.byte({job_var}, {loop_var}))\n"
        "end\n"
        f"{key_var} = bit32.bxor({key_var}, {place_var} % 256)\n"
        + src
    )


def _chacha_qr(a: int, b: int, c: int, d: int, r1: int = 16, r2: int = 12, r3: int = 8, r4: int = 7):
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = ((d << r1) | (d >> (32 - r1))) & 0xFFFFFFFF
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = ((b << r2) | (b >> (32 - r2))) & 0xFFFFFFFF
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = ((d << r3) | (d >> (32 - r3))) & 0xFFFFFFFF
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = ((b << r4) | (b >> (32 - r4))) & 0xFFFFFFFF
    return a, b, c, d


def _custom_cipher(data: bytes, key_bytes: list[int], mix_rounds: int = 4, state_mult: int = 31) -> bytes:
    state = [0] * 4
    for idx, chunk in enumerate(key_bytes):
        state[idx % 4] = (state[idx % 4] * state_mult + chunk) & 0xFFFFFFFF
    for _ in range(mix_rounds):
        state[0], state[1], state[2], state[3] = _chacha_qr(*state)

    out = []
    counter = 0
    for byte in data:
        if counter % 4 == 0:
            state[0], state[1], state[2], state[3] = _chacha_qr(*state)
            state[0] = (state[0] + counter) & 0xFFFFFFFF
        key_stream_byte = (state[counter % 4] >> ((counter % 4) * 8)) & 0xFF
        out.append(byte ^ key_stream_byte)
        counter += 1
    return bytes(out)


def layer_payload(src: str) -> str:
    mix_rounds = random.randint(3, 7)
    state_mult = random.choice([31, 37, 41, 43, 47, 53, 59, 61, 67])
    rot_amount = random.randint(1, 7)

    key_len = random.randint(14, 24)
    key_bytes = list(bytes(random.randint(1, 255) for _ in range(key_len)))
    source_bytes = src.encode("utf-8")

    source_checksum = 0
    for idx, byte in enumerate(source_bytes):
        source_checksum = (source_checksum ^ ((byte * (idx + 1)) & 0xFFFFFFFF)) & 0xFFFFFFFF

    for idx in range(min(4, key_len)):
        key_bytes[idx] ^= (source_checksum >> (idx * 8)) & 0xFF

    pass1 = _custom_cipher(source_bytes, key_bytes, mix_rounds, state_mult)

    shuffle_key = [random.randint(1, 255) for _ in range(8)]
    shuffle_mult = random.randint(13, 97)
    pass2 = bytes(
        (byte ^ shuffle_key[idx % 8] ^ ((idx * shuffle_mult) % 256))
        for idx, byte in enumerate(pass1)
    )

    pass3 = bytes(
        ((byte << rot_amount) | (byte >> (8 - rot_amount))) & 0xFF
        for byte in pass2
    )

    split_count = random.randint(8, 12)
    perm = list(range(split_count))
    random.shuffle(perm)
    inv_perm = [0] * split_count
    for idx, p in enumerate(perm):
        inv_perm[p] = idx

    split_data = [[] for _ in range(split_count)]
    for idx, byte in enumerate(pass3):
        split_data[idx % split_count].append(byte)
    stored = [split_data[perm[idx]] for idx in range(split_count)]

    data_checksum = 0
    for idx, byte in enumerate(pass3):
        data_checksum = (data_checksum ^ ((byte * (idx + 1)) & 0xFFFFFFFF)) & 0xFFFFFFFF

    var = {
        key: gen_name()
        for key in [
            "splits",
            "perm",
            "comb",
            "key",
            "sh",
            "shm",
            "state",
            "i",
            "j",
            "tmp",
            "out",
            "byte",
            "hash",
            "exec",
            "cnt",
            "ks",
            "a",
            "b",
            "c",
            "d",
            "qr",
            "n",
            "rot",
            "srchash",
            "maxn",
        ]
    }
    split_vars = [gen_name() for _ in range(split_count)]

    lines: list[str] = []
    for idx, table in enumerate(stored):
        lines.append(f"local {split_vars[idx]} = {{{','.join(str(byte) for byte in table)}}}")

    lines.append(f"local {var['perm']} = {{{','.join(str(p + 1) for p in inv_perm)}}}")
    lines.append(f"local {var['splits']} = {{{','.join(split_vars)}}}")
    lines.append(f"local {var['comb']} = {{}}")
    lines.append(f"local {var['maxn']} = 0")
    lines.append(f"for {var['i']} = 1, #{var['splits']} do")
    lines.append(f"if #{var['splits']}[{var['i']}] > {var['maxn']} then {var['maxn']} = #{var['splits']}[{var['i']}] end")
    lines.append("end")
    lines.append(f"for {var['i']} = 1, {var['maxn']} do")
    lines.append(f"for {var['j']} = 1, {split_count} do")
    lines.append(f"local {var['tmp']} = {var['splits']}[{var['perm']}[{var['j']}]]")
    lines.append(f"if {var['tmp']}[{var['i']}] then {var['comb']}[#{var['comb']}+1] = {var['tmp']}[{var['i']}] end")
    lines.append("end")
    lines.append("end")

    lines.append(f"local {var['hash']} = 0")
    lines.append(f"for {var['i']} = 1, #{var['comb']} do")
    lines.append(
        f"{var['hash']} = bit32.bxor({var['hash']}, bit32.band({var['comb']}[{var['i']}] * {var['i']}, 0xFFFFFFFF))"
    )
    lines.append("end")
    lines.append(f"if {var['hash']} ~= {data_checksum} then return end")

    lines.append(f"local {var['rot']} = {rot_amount}")
    lines.append(f"for {var['i']} = 1, #{var['comb']} do")
    lines.append(
        f"{var['comb']}[{var['i']}] = bit32.band(bit32.bor(bit32.rshift({var['comb']}[{var['i']}], {var['rot']}), bit32.lshift(bit32.band({var['comb']}[{var['i']}], {(1 << rot_amount) - 1}), {8 - rot_amount})), 0xFF)"
    )
    lines.append("end")

    lines.append(f"local {var['sh']} = {{{','.join(str(x) for x in shuffle_key)}}}")
    lines.append(f"local {var['shm']} = {shuffle_mult}")
    lines.append(f"for {var['i']} = 1, #{var['comb']} do")
    lines.append(f"{var['comb']}[{var['i']}] = bit32.bxor({var['comb']}[{var['i']}], ({var['i']} - 1) * {var['shm']} % 256)")
    lines.append(f"{var['comb']}[{var['i']}] = bit32.bxor({var['comb']}[{var['i']}], {var['sh']}[({var['i']} - 1) % #{var['sh']} + 1])")
    lines.append("end")

    lines.append(f"local {var['key']} = {{{','.join(str(b) for b in key_bytes)}}}")
    lines.append(f"local {var['srchash']} = {source_checksum}")
    lines.append(f"for {var['i']} = 1, math.min(4, #{var['key']}) do")
    lines.append(
        f"{var['key']}[{var['i']}] = bit32.bxor({var['key']}[{var['i']}], bit32.band(bit32.rshift({var['srchash']}, ({var['i']} - 1) * 8), 0xFF))"
    )
    lines.append("end")

    lines.append(f"local {var['state']} = {{0, 0, 0, 0}}")
    lines.append(f"for {var['i']} = 1, #{var['key']} do")
    lines.append(
        f"{var['state']}[({var['i']} - 1) % 4 + 1] = bit32.band({var['state']}[({var['i']} - 1) % 4 + 1] * {state_mult} + {var['key']}[{var['i']}], 0xFFFFFFFF)"
    )
    lines.append("end")

    lines.append(f"local function {var['qr']}({var['a']}, {var['b']}, {var['c']}, {var['d']})")
    lines.append(f"{var['a']} = bit32.band({var['a']} + {var['b']}, 0xFFFFFFFF)")
    lines.append(f"{var['d']} = bit32.bxor({var['d']}, {var['a']})")
    lines.append(f"{var['d']} = bit32.bor(bit32.lshift(bit32.band({var['d']}, 0xFFFF), 16), bit32.rshift({var['d']}, 16))")
    lines.append(f"{var['c']} = bit32.band({var['c']} + {var['d']}, 0xFFFFFFFF)")
    lines.append(f"{var['b']} = bit32.bxor({var['b']}, {var['c']})")
    lines.append(f"{var['b']} = bit32.bor(bit32.lshift(bit32.band({var['b']}, 0xFFFFF), 12), bit32.rshift({var['b']}, 20))")
    lines.append(f"{var['a']} = bit32.band({var['a']} + {var['b']}, 0xFFFFFFFF)")
    lines.append(f"{var['d']} = bit32.bxor({var['d']}, {var['a']})")
    lines.append(f"{var['d']} = bit32.bor(bit32.lshift(bit32.band({var['d']}, 0xFFFFFF), 8), bit32.rshift({var['d']}, 24))")
    lines.append(f"{var['c']} = bit32.band({var['c']} + {var['d']}, 0xFFFFFFFF)")
    lines.append(f"{var['b']} = bit32.bxor({var['b']}, {var['c']})")
    lines.append(f"{var['b']} = bit32.bor(bit32.lshift(bit32.band({var['b']}, 0x1FFFFFF), 7), bit32.rshift({var['b']}, 25))")
    lines.append(f"return {var['a']}, {var['b']}, {var['c']}, {var['d']}")
    lines.append("end")

    lines.append(f"for {var['i']} = 1, {mix_rounds} do")
    lines.append(
        f"{var['state']}[1], {var['state']}[2], {var['state']}[3], {var['state']}[4] = {var['qr']}({var['state']}[1], {var['state']}[2], {var['state']}[3], {var['state']}[4])"
    )
    lines.append("end")

    lines.append(f"local {var['cnt']} = 0")
    lines.append(f"local {var['out']} = {{}}")
    lines.append(f"for {var['byte']} = 1, #{var['comb']} do")
    lines.append(f"if {var['cnt']} % 4 == 0 then")
    lines.append(
        f"{var['state']}[1], {var['state']}[2], {var['state']}[3], {var['state']}[4] = {var['qr']}({var['state']}[1], {var['state']}[2], {var['state']}[3], {var['state']}[4])"
    )
    lines.append(f"{var['state']}[1] = bit32.band({var['state']}[1] + {var['cnt']}, 0xFFFFFFFF)")
    lines.append("end")
    lines.append(
        f"local {var['ks']} = bit32.band(bit32.rshift({var['state']}[{var['cnt']} % 4 + 1], ({var['cnt']} % 4) * 8), 0xFF)"
    )
    lines.append(f"{var['out']}[{var['byte']}] = string.char(bit32.bxor({var['comb']}[{var['byte']}], {var['ks']}))")
    lines.append(f"{var['cnt']} = {var['cnt']} + 1")
    lines.append("end")

    lines.append(f"local {var['exec']} = loadstring(table.concat({var['out']}))")
    lines.append(f"if {var['exec']} then xpcall({var['exec']}, function() end) end")

    return "\n".join(lines)


def obfuscate(src: str, layers: list[int] | None = None, density: int = 3) -> str:
    if layers is None:
        layers = [1, 2, 3, 4, 5]

    result = src
    if any(layer in layers for layer in [1, 2, 3]):
        result = "\n".join(re.sub(r"--(?!\[\[).*$", "", line) for line in result.split("\n"))
    if 1 in layers:
        result = layer_rename(result)
    if 2 in layers:
        result = layer_xor_strings(result)
    if 3 in layers:
        result = layer_junk(result, density)
    if 4 in layers:
        result = layer_envkey(result)
    if 5 in layers:
        result = layer_payload(result)
    return result


def obfuscate_lua_source(
    source: str,
    *,
    layers: list[int] | None = None,
    density: int = 3,
    double_wrap: bool = False,
) -> str:
    try:
        if not isinstance(source, str) or not source.strip():
            raise ObfuscationError("Source is empty.")

        if layers is None:
            layers = [1, 2, 3, 4, 5]
        valid_layers = [layer for layer in layers if layer in {1, 2, 3, 4, 5}]
        if not valid_layers:
            raise ObfuscationError("No valid layers selected.")

        density = max(1, min(9, int(density)))
        result = obfuscate(source, layers=valid_layers, density=density)
        if double_wrap:
            result = layer_payload(result)
        return result
    except ObfuscationError:
        raise
    except Exception as exc:
        raise ObfuscationError(f"Lua obfuscation failed: {exc}") from exc
