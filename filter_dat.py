#!/usr/bin/env python3
import json
import sys


def read_varint(buf, pos):
    result = shift = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7


def write_varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def entry_code(entry):
    if not entry or entry[0] != 0x0A:
        raise ValueError("Неожиданная структура записи")
    length, pos = read_varint(entry, 1)
    return entry[pos:pos + length].decode().upper()


def filter_dat(src, dst, wanted):
    data = open(src, "rb").read()
    wanted = {w.upper() for w in wanted}
    found = set()
    out = bytearray()
    pos = 0
    while pos < len(data):
        tag, pos = read_varint(data, pos)
        if tag != 0x0A: 
            raise ValueError(f"Неожиданный тег верхнего уровня: {tag}")
        length, pos = read_varint(data, pos)
        entry = data[pos:pos + length]
        pos += length
        code = entry_code(entry)
        if code in wanted:
            found.add(code)
            out += b"\x0a" + write_varint(len(entry)) + entry

    missing = wanted - found
    if missing:
        sys.exit(f"{src}: Не найдены теги {sorted(missing)}")

    with open(dst, "wb") as f:
        f.write(out)
    print(f"{dst}: {len(data) / 1e6:.1f} МБ -> {len(out) / 1e6:.2f} МБ ({len(found)} тегов)")


if __name__ == "__main__":
    cfg = json.load(open("config.json", encoding="utf-8"))
    filter_dat("full-geoip.dat", "geoip.dat", cfg["geoip"])
    filter_dat("full-geosite.dat", "geosite.dat", cfg["geosite"])
