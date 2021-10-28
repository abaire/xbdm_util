def match_hex(key: str) -> str:
    """Returns a string containing a regex matching key=<hex_or_integer_string>"""
    return f"{key}=((?:0x)?[0-9a-fA-F]+)"
