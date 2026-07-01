import pathlib

src = pathlib.Path("src/tools/settings_security.py")

code = r"""
"""

src.write_text(code.lstrip(), encoding="utf-8")
print("done", src.stat().st_size)
