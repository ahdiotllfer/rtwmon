import json
import os
import sys


def main(argv: list[str]) -> int:
    spec = os.environ.get("RTWMON_TERMUX_CALLBACK_JSON", "")
    try:
        base = json.loads(spec) if spec else []
    except Exception:
        base = []
    if not isinstance(base, list) or not all(isinstance(x, str) for x in base) or not base:
        sys.stderr.write("rtwmon_termux_callback: invalid RTWMON_TERMUX_CALLBACK_JSON\n")
        return 1

    cmd = [*base, *argv[1:]]
    try:
        os.execvp(cmd[0], cmd)
    except FileNotFoundError:
        sys.stderr.write(f"rtwmon_termux_callback: not found: {cmd[0]}\n")
        return 127
    except Exception as e:
        sys.stderr.write(f"rtwmon_termux_callback: exec failed: {e}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

