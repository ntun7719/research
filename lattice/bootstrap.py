"""Prepare a mounted data volume and permanently drop container privileges."""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path


def main() -> None:
    os.umask(0o077)
    if os.geteuid() == 0:
        root = Path(os.environ.get("DATA_DIR", "/data"))
        resolved = root.resolve()
        forbidden = {Path("/"), Path("/app"), Path("/etc"), Path("/usr"), Path("/tmp"), Path("/home")}
        if not root.is_absolute() or root.is_symlink() or resolved in forbidden:
            raise SystemExit("Unsafe DATA_DIR refused")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        for base, dirs, files in os.walk(root, followlinks=False):
            for candidate in [Path(base)] + [Path(base) / name for name in dirs + files]:
                info = candidate.lstat()
                if stat.S_ISLNK(info.st_mode):
                    continue
                if info.st_uid != 10001 or info.st_gid != 10001:
                    os.chown(candidate, 10001, 10001, follow_symlinks=False)
        os.setgroups([])
        os.setgid(10001)
        os.setuid(10001)
    if os.geteuid() == 0:
        raise SystemExit("Application refuses to run as root")
    args = sys.argv[1:] or ["python3", "-m", "lattice"]
    os.execvp(args[0], args)


if __name__ == "__main__":
    main()
