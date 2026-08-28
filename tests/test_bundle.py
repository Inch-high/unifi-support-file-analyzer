"""Tests for archive extraction and path containment.

These cover the two ways a support file can reach outside the directory it is
supposed to occupy, and one way the analyzer can read the wrong bundle:

  * A tar member whose path climbs out of the destination.

  * A tar member that is a symbolic or hard link. This is the subtle one. It
    is not enough to skip past links while checking the archive; if the
    extraction that follows still creates them, a link named "x" pointing at
    "../.." followed by a member "x/payload" writes wherever the link led.
    Windows is accidentally spared, because creating a symlink there needs a
    privilege the process does not hold, so this has to be tested for what the
    archive is asked to do rather than what lands on disk.

  * Containment tested as text rather than as paths. "support-1234" is a
    sibling of "support-123", not a child, but its name starts with the same
    characters, and a startswith check cannot tell those two apart.

Run: .venv/bin/python tests/test_bundle.py
"""
import io
import sys
import tarfile
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyzer import bundle  # noqa: E402

failures = []


def check(label, ok):
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        failures.append(label)


def _add(tar, name, data=b"", link_to=None, kind=tarfile.REGTYPE):
    ti = tarfile.TarInfo(name)
    ti.type = kind
    if link_to is not None:
        ti.linkname = link_to
    else:
        ti.size = len(data)
    tar.addfile(ti, io.BytesIO(data) if link_to is None else None)


def main():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)

        print("A symlink member is never created:")
        arc = td / "symlink.tgz"
        with tarfile.open(arc, "w:gz") as tar:
            _add(tar, "escape", link_to="../../outside", kind=tarfile.SYMTYPE)
            _add(tar, "escape/payload.txt", b"pwned\n")
            _add(tar, "real.txt", b"legitimate\n")
        dest = td / "sym-dest"
        dest.mkdir()
        try:
            with tarfile.open(arc, "r:*") as tar:
                bundle._safe_extract(tar, dest)
        except ValueError:
            pass  # refusing outright is also an acceptable outcome
        check("no symlink is written", not (dest / "escape").is_symlink())
        check("nothing lands outside the destination",
              not (td / "outside").exists())
        check("the ordinary file is still extracted",
              (dest / "real.txt").is_file())

        print("\nA member climbing out of the destination is refused:")
        arc2 = td / "traverse.tgz"
        with tarfile.open(arc2, "w:gz") as tar:
            _add(tar, "../evil.txt", b"pwned\n")
        dest2 = td / "trav-dest"
        dest2.mkdir()
        refused = False
        try:
            with tarfile.open(arc2, "r:*") as tar:
                bundle._safe_extract(tar, dest2)
        except (ValueError, tarfile.TarError):
            refused = True
        check("extraction is refused or contained",
              refused or not (td / "evil.txt").exists())

        print("\nA hard link member is never created:")
        arc3 = td / "hardlink.tgz"
        with tarfile.open(arc3, "w:gz") as tar:
            _add(tar, "target.txt", b"data\n")
            _add(tar, "alias.txt", link_to="target.txt", kind=tarfile.LNKTYPE)
        dest3 = td / "link-dest"
        dest3.mkdir()
        with tarfile.open(arc3, "r:*") as tar:
            bundle._safe_extract(tar, dest3)
        check("hard link is dropped", not (dest3 / "alias.txt").exists())
        check("its target is still extracted", (dest3 / "target.txt").is_file())

        print("\nContainment is a path question, not a string one:")
        root = td / "bundles" / "support-123"
        sibling = td / "bundles" / "support-1234"
        root.mkdir(parents=True)
        sibling.mkdir(parents=True)
        (sibling / "secret.txt").write_text("other bundle", encoding="utf-8")
        (root / "own.txt").write_text("mine", encoding="utf-8")

        escaped = False
        try:
            bundle.safe_join(root, "../support-1234/secret.txt")
            escaped = True
        except ValueError:
            pass
        check("a sibling with a shared name prefix is refused", not escaped)

        for rel in ("../../etc/passwd", "..", "../support-1234"):
            try:
                bundle.safe_join(root, rel)
                check(f"{rel!r} is refused", False)
            except ValueError:
                check(f"{rel!r} is refused", True)

        print("\nOrdinary paths still resolve:")
        check("a file inside the bundle is allowed",
              bundle.safe_join(root, "own.txt").read_text(encoding="utf-8")
              == "mine")

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED: {failures}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
