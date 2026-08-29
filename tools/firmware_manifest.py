#!/usr/bin/env python3
"""Build the list of what UniFi OS actually ships, from the firmware itself.

The process audit has to answer one question: did this binary come with the
device, or did somebody put it there. That was answered for years by a list of
names typed out by hand, which could only ever describe the hardware it was
written against - a Dream Router owner saw unifi-directory and udr-ui reported
as unrecognised, and both are stock. The firmware images say who is right.

A UniFi OS image is a `UBNT` container with a squashfs rootfs inside it. The
rootfs is not encrypted: find the superblock, walk it, and record every file
that carries an executable bit, plus the systemd units. Names and paths only;
no file content is read and nothing is redistributed except the listing.

Nothing in the running tool imports this. It needs two packages the analyzer
does not:

    pip install PySquashfsImage lz4

Then, with the images in one directory:

    python tools/firmware_manifest.py <dir-of-.bin> analyzer/data/firmware_manifest.json

Images come from https://www.ui.com/download/software/<model>, whose download
links are direct .bin URLs. The models covered at the time of writing are
listed in URLS below; re-run it when a release lands, and the manifest picks up
whatever that release changed.
"""
import json
import re
import struct
import sys
from pathlib import Path

# For reference and re-download; the tool reads whatever .bin files it is given.
URLS = {
    "UDM": "unifi-dream/6b06-UDM-5.1.31-c194bab7-cc64-4104-add0-22e96c8143a4.bin",
    "UDMPRO": "unifi-dream/f100-UDMPRO-5.1.31-c840591d-ddc5-4ab4-a08b-4df62f47403d.bin",
    "UDMSE": "unifi-dream/cf3d-UDMPROSE-5.1.31-2ef21a44-ce2c-4290-a1f8-6271b9260ae1.bin",
    "UDMPROMAX": "unifi-dream/ff15-UDMPROMAX-5.1.31-21fde9c8-1a23-44dd-bace-2ac450439f93.bin",
    "UDMBEAST": "unifi-dream/1ac6-UDMEA4C-5.1.31-1854fb46-32b6-41cc-a005-b9bfbb9a0d8d.bin",
    "UDR": "unifi-dream/4bbe-UDR-5.1.31-fe0e3e8b-c208-42e2-80d9-21466dd062e5.bin",
    "UDR7": "unifi-dream/f2d6-UDR7-5.1.31-952b4e20-5fcd-480f-9908-dcf9df9d3d9c.bin",
    "UCGULTRA": "unifi-dream/cf04-UDRULT-5.1.31-5e71244d-8b0c-4785-a428-c7bf77a94fc9.bin",
    "UCGMAX": "unifi-dream/7ed2-UCGMAX-5.1.31-a6b25671-ee07-4401-a169-2881d9f95757.bin",
    "UCGFIBER": "unifi-dream/0e28-UCGF-5.1.31-98fec72b-e1b2-4f87-8e04-01d712d35e0b.bin",
    "UX": "unifi-dream/2edb-UX-4.0.17-174febdb-3f93-4530-9013-3ab6656ac7a1.bin",
    "UXMAX": "unifi-dream/e368-UXMAX-5.1.31-7c41c653-c16a-47b6-927f-24a44c451b35.bin",
    "UXGPRO": "unifi-firmware/99f0-UXGPROV2-5.1.26-f0594436-4f08-4d3d-a852-e9004f3e7d43.bin",
    "UXGLITE": "unifi-firmware/2ead-UXG-5.1.26-54d4a70d-3690-49df-aeef-e175006e991d.bin",
    "UXGMAX": "unifi-firmware/153c-UXGB-5.1.26-b461f5d4-2bdd-479e-91f3-d8d1948180e4.bin",
}
BASE_URL = "https://fw-download.ubnt.com/data/"

# Marketing names, for the manifest to be readable by a person.
LABELS = {
    "UDM": "Dream Machine", "UDMPRO": "Dream Machine Pro",
    "UDMPROSE": "Dream Machine SE", "UDMPROMAX": "Dream Machine Pro Max",
    "UDMEA4C": "Dream Machine Pro Max (Beast)",
    "UDR": "Dream Router", "UDR7": "Dream Router 7",
    "UDRULT": "Cloud Gateway Ultra", "UCGMAX": "Cloud Gateway Max",
    "UCGF": "Cloud Gateway Fiber",
    "UEX": "Express", "UXMAX": "Express Max",
    "UXGPRO": "UXG Pro", "UXG": "UXG Lite", "UXGB": "UXG Max",
}

# Symlinks in these directories are real invocation names: awk, python3 and
# iptables are all links, and a process reports the name it was invoked by.
LINK_DIRS = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
             "/usr/local/bin/", "/usr/local/sbin/", "/usr/libexec/")


def _patch_lz4():
    """squashfs stores raw LZ4 blocks, PySquashfsImage expects LZ4 frames.

    Without this the Express and UXG Lite images fail to open at all, with
    ERROR_frameType_unknown. Substituted rather than patched into the package.
    """
    try:
        import lz4.block
        from PySquashfsImage import compressor as comp
        from PySquashfsImage.const import Compression

        class RawLZ4(comp.Compressor):
            name = "lz4"

            def uncompress(self, src, size, outsize):
                return lz4.block.decompress(src, uncompressed_size=outsize)

        comp.compressors[Compression.LZ4] = RawLZ4
    except ImportError:
        pass  # only the lz4 images will fail, and they say so


def find_squashfs(path: Path):
    """Offset, and superblock facts, of the rootfs inside a UBNT container."""
    size = path.stat().st_size
    with path.open("rb") as fh:
        pos, prev = 0, b""
        while True:
            buf = fh.read(8 << 20)
            if not buf:
                return None
            window = prev + buf
            base = pos - len(prev)
            for m in re.finditer(rb"hsqs", window):
                off = base + m.start()
                with path.open("rb") as probe:
                    probe.seek(off)
                    sb = probe.read(96)
                if len(sb) < 96:
                    continue
                (magic, _, _, block_size, _, comp, _, _, _,
                 major, _, _, used) = struct.unpack_from("<IIIIIHHHHHHQQ", sb, 0)
                if (magic == 0x73717368 and major == 4
                        and 4096 <= block_size <= (1 << 20) and 0 < used <= size):
                    return off, comp, used
            prev = buf[-8:]
            pos += len(buf)


def version_of(path: Path):
    head = path.open("rb").read(128)
    m = re.match(rb"UBNT([ -~]+)", head)
    return m.group(1).decode() if m else ""


def inventory(path: Path):
    """Executable names, and unit names, in one image."""
    from PySquashfsImage import SquashFsImage

    found = find_squashfs(path)
    if not found:
        raise RuntimeError("no squashfs rootfs found")
    off, _, _ = found
    names, units = set(), set()
    with SquashFsImage.from_file(str(path), offset=off) as image:
        for f in image:
            p = f.path if isinstance(f.path, str) else f.path.decode("utf-8", "replace")
            if not p.startswith("/"):
                p = "/" + p
            if p.endswith(".service") and "/systemd/system" in p:
                units.add(p.rsplit("/", 1)[-1])
            if f.is_symlink:
                if any(p.startswith(d) for d in LINK_DIRS):
                    names.add(p.rsplit("/", 1)[-1])
                continue
            if f.is_dir or not f.is_file or not (f.mode & 0o111):
                continue
            names.add(p.rsplit("/", 1)[-1])
    return names, units


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        print("\nusage: firmware_manifest.py <dir-of-.bin> <out.json>")
        print("\nimages:")
        for model, tail in URLS.items():
            print(f"  {model:11} {BASE_URL}{tail}")
        return 2

    _patch_lz4()
    src, out = Path(argv[1]), Path(argv[2])
    per_model = {}

    for image in sorted(src.glob("*.bin")):
        version = version_of(image)
        # The product code leads the version string, and is exactly what a
        # support file reports for the device, so it is the key that lets a
        # bundle find its own manifest.
        code = version.split(".")[0] if version else image.stem
        try:
            names, units = inventory(image)
        except Exception as exc:
            print(f"{image.name}: SKIPPED ({type(exc).__name__}: {exc})")
            continue
        print(f"{code:11} {len(names):5,} names  {len(units):4} units  {version}")
        per_model[code] = {"version": version, "names": names, "units": units}

    if not per_model:
        print("no images could be read")
        return 1

    common = set.intersection(*(m["names"] for m in per_model.values()))
    common_units = set.intersection(*(m["units"] for m in per_model.values()))

    manifest = {
        "note": ("Executable names and systemd units present in UniFi OS "
                 "firmware images, used to tell software that shipped with a "
                 "device from software somebody added. Generated by "
                 "tools/firmware_manifest.py; do not edit by hand."),
        "common": sorted(common),
        "common_units": sorted(common_units),
        "models": {
            code: {
                "label": LABELS.get(code, code),
                "version": m["version"],
                "names": sorted(m["names"] - common),
                "units": sorted(m["units"] - common_units),
            }
            for code, m in sorted(per_model.items())
        },
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=0, sort_keys=True), encoding="utf-8")
    total = len(set.union(*(m["names"] for m in per_model.values())))
    print(f"\n{len(per_model)} models, {len(common):,} names common, "
          f"{total:,} in union")
    print(f"wrote {out} ({out.stat().st_size / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
