"""What UniFi OS ships, per model, taken from the firmware itself.

The process audit needs to know whether a binary came with the device. That
used to be answered by a list of names typed out by hand, which described the
one machine it was written against: a Dream Router owner saw `unifi-directory`
and `udr-ui` reported as unrecognised, and both are stock. The firmware images
answer it properly, so `analyzer/data/firmware_manifest.json` holds the names
and units present in each one. tools/firmware_manifest.py regenerates it.

Two things make this exact rather than approximate. A support file records its
firmware in `system/system-version`, and that string - `UDMPRO.al324.v5.1.31.
5acc35d.260819.1714` - is byte-identical to the one in the firmware container
it came from, so a bundle can find its own manifest by model and say whether
the version matches too.

Where a device is not in the manifest, every name from every image is used
instead. That is weaker, and `known_model` says so, but it is still a list of
things that really ship somewhere rather than a guess about naming.
"""
import json
from pathlib import Path

MANIFEST_PATH = Path(__file__).resolve().parent / "data" / "firmware_manifest.json"

# The kernel truncates a process's comm to 15 characters, so a longer shipped
# name can only ever be recognised by its first 15.
COMM_MAX = 15

_CACHE = {}


def _manifest():
    if "m" not in _CACHE:
        try:
            _CACHE["m"] = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            _CACHE["m"] = {"common": [], "common_units": [], "models": {}}
    return _CACHE["m"]


def available():
    """Whether a manifest was shipped and could be read."""
    return bool(_manifest().get("models"))


def device_version(root: Path):
    """The firmware string the support file records, or ''."""
    try:
        return (root / "system/system-version").read_text(
            encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def device_code(root: Path):
    """The product code leading that string: UDMPRO, UDR7, UDRULT, UXG ..."""
    return device_version(root).split(".")[0].upper()


class Shipped:
    """The software one device's firmware contains."""

    def __init__(self, code, label, names, units, manifest_version="",
                 device_version="", known_model=True):
        self.code = code
        self.label = label
        self.names = names
        self.units = units
        self.manifest_version = manifest_version
        self.device_version = device_version
        self.known_model = known_model

    @property
    def exact_version(self):
        """Whether the manifest was built from the firmware this device runs."""
        return bool(self.manifest_version
                    and self.manifest_version == self.device_version)

    def has(self, name):
        """Whether this name is something the firmware ships."""
        if not name:
            return False
        if name in self.names:
            return True
        # A truncated comm matches any shipped name it is a prefix of. Only at
        # exactly the truncation length: shortening the test would let "unifi"
        # match every unifi-* binary there is.
        return len(name) == COMM_MAX and any(
            n.startswith(name) for n in self.names)

    def has_unit(self, unit):
        return bool(unit) and unit in self.units

    def __repr__(self):  # pragma: no cover - debugging only
        return (f"<Shipped {self.code} names={len(self.names)} "
                f"units={len(self.units)} known={self.known_model}>")


def _union():
    m = _manifest()
    names = set(m.get("common") or ())
    units = set(m.get("common_units") or ())
    for entry in (m.get("models") or {}).values():
        names |= set(entry.get("names") or ())
        units |= set(entry.get("units") or ())
    return names, units


def for_device(root: Path):
    """The manifest entry for this bundle's device, or the union as a fallback."""
    m = _manifest()
    code = device_code(root)
    version = device_version(root)
    entry = (m.get("models") or {}).get(code)
    if entry:
        names = set(m.get("common") or ()) | set(entry.get("names") or ())
        units = set(m.get("common_units") or ()) | set(entry.get("units") or ())
        return Shipped(code, entry.get("label") or code, names, units,
                       entry.get("version", ""), version, known_model=True)
    names, units = _union()
    return Shipped(code or "", "", names, units, "", version, known_model=False)
