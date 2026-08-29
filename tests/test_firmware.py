"""Tests for the shipped firmware manifest and how a bundle is matched to it.

The manifest is the difference between "this name is not on a list somebody
typed" and "this did not come with the device". That is only worth anything if
three things hold: the data is actually shipped and readable, a bundle finds
its own model rather than some other one, and an unknown model degrades to
something honest instead of either silence or a flood of false alarms.

Run: .venv/bin/python tests/test_firmware.py
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyzer import firmware  # noqa: E402

failures = []


def check(name, cond):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        failures.append(name)


def bundle(version=None):
    td = Path(tempfile.mkdtemp())
    if version is not None:
        (td / "system").mkdir(parents=True)
        (td / "system/system-version").write_text(version, encoding="utf-8")
    return td


def main():
    print("\nThe manifest ships and can be read:")
    check("the file is present", firmware.MANIFEST_PATH.is_file())
    check("it loads", firmware.available())
    m = json.loads(firmware.MANIFEST_PATH.read_text(encoding="utf-8"))
    check("it covers the gateway families", len(m["models"]) >= 10)
    check("it has a shared core", len(m["common"]) > 1000)
    check("every model carries the version it came from",
          all(e.get("version") for e in m["models"].values()))
    check("it says it is generated", "firmware_manifest.py" in m.get("note", ""))

    # The names the reports were about, settled by the images themselves.
    everywhere = set(m["common"])
    anywhere = set(everywhere)
    for e in m["models"].values():
        anywhere |= set(e["names"])
    print("\nThe names this was built to settle:")
    check("unifi-directory ships", "unifi-directory" in anywhere)
    check("udr-ui ships", "udr-ui" in anywhere)
    check("sshd ships everywhere", "sshd" in everywhere)
    check("ucg-dash2 ships nowhere", "ucg-dash2" not in anywhere)

    print("\nA bundle finds its own model:")
    b = bundle("UDMPRO.al324.v5.1.31.5acc35d.260819.1714")
    check("the code is read from system-version",
          firmware.device_code(b) == "UDMPRO")
    s = firmware.for_device(b)
    check("the model is known", s.known_model)
    check("the label is human-readable", "Dream Machine" in s.label)
    check("the version matches exactly", s.exact_version)
    check("it holds that model's software", s.has("unifi-directory"))

    print("\nA different model gets a different answer:")
    uxg = firmware.for_device(bundle("UXG.ipq5018.v5.1.26.0bc0fe4.260716.1128"))
    check("UXG Lite is known", uxg.known_model and uxg.code == "UXG")
    check("the two models differ", uxg.names != s.names)

    print("\nAn unknown or missing model degrades honestly:")
    unknown = firmware.for_device(bundle("NOSUCH.xx.v1.2.3.abc.111111.0000"))
    check("it does not claim to know the model", not unknown.known_model)
    check("it still compares against every image",
          len(unknown.names) > len(s.names))
    check("nothing shipped anywhere is called an add-on",
          unknown.has("unifi-directory") and unknown.has("udr-ui"))
    check("and something shipped nowhere still is not",
          not unknown.has("ucg-dash2"))

    none = firmware.for_device(bundle())
    check("a bundle with no version at all still answers",
          not none.known_model and none.has("sshd"))
    check("and reports no version rather than inventing one",
          none.device_version == "")

    print("\nA truncated process name matches the binary it came from:")
    # The kernel caps comm at 15 characters, so this is the only way a long
    # name is ever seen in a snapshot.
    long_name = next((n for n in sorted(anywhere) if len(n) > 15), None)
    check("the manifest contains a name longer than comm allows",
          long_name is not None)
    if long_name:
        s2 = firmware.for_device(bundle("NOSUCH.xx.v1.2.3.abc.111111.0000"))
        check(f"{long_name!r} matches its 15-character prefix",
              s2.has(long_name[:15]))
        check("a shorter prefix does not match anything",
              not s2.has(long_name[:6]))
    check("an empty name matches nothing", not s.has(""))

    print("\nUnits are carried too, for the services half of the question:")
    check("the shared units are present", len(m["common_units"]) > 100)
    check("a bundle's units resolve", len(s.units) > 100)

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED: {failures}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
