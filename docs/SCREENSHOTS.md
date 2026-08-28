# How the screenshots were made

They must never show real network data, so they are taken from a support file
that has been run through the tool's own cleaning step first. Every address,
device name, hardware address and domain in them is a stand-in.

1. Load a real support file and let it analyse.
2. Privacy tab, "Create cleaned copy".
3. Load the cleaned copy as a support file of its own. It appears in the
   selector under its own name.
4. Check it: search the cleaned copy for your own WAN address, a device name
   and your email. All three should return nothing.
5. Capture each tab. The page accepts deep links, so a headless browser can
   drive it:

```bash
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
B="support-EXAMPLE-0000000000"
for tab in findings forensics cpu network privacy history processes; do
  "$CHROME" --headless=new --hide-scrollbars --virtual-time-budget=20000 \
    --window-size=1400,1450 --screenshot="docs/screenshots/$tab.png" \
    "http://127.0.0.1:8077/#bundle=$B&tab=$tab"
done
```

Known limit worth checking before publishing: a domain buried inside a
hyphenated identifier, such as the gateway's own monitoring targets
(`eth9-mon8-198.51.100.7-google.com`), is left alone by the cleaner. Those are
UniFi defaults rather than anything about you, but look at the images before
publishing rather than assuming.
