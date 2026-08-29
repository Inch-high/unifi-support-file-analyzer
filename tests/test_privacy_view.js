/**
 * Tests that a slow result lands on its own tab and nowhere else.
 *
 * The privacy scan and the cleaned copy both take minutes, and both finish by
 * rendering. render() replaces #main with whatever it is handed, regardless of
 * what is in there. The tabs are buttons rather than a container that owns its
 * content, so a scan started on Privacy and finished while its owner was
 * reading Ramoops painted the privacy report over the Ramoops page, underneath
 * a heading that was still underlined as Ramoops. Reported by someone who did
 * exactly that and reasonably did not expect it.
 *
 * The fix is not to drag the reader back to Privacy - being moved off a tab
 * minutes after opening it is the more startling of the two - but to leave
 * them where they are and keep the result in state, so it is waiting when they
 * return. That is what these check: what does NOT get painted, and that
 * nothing is lost by not painting it.
 *
 * The real static/app.js is loaded and run, so reintroducing the bug fails
 * this rather than passing against a paraphrase.
 *
 * Run: node tests/test_privacy_view.js
 */
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

// ---------- the little of a DOM that app.js touches here ----------

function textNode(data) {
  return { nodeType: 3, textContent: String(data), children: [] };
}

class El {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase();
    this.nodeType = 1;
    this.children = [];
    this.className = '';
    const self = this;
    this.classList = {
      add(...c) { self.className = [...new Set(self.className.split(' ').concat(c))].join(' ').trim(); },
      remove(...c) { self.className = self.className.split(' ').filter(x => !c.includes(x)).join(' '); },
    };
  }
  append(...kids) { this.children.push(...kids); }
  replaceChildren(...kids) { this.children = []; this.append(...kids); }
  get textContent() { return this.children.map(c => c.textContent).join(''); }
  set textContent(v) { this.children = [textNode(v)]; }
}

const byId = {};
for (const id of ['addBtn', 'fileInput', 'bundleSel', 'reanalyze', 'tabs', 'main',
                  'devsub']) {
  byId[id] = new El('div');
}

// The scan is held open deliberately, so the moment between "started" and
// "finished" - the only moment in which this bug exists - can be inspected.
let releaseScan = null;
// The shape the endpoint really returns, in miniature, taken from a cached
// result rather than imagined: viewPrivacy reads files[] and categories[]
// field by field, so a stub missing any of them throws on the way in and
// proves nothing about where the result was painted.
const scanResult = {
  files: [
    {
      path: 'cfg/system.cfg', bytes: 2048, truncated: false, severity: 'major',
      categories: [{
        key: 'email', label: 'Email address', severity: 'major',
        count: 5, distinct: 1, samples: ['so*****@e*****.com'],
      }],
    },
  ],
  file_count: 1,
  categories: [{
    key: 'email', label: 'Email address', severity: 'major',
    count: 5, distinct: 1, files: 1,
  }],
  top_domains: [],
  scanned_files: 10, skipped_files: 0, truncated_files: 0,
  max_bytes_per_file: 1048576, masked: true,
};

// Enough of an analysis for loadAnalysis to get as far as drawing a tab, so
// that switching bundles can be exercised through the real code path rather
// than by poking state by hand.
const analysisResult = {
  id: 'support-OTHER',
  overview: { device: { name: 'UDR' }, firmware: '4.0.6' },
  findings: { findings: [], counts: {} },
};

function respond(body) {
  return {
    ok: true,
    headers: { get: () => 'application/json' },
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

const sandbox = {
  document: {
    createElement: tag => new El(tag),
    createTextNode: textNode,
    querySelector: sel => byId[sel.replace(/^#/, '')] || null,
    querySelectorAll: () => [],
    addEventListener: () => {},
  },
  location: { hash: '' },
  history: { replaceState: () => {} },
  fetch: async (url) => {
    const u = String(url);
    if (u.includes('/api/bundles')) return respond([]);
    if (u.includes('/analysis')) return respond(analysisResult);
    // The cheap "is one already cached" probe answers at once; only the real
    // scan is held open.
    if (u.includes('/pii')) {
      if (u.includes('only_cached=true')) return respond({ pending: true });
      return new Promise(res => { releaseScan = () => res(respond(scanResult)); });
    }
    return respond({});
  },
  Chart: class { destroy() {} },
  console,
};
sandbox.globalThis = sandbox;
sandbox.window = sandbox;

const source = fs.readFileSync(
  path.join(__dirname, '..', 'static', 'app.js'), 'utf8');
// repaintIf is handed out only if it exists, so that a build without it fails
// on the behaviour these checks describe rather than on a ReferenceError while
// loading. A test that cannot start says much less than one that says which
// guarantee broke.
vm.runInNewContext(
  source + '\n;globalThis.__test = { state, viewPrivacy, loadAnalysis,'
  + ' repaintIf: typeof repaintIf === "function" ? repaintIf : null };', sandbox);
const { state, viewPrivacy, loadAnalysis, repaintIf } = sandbox.__test;
const realFetch = sandbox.fetch;

// ---------- helpers ----------

function walk(node, out = []) {
  for (const kid of node.children || []) {
    out.push(kid);
    walk(kid, out);
  }
  return out;
}

function findButton(label) {
  return walk(byId.main).find(
    n => n.tagName === 'BUTTON' && n.textContent === label);
}

function findRevealToggle() {
  const label = walk(byId.main).find(
    n => n.tagName === 'LABEL' && n.textContent.includes('Reveal actual values'));
  return label && label.children.find(c => c.tagName === 'INPUT');
}

const OTHER_TAB_CONTENT = 'the ramoops page the reader moved to';

function tick() { return new Promise(res => setImmediate(res)); }

async function main() {
  const failures = [];
  const check = (name, cond) => {
    console.log(`  ${cond ? 'PASS' : 'FAIL'}  ${name}`);
    if (!cond) failures.push(name);
  };

  // app.js asks for the bundle list as it loads and renders the empty state
  // when the answer is "none". That lands on #main a tick after load, so it
  // has to be allowed to happen before anything here paints, or it arrives
  // mid-test and looks like the very clobbering these checks are about.
  await tick();
  await tick();

  // Start every case from the Privacy tab with nothing scanned yet.
  async function startScan() {
    state.bid = 'support-TEST';
    state.tab = 'privacy';
    state.pii = undefined;
    state.piiError = null;
    releaseScan = null;
    byId.main.replaceChildren();
    viewPrivacy();
    const btn = findButton('Run privacy scan');
    if (!btn) throw new Error('the run button was not rendered');
    const running = btn.onclick({ target: {} });
    await tick();          // let the handler reach its await
    // Wrapped, not returned bare: an async function adopts a promise it
    // returns, so handing back the in-flight scan would make awaiting this
    // helper wait for a scan that is only released afterwards.
    return { running };
  }

  console.log('\nA scan that finishes on another tab does not paint over it:');
  {
    const { running } = await startScan();
    check('the scan is actually in flight', typeof releaseScan === 'function');

    // The reader moves to Ramoops while it runs.
    state.tab = 'ramoops';
    byId.main.replaceChildren(textNode(OTHER_TAB_CONTENT));

    releaseScan();
    await running;

    check('the other tab still shows its own content',
      byId.main.textContent === OTHER_TAB_CONTENT);
    check('the report is not painted over it',
      !byId.main.textContent.includes('What leaves with this file'));
    check('but the result is kept, so returning to Privacy shows it',
      state.pii && state.pii.file_count === 1);
  }

  console.log('\nComing back to Privacy shows the finished scan:');
  {
    state.tab = 'privacy';
    byId.main.replaceChildren();
    viewPrivacy();
    check('the report renders on return',
      byId.main.textContent.includes('What leaves with this file'));
    check('and the run button is gone', !findButton('Run privacy scan'));
  }

  console.log('\nStaying on Privacy still repaints, as before:');
  {
    const { running } = await startScan();
    releaseScan();
    await running;
    check('the report replaces the spinner',
      byId.main.textContent.includes('What leaves with this file'));
  }

  console.log('\nA failure is kept too, rather than painted onto another tab:');
  {
    state.bid = 'support-TEST';
    state.tab = 'privacy';
    state.pii = undefined;
    state.piiError = null;
    byId.main.replaceChildren();
    viewPrivacy();
    const btn = findButton('Run privacy scan');
    let rejectScan;
    sandbox.fetch = async (url) => {
      if (String(url).includes('/pii')) {
        return new Promise((_, rej) => { rejectScan = () => rej(new Error('boom')); });
      }
      return respond([]);
    };
    const running = btn.onclick({ target: {} });
    await tick();
    state.tab = 'ramoops';
    byId.main.replaceChildren(textNode(OTHER_TAB_CONTENT));
    rejectScan();
    await running;
    check('the error does not replace the other tab',
      byId.main.textContent === OTHER_TAB_CONTENT);
    check('the error is remembered', state.piiError === 'boom');

    state.tab = 'privacy';
    byId.main.replaceChildren();
    viewPrivacy();
    check('and is shown when Privacy is opened again',
      byId.main.textContent.includes('Scan failed')
      && byId.main.textContent.includes('boom'));
    check('with the run button offered again',
      Boolean(findButton('Run privacy scan')));
  }

  sandbox.fetch = realFetch;

  // The other half of "the result is waiting when you return": while it is
  // still running, coming back has to say so. Disabling the button that was
  // clicked says nothing about the button drawn the next time the tab is
  // opened, so this used to offer a fresh Run button as though nothing were
  // happening - and clicking it scanned every file in the bundle a second
  // time, with two handlers then racing to paint.
  console.log('\nComing back while it is still running says so:');
  {
    const { running } = await startScan();
    state.tab = 'ramoops';
    byId.main.replaceChildren(textNode(OTHER_TAB_CONTENT));

    state.tab = 'privacy';
    byId.main.replaceChildren();
    viewPrivacy();
    check('the scan in progress is shown',
      byId.main.textContent.includes('Scanning every file in the bundle'));
    check('and no second scan is offered', !findButton('Run privacy scan'));

    releaseScan();
    await running;
    check('the report arrives when it finishes',
      byId.main.textContent.includes('What leaves with this file'));
    check('and the running flag is cleared', state.piiRunning === false);
  }

  // A report belongs to the bundle it was scanned from. Showing one bundle's
  // secrets under another bundle's name is the worst version of this mistake,
  // so both the result and the failure have to be dropped when the selector
  // moves - including one still in flight when it does.
  console.log('\nA report does not follow you to another bundle:');
  {
    state.pii = scanResult;
    state.piiError = 'boom';
    state.tab = 'privacy';
    await loadAnalysis('support-OTHER');
    check('the previous report is forgotten', !state.pii);
    check('so is the previous failure', !state.piiError);
    check('and the new bundle is not shown the old report',
      !byId.main.textContent.includes('cfg/system.cfg'));
  }

  {
    const { running } = await startScan();
    await loadAnalysis('support-ANOTHER');
    releaseScan();
    await running;
    check('a scan that outlives its bundle is discarded, not stored',
      state.bid === 'support-ANOTHER' && state.pii !== scanResult);
  }

  // Revealing the values re-reads the whole bundle, so it is the same wait by
  // a different button, and it used to paint its answer unconditionally.
  console.log('\nRevealing the values is held the same way:');
  {
    state.bid = 'support-TEST';
    state.tab = 'privacy';
    state.pii = scanResult;
    state.piiError = null;
    state.piiRunning = false;
    releaseScan = null;
    byId.main.replaceChildren();
    viewPrivacy();
    const toggle = findRevealToggle();
    check('the reveal toggle is drawn', Boolean(toggle));
    const running = toggle.onchange({ target: { checked: true } });
    await tick();
    check('its own wording is shown, not the first-scan wording',
      byId.main.textContent.includes('Re-scanning with values revealed'));

    state.tab = 'ramoops';
    byId.main.replaceChildren(textNode(OTHER_TAB_CONTENT));
    releaseScan();
    await running;
    check('and the re-scan does not paint over the tab you moved to',
      byId.main.textContent === OTHER_TAB_CONTENT);
    check('while the revealed result is kept for the tab that asked',
      state.pii === scanResult && state.piiRunning === false);
    state.piiReveal = false;
  }

  console.log('\nThe cleaned copy cannot be started twice either:');
  {
    state.bid = 'support-TEST';
    state.tab = 'privacy';
    state.pii = scanResult;
    state.piiError = null;
    state.piiRunning = false;
    state.sanitise = { running: true };
    byId.main.replaceChildren();
    viewPrivacy();
    const btn = findButton('Create cleaned copy');
    check('the button is drawn', Boolean(btn));
    check('but disabled while a copy is being written',
      Boolean(btn && btn.disabled));
    state.sanitise = null;
  }

  console.log('\nrepaintIf only fires for the tab that owns the work:');
  {
    check('the guard exists', typeof repaintIf === 'function');
    if (typeof repaintIf === 'function') {
      let ran = 0;
      state.tab = 'privacy';
      repaintIf('privacy', () => { ran += 1; });
      check('runs on a match', ran === 1);
      state.tab = 'cpu';
      repaintIf('privacy', () => { ran += 1; });
      check('does nothing on a mismatch', ran === 1);
    }
  }

  console.log();
  if (failures.length) {
    console.log(`${failures.length} check(s) FAILED: ${JSON.stringify(failures)}`);
    return 1;
  }
  console.log('All checks passed.');
  return 0;
}

// exitCode rather than exit(): stdout is asynchronous when it is a pipe, and
// process.exit() throws away whatever has not been flushed - which on a
// redirected run is the entire report this file exists to print. Letting the
// process end on its own flushes first.
main().then(
  code => { process.exitCode = code; },
  err => {
    console.error(`\nthrew: ${(err && err.stack) || err}`);
    process.exitCode = 1;
  });
