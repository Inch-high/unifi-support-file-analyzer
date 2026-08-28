/**
 * Tests for the History tab's retention chart.
 *
 * This tab draws every bar against one shared scale taken from the earliest
 * and latest date across the sources, and it used to build that scale without
 * asking whether any source had a date at all. The minimum of an empty list is
 * Infinity, the maximum is -Infinity, and formatting either as a date throws.
 * It threw while building the axis, before anything had been appended to the
 * page, so a bundle whose logs carry no readable timestamps lost the whole tab
 * - table, notes and all - rather than just the chart. One unreadable date
 * among many good ones did the same by way of NaN.
 *
 * The cases below therefore care as much about what survives as about what is
 * suppressed: a bundle nobody can date must still show which logs were found
 * and the note saying why they have no dates, and a single bad date must not
 * take the other bars down with it.
 *
 * The real static/app.js is loaded and run, not a copy of its logic, so that
 * reintroducing the bug fails this rather than passing against a paraphrase.
 * The DOM here is a stub: only the handful of operations the file actually
 * performs are implemented, which is cheaper and more honest than pulling in a
 * browser engine to build seven divs.
 *
 * Run: node tests/test_history_view.js
 */
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

// ---------- a DOM, in as much detail as app.js asks for ----------

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

  // Assigned through el()'s Object.assign, so it has to behave like the real
  // accessor: writing replaces the children, reading walks them.
  get textContent() { return this.children.map(c => c.textContent).join(''); }

  set textContent(v) { this.children = [textNode(v)]; }
}

// Only the ids app.js wires itself to on load need to exist.
const byId = {};
for (const id of ['addBtn', 'fileInput', 'bundleSel', 'reanalyze', 'tabs', 'main']) {
  byId[id] = new El('div');
}

const documentStub = {
  createElement: tag => new El(tag),
  createTextNode: textNode,
  querySelector: sel => byId[sel.replace(/^#/, '')] || null,
  querySelectorAll: () => [],
  addEventListener: () => {},
};

const sandbox = {
  document: documentStub,
  location: { hash: '' },
  history: { replaceState: () => {} },
  // The load-time IIFE asks for the bundle list; an empty one takes the
  // no-bundles path and settles without touching anything this file tests.
  fetch: async () => ({ ok: true, json: async () => [], text: async () => '[]' }),
  Chart: class { destroy() {} },
  console,
};
sandbox.globalThis = sandbox;
sandbox.window = sandbox;

const source = fs.readFileSync(
  path.join(__dirname, '..', 'static', 'app.js'), 'utf8');

// Top-level const bindings are not properties of the global object, so the
// pieces under test are handed out explicitly rather than fished off it.
vm.runInNewContext(
  source + '\n;globalThis.__test = { state, viewHistory };', sandbox);
const { state, viewHistory } = sandbox.__test;

// ---------- looking at what was rendered ----------

function walk(node, out = []) {
  for (const kid of node.children || []) {
    out.push(kid);
    walk(kid, out);
  }
  return out;
}

function draw(coverage) {
  state.data = { coverage };
  byId.main.replaceChildren();
  viewHistory();
  const nodes = walk(byId.main);
  return {
    text: byId.main.textContent,
    // Every bar carries a title naming its source and span; nothing else does.
    bars: nodes.filter(n => typeof n.title === 'string'),
    rows: nodes.filter(n => n.tagName === 'TR' && n.children.some(c => c.tagName === 'TD')),
    // Axis labels are the absolutely positioned dates above the bars; the
    // From and To columns of the table below hold dates too.
    ticks: nodes.filter(n => /^\d{4}-\d{2}-\d{2}$/.test(n.textContent)
      && /position:absolute/.test(String(n.style || ''))),
    styles: nodes.map(n => n.style).filter(s => typeof s === 'string'),
  };
}

function attempt(coverage) {
  try {
    return { ok: true, out: draw(coverage) };
  } catch (e) {
    return { ok: false, error: `${e.constructor.name}: ${e.message}` };
  }
}

// ---------- fixtures ----------

const src = (label, from, to, days, extra = {}) => ({
  label, path: `system/var/log/${label}`, files: 2, filenames: [], bytes: 1000,
  from, to, days, note: null, ...extra,
});

const UNDATED_NOTE =
  'This log carries no parseable timestamps, so its entries cannot be placed ' +
  'on the timeline, open it from Browse files to read it directly.';

const healthy = () => ({
  sources: [
    src('kern.log', '2025-12-26T20:07:39+00:00', '2026-08-27T09:00:00+00:00', 243.7),
    src('messages', '2026-03-31T00:00:00+00:00', '2026-08-27T09:00:00+00:00', 149.2),
    src('daemon.log', '2026-08-09T00:00:00+00:00', '2026-08-27T09:00:00+00:00', 18.3),
  ],
  oldest: '2025-12-26T20:07:39+00:00',
  newest: '2026-08-27T09:00:00+00:00',
});

// What the backend returns for a bundle whose logs it could not timestamp:
// present, counted, and with a note, but with no dates. test_coverage.py
// proves this shape is really produced rather than only imagined here.
const undated = () => ({
  sources: [
    src('kern.log', null, null, null, { note: UNDATED_NOTE }),
    src('messages', null, null, null, { note: UNDATED_NOTE }),
  ],
  oldest: null,
  newest: null,
});

function main() {
  const failures = [];

  const check = (name, cond) => {
    console.log(`  ${cond ? 'PASS' : 'FAIL'}  ${name}`);
    if (!cond) failures.push(name);
  };

  console.log('\nA bundle that can be dated is drawn as before:');
  {
    const r = attempt(healthy());
    check('renders without throwing', r.ok);
    if (r.ok) {
      check('one bar per dated source', r.out.bars.length === 3);
      check('every source is in the table', r.out.rows.length === 3);
      check('the chart is shown', r.out.text.includes('Retention by source'));
      check('the axis is labelled at both ends',
        r.out.ticks.length === 5
        && r.out.ticks[0].textContent === '2025-12-26'
        && r.out.ticks[4].textContent === '2026-08-27');
      check('bars are positioned by date, not stacked at the left',
        r.out.bars.some(b => !/left:0%/.test(b.style || '')));
    }
  }

  console.log('\nA bundle nothing can date keeps everything but the chart:');
  {
    const r = attempt(undated());
    check('renders without throwing', r.ok);
    if (r.ok) {
      check('no chart is drawn', !r.out.text.includes('Retention by source'));
      check('no bars are drawn', r.out.bars.length === 0);
      check('the logs that were found are still listed', r.out.rows.length === 2);
      check('the note explaining why is still shown',
        r.out.text.includes('no parseable timestamps'));
      check('the tab says why there is no chart',
        r.out.text.includes('no log in this bundle carries timestamps this tool could read'
          .replace(/^no/, 'No')));
      check('nothing renders as an invalid date',
        !/NaN|Infinity/.test(r.out.text));
    }
  }

  console.log('\nDates that cannot be read are excluded, not fed to the scale:');
  {
    const c = healthy();
    c.sources.forEach(s => { s.from = 'n/a'; s.to = 'n/a'; });
    const r = attempt(c);
    check('unreadable dates throughout do not throw', r.ok);
    check('and produce no chart', r.ok && !r.out.text.includes('Retention by source'));
  }
  {
    // The case that matters most: one source is fine, the rest are not. The
    // old filter let the bad ones through, NaN reached Math.min, and the tab
    // died despite having a perfectly good source to draw.
    const c = healthy();
    c.sources[1].from = 'n/a';
    c.sources[2].to = undefined;
    const r = attempt(c);
    check('one unreadable date does not lose the readable ones', r.ok);
    if (r.ok) {
      check('the good source is still charted', r.out.bars.length === 1);
      check('the others remain in the table', r.out.rows.length === 3);
      check('no bar is positioned by an invalid number',
        !r.out.styles.some(s => /NaN|Infinity/.test(s)));
    }
  }

  console.log('\nEmpty and missing coverage:');
  {
    const r = attempt({ sources: [], oldest: null, newest: null });
    check('a bundle with no log sources at all does not throw', r.ok);
    check('and shows an empty table rather than a chart',
      r.ok && r.out.bars.length === 0 && r.out.rows.length === 0);
  }
  {
    const r = attempt(null);
    check('absent coverage keeps its own message', r.ok && r.out.text === 'No coverage data.');
  }

  console.log();
  if (failures.length) {
    console.log(`${failures.length} check(s) FAILED: ${JSON.stringify(failures)}`);
    return 1;
  }
  console.log('All checks passed.');
  return 0;
}

process.exit(main());
