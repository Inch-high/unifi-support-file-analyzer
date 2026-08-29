'use strict';

const $ = (s, r = document) => r.querySelector(s);
const el = (tag, props = {}, ...kids) => {
  const n = Object.assign(document.createElement(tag), props);
  for (const k of kids.flat()) n.append(k?.nodeType ? k : document.createTextNode(k));
  return n;
};
const esc = s => String(s ?? '').replace(/[<>&]/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;' }[c]));

const state = { bid: null, data: null, tab: 'findings', charts: [],
                gcRun: null, logFrom: '', logTo: '', pii: null,
                piiError: null, piiRunning: false,
                piiFilter: null, piiShowAll: false, piiQuery: '', piiReveal: false,
                fxFilter: null, bundleList: null, cmp: null, cmpA: null, cmpB: null,
                sanitise: null, sanitiseKeep: {} };

const TABS = [
  ['findings', 'Findings'], ['overview', 'Overview'], ['reboots', 'Restarts'],
  ['forensics', 'Restart causes'], ['compare', 'Compare'],
  ['cpu', 'CPU'], ['memory', 'Memory'], ['logs', 'Log signals'],
  ['processes', 'Processes'], ['network', 'Network devices'],
  ['history', 'History'], ['privacy', 'Privacy'],
  ['ramoops', 'Ramoops'], ['browse', 'Browse files'],
];

// ---------- formatting ----------
const fmtKB = kb => kb == null ? '-'
  : kb >= 1048576 ? (kb / 1048576).toFixed(2) + ' GB'
  : kb >= 1024 ? (kb / 1024).toFixed(0) + ' MB' : kb + ' KB';
const fmtDur = s => {
  if (s == null) return '-';
  // Comparisons produce negative values, so choose the unit from the
  // magnitude and put the sign back afterwards.
  const sign = s < 0 ? '-' : '';
  const a = Math.abs(s);
  if (a >= 86400) return sign + (a / 86400).toFixed(1) + ' d';
  if (a >= 3600) return sign + (a / 3600).toFixed(1) + ' h';
  return sign + Math.round(a / 60) + ' min';
};
const fmtTime = iso => iso ? iso.replace('T', ' ').replace(/(\+00:00|Z)$/, '').slice(0, 16) + ' UTC' : '-';
const fmtDate = iso => iso ? iso.slice(0, 10) : '-';

// ---------- data ----------
async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error((await r.text()).slice(0, 300) || r.statusText);
  const ct = r.headers.get('content-type') || '';
  return ct.includes('json') ? r.json() : r.text();
}

async function loadBundles(select) {
  const list = await api('/api/bundles');
  const sel = $('#bundleSel');
  sel.replaceChildren(...list.map(b => el('option', { value: b.id, textContent: b.id })));
  const wanted = readHash().bundle;
  if (list.length) {
    sel.value = select
      || (list.some(b => b.id === wanted) ? wanted : list[list.length - 1].id);
    return sel.value;
  }
  return null;
}

function readHash() {
  const out = {};
  for (const part of (location.hash || '').replace(/^#/, '').split('&')) {
    const [k, v] = part.split('=');
    if (k && v) out[k] = decodeURIComponent(v);
  }
  return out;
}

function writeHash() {
  const bits = [];
  if (state.bid) bits.push('bundle=' + encodeURIComponent(state.bid));
  if (state.tab) bits.push('tab=' + encodeURIComponent(state.tab));
  const next = '#' + bits.join('&');
  if (location.hash !== next) history.replaceState(null, '', next);
}

// Everything held per bundle rather than per session. A privacy report, or a
// failure, or a cleaned copy belongs to the bundle it was produced from and
// means nothing against another one - and on the Privacy tab in particular,
// showing one bundle's secrets under another's name is the worst place to get
// this wrong.
function forgetBundleWork() {
  state.pii = null;
  state.piiError = null;
  state.piiRunning = false;
  state.piiFilter = null;
  state.piiQuery = '';
  state.piiShowAll = false;
  state.sanitise = null;
}

async function loadAnalysis(bid, refresh) {
  if (bid !== state.bid) forgetBundleWork();
  state.bid = bid;
  render(el('div', { className: 'card' }, el('span', { className: 'spin' }), ' Analyzing bundle…'));
  try {
    state.data = await api(`/api/bundle/${encodeURIComponent(bid)}/analysis` + (refresh ? '?refresh=true' : ''));
  } catch (e) {
    render(el('div', { className: 'finding critical' }, el('h4', {}, 'Analysis failed'), el('p', {}, e.message)));
    return;
  }
  const d = state.data.overview.device;
  $('#devsub').textContent = `${d.name} · ${state.data.overview.firmware}`;
  drawTabs();
  const wanted = readHash().tab;
  show(TABS.some(([k]) => k === wanted) ? wanted : state.tab);
}

// ---------- shell ----------
function render(...nodes) {
  state.charts.forEach(c => c.destroy());
  state.charts = [];
  $('#main').replaceChildren(...nodes.flat());
}

function drawTabs() {
  $('#tabs').replaceChildren(...TABS.map(([k, label]) => {
    const b = el('button', { textContent: label, onclick: () => show(k) });
    if (k === state.tab) b.classList.add('active');
    return b;
  }));
}

// A privacy scan or a cleaned copy takes minutes to come back, and render()
// replaces #main with whatever it is given regardless of what is in there. The
// tabs are buttons rather than a container that owns its content, so without
// this check a result painted itself over whichever tab had been opened while
// it ran, underneath that tab's still-underlined heading. The result is held
// in state either way, so going back to the tab shows it.
function repaintIf(tab, view) {
  if (state.tab === tab) view();
}

function show(tab) {
  state.tab = tab;
  writeHash();
  drawTabs();
  ({ findings: viewFindings, overview: viewOverview, reboots: viewReboots,
     forensics: viewForensics, compare: viewCompare,
     cpu: viewCpu, memory: viewMemory, logs: viewLogs, processes: viewProcesses,
     network: viewNetwork, history: viewHistory, privacy: viewPrivacy,
     ramoops: viewRamoops, browse: viewBrowse })[tab]();
}

// ---------- views ----------
function viewFindings() {
  const { findings, counts } = state.data.findings;
  const order = ['critical', 'major', 'minor', 'info'];
  const summary = el('div', { className: 'grid' },
    ...order.map(sev => el('div', { className: 'card' },
      el('h3', {}, sev),
      el('div', { className: 'stat' }, String(counts[sev] || 0),
        el('small', {}, ' finding' + ((counts[sev] || 0) === 1 ? '' : 's'))))));

  const list = findings.map(f => {
    const node = el('div', { className: 'finding ' + f.severity },
      el('h4', {}, el('span', { className: 'badge ' + f.severity }, f.severity), f.title),
      el('p', {}, f.detail));
    if (f.evidence?.length) {
      const pre = el('pre', {},
        f.evidence.map(e => `${e.time ? e.time.slice(0, 19) + '  ' : ''}${e.line}`).join('\n'));
      node.append(el('details', { className: 'evidence' },
        el('summary', {}, `Evidence (${f.evidence.length} sample${f.evidence.length === 1 ? '' : 's'})`), pre));
    }
    return node;
  });

  render(summary, el('h2', { style: 'font-size:17px;margin:24px 0 12px' }, 'What the bundle shows'),
    list.length ? list : el('div', { className: 'card' }, 'No findings, nothing notable detected.'));
}

function viewOverview() {
  const o = state.data.overview;
  const m = o.memory, s = o.snapshot || {};
  const availPct = m.total_kb ? (m.available_kb / m.total_kb * 100) : 0;

  const cards = el('div', { className: 'grid' },
    el('div', { className: 'card' }, el('h3', {}, 'Device'),
      el('div', { className: 'stat' }, o.device.shortname || o.device.name),
      el('div', { className: 'muted small' }, o.device.name)),
    el('div', { className: 'card' }, el('h3', {}, 'Firmware'),
      el('div', { className: 'stat', style: 'font-size:17px' }, o.firmware || '-'),
      el('div', { className: 'muted small' }, 'kernel ' + (o.kernel || '-'))),
    el('div', { className: 'card' }, el('h3', {}, 'Uptime at capture'),
      el('div', { className: 'stat' }, s.uptime || '-'),
      el('div', { className: 'muted small' }, 'load ' + (s.load ? s.load.join(' / ') : '-'))),
    el('div', { className: 'card' }, el('h3', {}, 'Memory available'),
      el('div', { className: 'stat' }, availPct.toFixed(0) + '%'),
      el('div', { className: 'muted small' }, `${fmtKB(m.available_kb)} of ${fmtKB(m.total_kb)}`)));

  const info = el('div', { className: 'card', style: 'margin-top:15px' },
    el('h3', {}, 'Hardware'),
    el('dl', { className: 'kv' },
      ...[['Model', o.device.name], ['CPU', o.device.cpu],
          ['Serial', o.device.serial], ['Board rev', o.device.board_rev],
          ['Manufactured', o.device.mfg_week],
          ['RAM', fmtKB(o.device.ram_bytes / 1024)],
          ['Swap used', `${fmtKB(m.swap_used_kb)} of ${fmtKB(m.swap_total_kb)}`],
      ].flatMap(([k, v]) => [el('dt', {}, k), el('dd', {}, String(v || '-'))])));

  const disks = el('div', { className: 'table-wrap', style: 'margin-top:15px' },
    el('table', {},
      el('thead', {}, el('tr', {}, ...['Mount', 'Filesystem', 'Size', 'Used', 'Avail', 'Use%']
        .map(h => el('th', {}, h)))),
      el('tbody', {}, ...o.storage.map(r => {
        const tr = el('tr', {}, el('td', {}, r.mount), el('td', { className: 'num' }, r.fs),
          el('td', { className: 'num' }, r.size), el('td', { className: 'num' }, r.used),
          el('td', { className: 'num' }, r.avail), el('td', { className: 'num' }, r.use_pct + '%'));
        if (r.use_pct >= 97) tr.className = 'bad';
        else if (r.use_pct >= 90) tr.className = 'warn';
        return tr;
      }))));

  const sm = o.smart || {};
  const smart = el('div', { className: 'card', style: 'margin-top:15px' },
    el('h3', {}, 'Disk SMART'),
    el('div', { className: 'muted small', style: 'margin-bottom:9px' },
      `${sm.model || 'unknown disk'}, health: ${sm.health || 'unknown'}`),
    sm.attrs?.length
      ? el('div', { className: 'table-wrap' }, el('table', {},
          el('thead', {}, el('tr', {}, ...['ID', 'Attribute', 'Value', 'Worst', 'Thresh', 'Raw']
            .map(h => el('th', {}, h)))),
          el('tbody', {}, ...sm.attrs.map(a => el('tr', {},
            el('td', { className: 'num' }, String(a.id)), el('td', {}, a.name),
            el('td', { className: 'num' }, String(a.value)), el('td', { className: 'num' }, String(a.worst)),
            el('td', { className: 'num' }, String(a.thresh)), el('td', { className: 'num' }, a.raw))))))
      : el('div', { className: 'muted small' }, 'No SMART attributes parsed.'));

  render(cards, info, el('h2', { style: 'font-size:17px;margin:24px 0 0' }, 'Storage'), disks, smart);
}

function viewReboots() {
  const { boots, stats } = state.data.boots;
  const cards = el('div', { className: 'grid' },
    el('div', { className: 'card' }, el('h3', {}, 'Reboots (30 days)'),
      el('div', { className: 'stat' }, String(stats.reboots_last_30d ?? '-'))),
    el('div', { className: 'card' }, el('h3', {}, 'Median uptime'),
      el('div', { className: 'stat' }, fmtDur(stats.median_uptime_s))),
    el('div', { className: 'card' }, el('h3', {}, 'Boots recorded'),
      el('div', { className: 'stat' }, String(stats.count ?? '-'),
        el('small', {}, ` since ${fmtDate(stats.first_boot)}`))),
    el('div', { className: 'card' }, el('h3', {}, 'Classified'),
      el('div', { className: 'stat', style: 'font-size:19px' },
        `${stats.clean_count} clean · ${stats.unclean_count} unclean`),
      el('div', { className: 'muted small' }, `${stats.unknown_count} unknown`)));

  const note = el('div', { className: 'card', style: 'margin-top:15px' },
    el('h3', {}, 'How these are classified'),
    el('p', { className: 'small muted', style: 'margin:0' },
      `A reboot is "clean" when the systemd shutdown cascade appears in the logs before it, ` +
      `"unclean" when logging ran up to the reboot without one (a hang, watchdog reset, or ` +
      `power loss), and "unknown" when the log that carries the cascade had already rotated ` +
      `away. On this firmware only ${(stats.cascade_sources || []).join(', ') || 'none'} carries it, ` +
      `so causes are only determinable from ${fmtDate(stats.classifiable_from)} onward. ` +
      `Boot times come from ${stats.boot_source}.`));

  const rows = [...boots].reverse().map(b => {
    const tr = el('tr', {},
      el('td', { className: 'num' }, fmtTime(b.time)),
      el('td', {}, el('span', { className: 'badge ' + b.cause }, b.cause)),
      el('td', { className: 'num' }, b.current ? 'current' : fmtDur(b.uptime_s)),
      el('td', { className: 'num' }, b.silent_gap_s != null ? Math.round(b.silent_gap_s) + ' s' : '-'),
      el('td', { className: 'small muted' }, b.confidence));
    if (b.cause === 'unclean') tr.className = 'bad';
    return tr;
  });

  const table = el('div', { className: 'table-wrap', style: 'margin-top:15px' },
    el('table', {}, el('thead', {}, el('tr', {},
      el('th', {}, 'Boot time'), el('th', {}, 'Cause'), el('th', {}, 'Ran for'),
      el('th', { title: 'Time between the last log line and the boot' }, 'Silent gap'),
      el('th', {}, 'Basis'))), el('tbody', {}, ...rows)));

  const chartBox = el('div', { className: 'chart-box', style: 'margin-top:15px' },
    el('h3', {}, 'Uptime per boot'),
    el('p', { className: 'note' }, 'How long each boot lasted before the next reboot.'),
    el('div', { className: 'chart-holder' }, el('canvas', { id: 'upChart' })));

  render(cards, note, chartBox, table);

  const pts = boots.filter(b => b.uptime_s);
  state.charts.push(new Chart($('#upChart'), {
    type: 'bar',
    data: {
      labels: pts.map(b => fmtDate(b.time)),
      datasets: [{
        label: 'Uptime (days)',
        data: pts.map(b => +(b.uptime_s / 86400).toFixed(2)),
        backgroundColor: pts.map(b => b.cause === 'unclean' ? '#c0263a'
          : b.cause === 'clean' ? '#4b93ff' : '#9aa3b2'),
      }],
    },
    options: chartOpts('days'),
  }));
}

function chartOpts(unit, extra = {}) {
  const grid = getComputedStyle(document.body).getPropertyValue('--border').trim();
  const tick = getComputedStyle(document.body).getPropertyValue('--muted').trim();
  return {
    responsive: true, maintainAspectRatio: false,
    interaction: { mode: 'index', intersect: false },
    plugins: { legend: { labels: { color: tick, boxWidth: 12, font: { size: 11 } } } },
    scales: {
      x: { ticks: { color: tick, maxRotation: 0, autoSkipPadding: 24, font: { size: 10 } },
           grid: { color: grid } },
      y: { title: { display: !!unit, text: unit, color: tick },
           ticks: { color: tick, font: { size: 10 } }, grid: { color: grid } },
    },
    ...extra,
  };
}

const PALETTE = ['#4b93ff', '#e2574c', '#f0b357', '#3fbf8f', '#a97bdb', '#4bc0c0',
  '#ff8fab', '#8cc63f', '#c0263a', '#7a8699', '#00a3a3', '#d97706'];

function viewCpu() {
  const c = state.data.cpu || {};
  const gc = state.data.gc || {};
  if (c.error) { render(el('div', { className: 'card' }, c.error)); return; }

  const labels = c.times.map(t => t.slice(5, 16).replace('T', ' '));
  const nodes = [];

  nodes.push(el('div', { className: 'grid' },
    el('div', { className: 'card' }, el('h3', {}, 'Peak total CPU'),
      el('div', { className: 'stat' }, c.peak_total_pct + '%'),
      el('div', { className: 'muted small' }, `of ${c.capacity_pct}% (${c.cores} cores)`)),
    el('div', { className: 'card' }, el('h3', {}, 'Hours near saturation'),
      el('div', { className: 'stat' }, String(c.saturated_intervals || 0)),
      el('div', { className: 'muted small' }, c.saturated_from
        ? `${fmtTime(c.saturated_from)} →` : 'above 75% of capacity')),
    el('div', { className: 'card' }, el('h3', {}, 'Runaway processes'),
      el('div', { className: 'stat' }, String((c.loops || []).length)),
      el('div', { className: 'muted small' },
        `≥${c.loop_threshold_pct}% of a core for ${2}+ hours`)),
    el('div', { className: 'card' }, el('h3', {}, 'Busiest process'),
      el('div', { className: 'stat', style: 'font-size:19px' },
        c.processes?.[0]?.name || '-'),
      el('div', { className: 'muted small' }, 'peak ' + (c.processes?.[0]?.peak_pct ?? '-') + '%'))));

  nodes.push(el('div', { className: 'card', style: 'margin-top:15px' },
    el('h3', {}, 'How this is measured'),
    el('p', { className: 'small muted', style: 'margin:0' },
      `The support file contains no CPU time series, only a single instant from ` +
      `top. These figures are reconstructed by differencing each process's ` +
      `cumulative CPU tick counters between consecutive hourly snapshots, so every ` +
      `point is an hourly average. 100% means one core fully consumed; this device ` +
      `has ${c.cores}, so ${c.capacity_pct}% is everything it has.` +
      (c.intervals_skipped_over_boot
        ? ` ${c.intervals_skipped_over_boot} interval(s) spanning a reboot were dropped, since the counters reset.`
        : ''))));

  for (const loop of (c.loops || [])) {
    nodes.push(el('div', { className: 'finding critical' },
      el('h4', {}, el('span', { className: 'badge critical' }, 'runaway'),
        `${loop.name}, peaked at ${loop.peak_pct}%`),
      el('p', {}, `Held above ${c.loop_threshold_pct}% of a core for ` +
        `${loop.sustained_intervals} consecutive hour(s), through ${fmtTime(loop.sustained_until)}. ` +
        `Mean across the window was ${loop.mean_pct}%, so this is a departure from its ` +
        `normal behaviour, not its usual load. Peak thread count ${loop.peak_threads}.`)));
  }

  nodes.push(el('div', { className: 'chart-box', style: 'margin-top:15px' },
    el('h3', {}, 'CPU by process'),
    el('p', { className: 'note' },
      `Hourly average CPU per process. The dashed line is total capacity ` +
      `(${c.capacity_pct}%). Click a legend entry to hide it.`),
    el('div', { className: 'chart-holder', style: 'height:340px' },
      el('canvas', { id: 'cpuChart' }))));

  // ---- memory-cleanup panel ----
  if (gc.available) {
    const runs = gc.runs || [];
    if (state.gcRun == null || !runs.some(r => r.id === state.gcRun))
      state.gcRun = gc.worst_run_id ?? runs[0]?.id ?? 0;
    const run = runs.find(r => r.id === state.gcRun) || gc;
    const w = run.worst_spiral;

    nodes.push(el('h2', { style: 'font-size:17px;margin:26px 0 12px' },
      'UniFi Network app, memory cleanup'));

    if (runs.length > 1) {
      const sel = el('select', {
        onchange: e => { state.gcRun = +e.target.value; viewCpu(); },
      }, ...runs.map(r => el('option', {
        value: r.id, selected: r.id === state.gcRun,
        textContent: `${r.start_wall ? fmtDate(r.start_wall) : 'undated'} → ` +
          `${r.end_wall ? fmtDate(r.end_wall) : '?'}  ·  ${(r.span_s / 3600).toFixed(0)}h · ` +
          `${r.full_gc_count.toLocaleString()} full cleanup pass` +
          ((r.worst_spiral?.duration_s || 0) >= 600 ? '  ⚠ ran out of memory' : '  · healthy'),
      })));
      nodes.push(el('div', { className: 'card', style: 'margin-bottom:15px' },
        el('h3', {}, `Network application run (${runs.length} retained)`),
        el('div', { className: 'row', style: 'margin-bottom:8px' }, sel),
        el('p', { className: 'small muted', style: 'margin:0' },
          `Each run is one lifetime of the Network app between restarts. memory-cleanup logs rotate ` +
          `independently of the kernel log, so these are separate windows rather than a ` +
          `continuous record, reboots falling in the gaps cannot be assessed. ` +
          `Selected run used ${run.collectors.join(', ')} and came from ` +
          `${run.sources.join(', ')}.`)));
    }

    nodes.push(el('div', { className: 'grid' },
      el('div', { className: 'card' }, el('h3', {}, 'Full cleanup passes'),
        el('div', { className: 'stat' }, run.full_gc_count.toLocaleString()),
        el('div', { className: 'muted small' }, run.collections.toLocaleString() + ' total')),
      el('div', { className: 'card' }, el('h3', {}, 'Lifetime spent tidying memory'),
        el('div', { className: 'stat' }, Math.round((run.gc_time_fraction || 0) * 100) + '%'),
        el('div', { className: 'muted small' }, 'across the whole run')),
      el('div', { className: 'card' }, el('h3', {}, 'Largest memory footprint'),
        el('div', { className: 'stat' }, Math.round(run.peak_heap_mb) + ' MB'),
        el('div', { className: 'muted small' },
          run.mean_full_freed_mb != null ? `each full pass frees ~${run.mean_full_freed_mb} MB` : '')),
      el('div', { className: 'card' }, el('h3', {}, 'Final hour spent tidying memory'),
        el('div', { className: 'stat' },
          run.final_hour ? Math.round(run.final_hour.gc_time_fraction * 100) + '%' : '-'),
        el('div', { className: 'muted small' },
          run.final_hour ? `${run.final_hour.full_gc_count.toLocaleString()} full cleanup passes` : ''))));

    if (w) {
      nodes.push(el('div', { className: 'finding critical', style: 'margin-top:15px' },
        el('h4', {}, el('span', { className: 'badge critical' }, 'deadlock'),
          `${(w.duration_s / 3600).toFixed(1)} hours of continuous collection`),
        el('p', {}, `${fmtTime(w.from_wall)} → ${fmtTime(w.to_wall)}. ` +
          `${w.gc_time_fraction * 100 | 0}% of the time spent freeing memory, across ` +
          `${w.full_gc_count.toLocaleString()} full collections, each freeing about ` +
          `${w.mean_freed_mb} MB against a working set stuck near ${Math.round(w.peak_heap_mb)} MB. ` +
          `The collector reclaims almost nothing and immediately runs again; its parallel ` +
          `threads are what consumed the cores.`)));
    }

    nodes.push(el('div', { className: 'chart-box' },
      el('h3', {}, 'Memory cleanup effort over time'),
      el('p', { className: 'note' },
        'Share of wall-clock time spent collecting, and its working memory size it kept ' +
        'failing to reduce. Sustained values near 100% are the problem.'),
      el('div', { className: 'chart-holder' }, el('canvas', { id: 'gcChart' }))));

    nodes.push(el('div', { className: 'card' },
      el('h3', {}, 'Last collections before the device went down'),
      el('pre', {}, run.last_lines.map(l =>
        `${(l.wall || (l.uptime_s + 's')).slice(0, 19).replace('T', ' ')}  ${l.kind.padEnd(14)}` +
        ` ${String(Math.round(l.before_mb)).padStart(4)}MB -> ${String(Math.round(l.after_mb)).padStart(4)}MB` +
        `  ${l.ms.toFixed(0)}ms`).join('\n'))));
  }

  const selectedRunBuckets = gc.available
    ? ((gc.runs || []).find(r => r.id === state.gcRun) || gc).buckets
    : null;

  const rows = (c.processes || []).map(p => {
    const tr = el('tr', {},
      el('td', {}, p.name),
      el('td', { className: 'num' }, p.peak_pct + '%'),
      el('td', { className: 'num' }, p.mean_pct + '%'),
      el('td', { className: 'num' }, p.last_pct + '%'),
      el('td', { className: 'num' }, String(p.peak_threads)),
      el('td', { className: 'num' }, p.sustained_intervals ? p.sustained_intervals + ' h' : '-'));
    if (p.sustained_intervals >= 2) tr.className = 'bad';
    else if (p.peak_pct >= 100) tr.className = 'warn';
    return tr;
  });
  nodes.push(el('div', { className: 'table-wrap' }, el('table', {},
    el('thead', {}, el('tr', {},
      el('th', {}, 'Process'), el('th', {}, 'Peak'), el('th', {}, 'Mean'),
      el('th', {}, 'Latest'), el('th', {}, 'Threads'),
      el('th', { title: 'Longest run of consecutive hours above one core' }, 'Sustained'))),
    el('tbody', {}, ...rows))));

  render(nodes);

  const datasets = (c.processes || []).map((p, i) => ({
    label: p.name,
    data: p.pct.map(v => v == null ? null : v),
    borderColor: PALETTE[i % PALETTE.length], pointRadius: 0,
    borderWidth: 1.8, tension: .25, spanGaps: true,
  }));
  datasets.push({
    label: `capacity (${c.capacity_pct}%)`,
    data: labels.map(() => c.capacity_pct),
    borderColor: '#7a8699', borderDash: [6, 4], borderWidth: 1,
    pointRadius: 0, fill: false,
  });
  state.charts.push(new Chart($('#cpuChart'), {
    type: 'line', data: { labels, datasets }, options: chartOpts('% of one core'),
  }));

  if (gc.available && selectedRunBuckets?.length) {
    const b = selectedRunBuckets;
    state.charts.push(new Chart($('#gcChart'), {
      type: 'line',
      data: {
        labels: b.map(x => (x.wall || '').slice(5, 16).replace('T', ' ')),
        datasets: [
          { label: 'Time spent tidying memory (%)', data: b.map(x => +(x.gc_fraction * 100).toFixed(1)),
            borderColor: '#e2574c', backgroundColor: '#e2574c22', fill: true,
            pointRadius: 0, borderWidth: 2, tension: .2, yAxisID: 'y' },
          { label: 'Memory in use before cleanup (MB)', data: b.map(x => x.heap_mb),
            borderColor: '#a97bdb', pointRadius: 0, borderWidth: 1.5,
            tension: .2, yAxisID: 'y1' },
        ],
      },
      options: {
        ...chartOpts('% of wall time'),
        scales: {
          ...chartOpts('% of wall time').scales,
          y: { ...chartOpts('% of wall time').scales.y, min: 0, max: 100 },
          y1: { position: 'right', grid: { drawOnChartArea: false },
                title: { display: true, text: 'MB' },
                ticks: { font: { size: 10 } } },
        },
      },
    }));
  }
}

function viewMemory() {
  const m = state.data.memory;
  if (m.error) { render(el('div', { className: 'card' }, m.error)); return; }
  if (!m.snapshot_count) {
    render(el('div', { className: 'card' }, 'No memory snapshots in this bundle.'));
    return;
  }
  const labels = m.times.map(t => t.slice(5, 16).replace('T', ' '));

  const head = el('div', { className: 'grid' },
    el('div', { className: 'card' }, el('h3', {}, 'Trend window'),
      el('div', { className: 'stat' }, m.window_days.toFixed(1) + ' d'),
      el('div', { className: 'muted small' }, m.snapshot_count + ' hourly snapshots')),
    el('div', { className: 'card' }, el('h3', {}, 'Available memory trend'),
      el('div', { className: 'stat' }, (m.avail_slope_kb_per_day / 1024).toFixed(0) + ' MB/d'),
      el('div', { className: 'muted small' }, 'fit r² = ' + m.avail_r2)),
    el('div', { className: 'card' }, el('h3', {}, 'Lowest available'),
      el('div', { className: 'stat' }, fmtKB(Math.min(...m.mem_available_kb))),
      el('div', { className: 'muted small' }, 'of ' + fmtKB(m.mem_total_kb))),
    el('div', { className: 'card' }, el('h3', {}, 'Peak swap used'),
      el('div', { className: 'stat' }, fmtKB(Math.max(...m.swap_used_kb)))));

  const box1 = el('div', { className: 'chart-box', style: 'margin-top:15px' },
    el('h3', {}, 'System memory over time'),
    el('p', { className: 'note' },
      'MemAvailable is the number that matters, free memory alone looks alarming on Linux ' +
      'because the kernel deliberately fills it with cache.'),
    el('div', { className: 'chart-holder' }, el('canvas', { id: 'memChart' })));

  const box2 = el('div', { className: 'chart-box' },
    el('h3', {}, 'Per-process resident memory'),
    el('p', { className: 'note' }, 'Top processes by peak memory in use. Click a legend entry to hide it.'),
    el('div', { className: 'chart-holder', style: 'height:340px' }, el('canvas', { id: 'procChart' })));

  const rows = m.processes.map(p => {
    const grow = p.slope_kb_per_day;
    const tr = el('tr', {},
      el('td', {}, p.name),
      el('td', { className: 'num' }, fmtKB(p.peak_kb)),
      el('td', { className: 'num' }, fmtKB(p.first_kb)),
      el('td', { className: 'num' }, fmtKB(p.last_kb)),
      el('td', { className: 'num' }, (grow >= 0 ? '+' : '') + (grow / 1024).toFixed(1) + ' MB/d'),
      el('td', { className: 'num' }, String(p.r2)));
    if (grow > 15360 && p.r2 >= 0.55) tr.className = 'warn';
    return tr;
  });
  const table = el('div', { className: 'table-wrap' },
    el('table', {}, el('thead', {}, el('tr', {},
      el('th', {}, 'Process'), el('th', {}, 'Peak memory in use'), el('th', {}, 'First'), el('th', {}, 'Last'),
      el('th', { title: 'Least-squares growth rate' }, 'Trend'),
      el('th', { title: 'Fit quality: 1.0 is a perfect straight line' }, 'r²'))),
      el('tbody', {}, ...rows)));

  render(head, box1, box2, table);

  const palette = PALETTE;

  state.charts.push(new Chart($('#memChart'), {
    type: 'line',
    data: {
      labels,
      datasets: [
        { label: 'MemAvailable', data: m.mem_available_kb.map(v => +(v / 1024).toFixed(0)),
          borderColor: '#4b93ff', backgroundColor: '#4b93ff22', fill: true,
          pointRadius: 0, borderWidth: 2, tension: .25 },
        { label: 'MemFree', data: m.mem_free_kb.map(v => +(v / 1024).toFixed(0)),
          borderColor: '#7a8699', pointRadius: 0, borderWidth: 1.5, tension: .25 },
        { label: 'Swap used', data: m.swap_used_kb.map(v => +(v / 1024).toFixed(0)),
          borderColor: '#e2574c', pointRadius: 0, borderWidth: 1.5, tension: .25 },
      ],
    },
    options: chartOpts('MB'),
  }));

  state.charts.push(new Chart($('#procChart'), {
    type: 'line',
    data: {
      labels,
      datasets: m.processes.map((p, i) => ({
        label: p.name,
        data: p.rss_kb.map(v => v == null ? null : +(v / 1024).toFixed(0)),
        borderColor: palette[i % palette.length], pointRadius: 0,
        borderWidth: 1.8, tension: .25, spanGaps: true,
      })),
    },
    options: chartOpts('MB'),
  }));
}

function viewLogs() {
  const all = state.data.logscan.patterns;
  if (!all.length) { render(el('div', { className: 'card' }, 'No known error signatures matched.')); return; }

  const from = state.logFrom || '', to = state.logTo || '';
  const inRange = t => (!from || (t && t >= from)) && (!to || (t && t <= to + 'T23:59:59'));
  const filtering = !!(from || to);

  // Filter by the sample timestamps we retained, so an older window can be
  // inspected rather than only the most recent occurrences.
  const pats = all.map(p => {
    if (!filtering) return p;
    const samples = p.samples.filter(s => inRange(s.time));
    return { ...p, samples, filtered: true };
  }).filter(p => !filtering || p.samples.length);

  const cov = state.data.coverage || {};
  const controls = el('div', { className: 'card' },
    el('h3', {}, 'Time range'),
    el('div', { className: 'row' },
      el('span', { className: 'small muted' }, 'From'),
      el('input', {
        type: 'date', value: from, style: 'flex:0 0 auto',
        onchange: e => { state.logFrom = e.target.value; viewLogs(); },
      }),
      el('span', { className: 'small muted' }, 'to'),
      el('input', {
        type: 'date', value: to, style: 'flex:0 0 auto',
        onchange: e => { state.logTo = e.target.value; viewLogs(); },
      }),
      el('button', {
        textContent: 'Clear',
        onclick: () => { state.logFrom = state.logTo = ''; viewLogs(); },
      })),
    el('p', { className: 'small muted', style: 'margin:0' },
      `Logs in this bundle run from ${fmtDate(cov.oldest)} to ${fmtDate(cov.newest)}, ` +
      `though each source covers a different slice, see the History tab. ` +
      (filtering
        ? 'Filtering applies to the retained sample lines, so counts below still reflect the whole bundle.'
        : 'Counts are across all retained history, not just recent logs.')));

  const nodes = pats.map(p => {
    const groups = Object.entries(p.groups || {});
    // everything this pattern matched was part of an orderly shutdown
    const onlyShutdown = p.count === 0 && p.shutdown_count > 0;
    const sev = onlyShutdown ? 'info' : p.severity;
    const body = el('div', { className: 'finding ' + sev },
      el('h4', {}, el('span', { className: 'badge ' + sev }, sev), p.title,
        el('span', { className: 'muted small' },
          onlyShutdown ? 'shutdown-time only' : `${p.count} matched`)),
      el('p', {}, onlyShutdown
        ? `All ${p.shutdown_count} occurrence(s) fell within ${state.data.logscan.shutdown_window_min} `
          + 'minutes of a reboot, which is what an orderly teardown looks like. Not a fault signal.'
        : (p.first_time ? `From ${fmtDate(p.first_time)} to ${fmtDate(p.last_time)}. ` : '') +
          (p.shutdown_count ? `${p.shutdown_count} further occurrence(s) during shutdown are excluded. ` : '') +
          (groups.length ? 'Concentrated on: ' + groups.map(([k, v]) => `${k} (${v})`).join(', ') + '.' : '')));
    if (p.samples.length) {
      body.append(el('details', { className: 'evidence' },
        el('summary', {}, `Show ${p.samples.length} sample line(s)`),
        el('pre', { className: 'tall' },
          p.samples.map(s => `${s.file}\n  ${s.line}`).join('\n'))));
    }
    return body;
  });
  render(controls,
    el('p', { className: 'muted small', style: 'margin:15px 0 12px' },
      `Lines matching a known failure signature. Occurrences within ` +
      `${state.data.logscan.shutdown_window_min} minutes before a reboot are counted separately, ` +
      `because an orderly teardown always produces service failures.`),
    nodes.length ? nodes
      : el('div', { className: 'card' }, 'No retained sample lines fall in that range.'));
}

function viewProcesses() {
  const a = state.data.procaudit || {};
  if (a.error) { render(el('div', { className: 'card' }, a.error)); return; }

  const nodes = [];
  const flagged = a.flagged || [];

  nodes.push(el('div', { className: 'grid' },
    el('div', { className: 'card' }, el('h3', {}, 'Suspect processes'),
      el('div', { className: 'stat', style: flagged.length ? 'color:var(--crit)' : '' },
        String(flagged.length)),
      el('div', { className: 'muted small' }, 'flagged for review')),
    el('div', { className: 'card' }, el('h3', {}, 'Distinct processes'),
      el('div', { className: 'stat' }, String(a.total_processes || 0)),
      el('div', { className: 'muted small' },
        `across ${a.snapshot_count || 0} snapshots`)),
    el('div', { className: 'card' }, el('h3', {}, 'Kernel threads'),
      el('div', { className: 'stat' }, String(a.kernel_threads || 0)),
      el('div', { className: 'muted small' }, 'structurally genuine')),
    el('div', { className: 'card' }, el('h3', {}, 'Unrecognized'),
      el('div', { className: 'stat' }, String(a.unrecognized || 0)),
      el('div', { className: 'muted small' }, 'not in the known stack'))));

  nodes.push(el('div', { className: 'card', style: 'margin-top:15px' },
    el('h3', {}, 'What this checks'),
    el('p', { className: 'small muted', style: 'margin:0' },
      `A UDM Pro is an appliance: its root filesystem is read-only and every stock ` +
      `process runs from a system path. So rather than matching malware signatures, ` +
      `this looks for processes running from writable storage, running a deleted ` +
      `binary, borrowing a kernel-thread name, loading libraries out of temporary ` +
      `storage, listening on unexpected ports, or running command lines that fetch ` +
      `and execute code. It runs over every retained snapshot, so a process that ` +
      `lived for one hour days ago is still caught, something a live process list ` +
      `would miss entirely. Findings are prompts to investigate, not verdicts: on an ` +
      `appliance an unrecognized process is more often a firmware change or an ` +
      `add-on you installed than an intrusion.`)));

  if (!flagged.length) {
    nodes.push(el('div', { className: 'finding info', style: 'margin-top:15px' },
      el('h4', {}, el('span', { className: 'badge info' }, 'clean'),
        'Nothing suspect found'),
      el('p', {}, `All ${a.total_processes} distinct processes ran from read-only ` +
        `system paths, and every listening socket resolved to a process that was ` +
        `actually present. That is the expected result for a healthy device.`)));
  }

  for (const e of flagged) {
    const worst = e.flags.reduce((w, f) =>
      ['critical', 'major', 'minor'].indexOf(f.severity) < ['critical', 'major', 'minor'].indexOf(w)
        ? f.severity : w, 'minor');
    const node = el('div', { className: 'finding ' + worst, style: 'margin-top:11px' },
      el('h4', {}, el('span', { className: 'badge ' + worst }, worst), e.comm,
        el('span', { className: 'muted small' }, e.exe || 'no executable mapping')),
      el('p', {}, `Seen in ${e.snapshots} snapshot(s), ${e.first_seen.slice(0, 16)} → ` +
        `${e.last_seen.slice(0, 16)}. ${e.pid_count} pid(s), peak ${e.peak_threads} ` +
        `thread(s), ${e.cpu_seconds}s CPU` +
        (e.user ? `, running as ${e.user}` : '') +
        (e.listening.length ? `. Listening: ${e.listening.join(', ')}` : '') + '.'),
      el('ul', { style: 'margin:9px 0 0;padding-left:19px' },
        ...e.flags.map(f => el('li', { className: 'small' },
          el('strong', {}, f.title), ', ', el('span', { className: 'muted' }, f.detail)))));
    if (e.cmdline) {
      node.append(el('details', { className: 'evidence' },
        el('summary', {}, 'Command line'), el('pre', {}, e.cmdline)));
    }
    nodes.push(node);
  }

  if (a.orphan_sockets?.length) {
    nodes.push(el('h2', { style: 'font-size:17px;margin:24px 0 12px' },
      'Listening sockets with no matching process'));
    nodes.push(el('div', { className: 'table-wrap' }, el('table', {},
      el('thead', {}, el('tr', {}, ...['Proto', 'Address', 'Port', 'Program', 'PID']
        .map(h => el('th', {}, h)))),
      el('tbody', {}, ...a.orphan_sockets.map(s => el('tr', { className: 'warn' },
        el('td', { className: 'num' }, s.proto), el('td', { className: 'num' }, s.addr),
        el('td', { className: 'num' }, s.port), el('td', {}, s.program),
        el('td', { className: 'num' }, s.pid)))))));
  }

  // Interesting rows first: flagged, then unrecognized userspace, then things
  // holding sockets, then the stock stack, with kernel threads last, they are
  // the bulk of the list and the least worth scrolling past.
  const rank = e => e.flags?.length ? 0
    : (!e.known && !e.kernel_thread) ? 1
    : e.listening.length ? 2
    : e.kernel_thread ? 4 : 3;
  const inv = [...(a.processes || [])].sort((x, y) =>
    rank(x) - rank(y) || (y.listening.length - x.listening.length) ||
    x.comm.localeCompare(y.comm));
  nodes.push(el('h2', { style: 'font-size:17px;margin:24px 0 12px' },
    `All processes seen (${inv.length})`));
  nodes.push(el('div', { className: 'table-wrap' }, el('table', {},
    el('thead', {}, el('tr', {}, ...['Process', 'Executable', 'Kind', 'CPU', 'Threads',
      'Listening', 'Last seen'].map(h => el('th', {}, h)))),
    el('tbody', {}, ...inv.map(e => {
      const kind = e.kernel_thread ? 'kernel' : e.known ? 'known' : 'unrecognized';
      const tr = el('tr', {},
        el('td', {}, e.comm),
        el('td', { className: 'num' }, e.exe || '-'),
        el('td', { className: 'small muted' }, kind + (e.transient ? ' · transient' : '')),
        el('td', { className: 'num' }, e.cpu_seconds + 's'),
        el('td', { className: 'num' }, String(e.peak_threads)),
        el('td', {
          className: 'num', title: e.listening.join('\n'),
          style: 'white-space:nowrap',
        }, e.listening.length
          ? (e.listening.length === 1 ? e.listening[0]
            : `${e.listening[0]} +${e.listening.length - 1}`)
          : '-'),
        el('td', { className: 'num', style: 'white-space:nowrap' },
          e.last_seen.slice(0, 16).replace('T', ' ')));
      if (e.flags?.length) tr.className = 'bad';
      else if (kind === 'unrecognized') tr.className = 'warn';
      return tr;
    })))));

  render(nodes);
}


function viewNetwork() {
  const n = state.data.lan;
  if (!n || !n.available) {
    render(el('div', { className: 'card' },
      (n && n.reason) || 'No connection table in this support file.'));
    return;
  }
  const nodes = [];

  nodes.push(el('div', { className: 'grid' },
    el('div', { className: 'card' }, el('h3', {}, 'Devices seen'),
      el('div', { className: 'stat' }, String(n.device_count)),
      el('div', { className: 'muted small' },
        `${n.named_devices} of them named`)),
    el('div', { className: 'card' }, el('h3', {}, 'Worth a look'),
      el('div', { className: 'stat', style: n.flagged_count ? 'color:var(--crit)' : '' },
        String(n.flagged_count)),
      el('div', { className: 'muted small' }, 'devices with something unusual')),
    el('div', { className: 'card' }, el('h3', {}, 'Connections out'),
      el('div', { className: 'stat' }, String(n.external_flows)),
      el('div', { className: 'muted small' },
        `of ${n.flows_total} open at capture`)),
    el('div', { className: 'card' }, el('h3', {}, 'Covers'),
      el('div', { className: 'stat', style: 'font-size:18px' }, 'One moment'),
      el('div', { className: 'muted small' }, 'not a period of time'))));

  nodes.push(el('div', { className: 'card', style: 'margin-top:15px' },
    el('h3', {}, 'What this can and cannot tell you'),
    el('p', { className: 'small muted', style: 'margin:0' },
      'This is the list of connections that happened to be open at the instant ' +
      'the support file was made, usually a few minutes’ worth. It is a ' +
      'photograph, not a recording. A device that phones home once an hour ' +
      'almost certainly will not appear here, so nothing on this page can be ' +
      'read as "that device was quiet". What it does show is anything that was ' +
      'mid-conversation at that moment, which is enough to catch a device ' +
      'talking somewhere it should not.')));

  for (const d of n.flagged) {
    const node = el('div', { className: 'finding ' + d.severity, style: 'margin-top:11px' },
      el('h4', {}, el('span', { className: 'badge ' + d.severity }, d.severity),
        (d.name || d.ip),
        el('span', { className: 'muted small' },
          `  ${d.ip}${d.mac ? ' · ' + d.mac : ''}` +
          `${d.interface ? ' · ' + d.interface : ''}`)),
      el('ul', { style: 'margin:8px 0 0;padding-left:19px' },
        ...d.findings.map(f => el('li', { className: 'small' },
          el('strong', {}, f.title),
          el('span', { className: 'muted' }, ': ' + f.detail)))));
    if (d.samples?.length) {
      node.append(el('details', { className: 'evidence' },
        el('summary', {}, 'Connections that were open'),
        el('pre', {}, d.samples.map(s =>
          `${s.proto.padEnd(4)} to ${s.dst}:${s.dport}  ` +
          `${s.packets} packets, ${s.bytes} bytes`).join('\n'))));
    }
    nodes.push(node);
  }

  if (n.notable_ports?.length) {
    nodes.push(el('div', { className: 'card', style: 'margin-top:15px' },
      el('h3', {}, 'Ports worth noticing, across all devices'),
      el('div', { className: 'small', style: 'font-family:var(--mono)' },
        n.notable_ports.map(([p, c]) => `${p} (${c})`).join('  ·  '))));
  }

  nodes.push(el('h2', { style: 'font-size:17px;margin:24px 0 12px' },
    `Every device that was talking out (${n.devices.length})`));
  nodes.push(el('div', { className: 'table-wrap' }, el('table', {},
    el('thead', {}, el('tr', {}, ...['Device', 'Address', 'Hardware address',
      'Network', 'Connections', 'Places reached', 'Data', 'Busiest ports']
      .map(h => el('th', {}, h)))),
    el('tbody', {}, ...n.devices.map(d => {
      const tr = el('tr', {},
        el('td', {}, d.name || el('span', { className: 'muted' }, 'not named')),
        el('td', { className: 'num' }, d.ip),
        el('td', { className: 'num' }, d.mac || '-'),
        el('td', { className: 'num' }, d.interface || '-'),
        el('td', { className: 'num' }, String(d.flows)),
        el('td', { className: 'num' }, String(d.destination_count)),
        el('td', { className: 'num' }, fmtKB(Math.round(d.bytes / 1024))),
        el('td', { className: 'num small' },
          d.top_ports.map(([p, c]) => `${p}×${c}`).join(' ')));
      if (d.severity === 'critical' || d.severity === 'major') tr.className = 'bad';
      else if (d.severity) tr.className = 'warn';
      return tr;
    })))));

  render(nodes);
}

function viewHistory() {
  const c = state.data.coverage;
  if (!c) { render(el('div', { className: 'card' }, 'No coverage data.')); return; }

  // A source counts towards the timeline only if both its ends can actually be
  // turned into a date. A log whose timestamps the parser did not recognise
  // arrives here with from and to null, and one unreadable date poisons the
  // whole scale, so both are excluded rather than left to become NaN.
  const dated = c.sources.filter(s =>
    s.from && s.to && !isNaN(Date.parse(s.from)) && !isNaN(Date.parse(s.to)));

  const table = el('div', { className: 'table-wrap', style: 'margin-top:15px' },
    el('table', {},
      el('thead', {}, el('tr', {}, ...['Source', 'Path', 'Files', 'From', 'To', 'Span', 'Notes']
        .map(h => el('th', {}, h)))),
      el('tbody', {}, ...c.sources.map(s => el('tr', {},
        el('td', {}, s.label),
        el('td', { className: 'num' }, s.path),
        el('td', { className: 'num' }, String(s.files)),
        el('td', { className: 'num' }, s.from ? fmtDate(s.from) : '-'),
        el('td', { className: 'num' }, s.to ? fmtDate(s.to) : '-'),
        el('td', { className: 'num' }, s.days != null ? s.days + ' d' : '-'),
        el('td', { className: 'small muted' }, s.note || ''))))));

  // Nothing datable means there is no scale to draw the bars against, and
  // asking for one produces an invalid date rather than an empty chart. The
  // table still says which logs were found and, in its notes, why none of
  // them could be placed in time, so show that on its own.
  if (!dated.length) {
    render(
      el('div', { className: 'card' },
        el('h3', {}, 'How far back you can look'),
        el('p', { className: 'small muted', style: 'margin:0' },
          'No log in this bundle carries timestamps this tool could read, so ' +
          'none of them can be placed on a timeline and there is no retention ' +
          'chart to draw. The sources found are listed below; open them from ' +
          'Browse files to read them directly. Answers elsewhere in the tool ' +
          'that depend on dates will be missing for the same reason.')),
      table);
    return;
  }

  const t0 = Math.min(...dated.map(s => Date.parse(s.from)));
  const t1 = Math.max(...dated.map(s => Date.parse(s.to)));
  const span = Math.max(t1 - t0, 1);

  const intro = el('div', { className: 'card' },
    el('h3', {}, 'How far back you can look'),
    el('p', { className: 'small muted', style: 'margin:0' },
      `Every answer this tool gives is bounded by what the device still had on disk ` +
      `when the support file was made, and those limits differ enormously between ` +
      `sources. The bundle spans ${fmtDate(c.oldest)} to ${fmtDate(c.newest)} overall, ` +
      `but no single source covers all of it. Bars below are drawn against that full ` +
      `range, so a short bar means questions about earlier dates cannot be answered ` +
      `from that source at all, not that nothing happened.`));

  // A shared scale, drawn once above the bars. Without it every short bar sits
  // against the right edge with nothing to measure against, and reads as a
  // right-aligned progress bar rather than as a position in time.
  const axisDate = f => {
    const d = new Date(t0 + span * f);
    return d.toISOString().slice(0, 10);
  };
  const TICKS = [0, 0.25, 0.5, 0.75, 1];
  const gridline =
    'background-image:repeating-linear-gradient(to right,' +
    'var(--border) 0 1px, transparent 1px 25%);';

  const axis = el('div', { style: 'margin:4px 0 14px' },
    el('div', { style: 'position:relative;height:7px' },
      ...TICKS.map(f => el('div', {
        style: `position:absolute;left:${f * 100}%;top:0;bottom:0;width:1px;` +
          'background:var(--border)',
      }))),
    el('div', { style: 'position:relative;height:16px' },
      ...TICKS.map((f, i) => el('div', {
        className: 'small muted',
        style: `position:absolute;left:${f * 100}%;white-space:nowrap;` +
          (i === 0 ? '' : i === TICKS.length - 1
            ? 'transform:translateX(-100%)' : 'transform:translateX(-50%)'),
        textContent: axisDate(f),
      }))));

  const bars = dated.map(s => {
    const a = (Date.parse(s.from) - t0) / span * 100;
    const w = Math.max((Date.parse(s.to) - Date.parse(s.from)) / span * 100, 0.6);
    return el('div', { style: 'margin-bottom:11px' },
      el('div', { className: 'small', style: 'display:flex;justify-content:space-between;gap:10px' },
        el('span', {}, s.label),
        el('span', { className: 'muted' }, `${s.days} d · ${fmtDate(s.from)} → ${fmtDate(s.to)}`)),
      el('div', {
        title: `${s.label}: ${fmtDate(s.from)} to ${fmtDate(s.to)}`,
        style: 'position:relative;height:9px;background:var(--panel-2);' +
          'border:1px solid var(--border);border-radius:5px;margin-top:4px;' +
          gridline,
      },
        el('div', {
          style: `position:absolute;left:${a}%;width:${w}%;top:0;bottom:0;` +
            `background:${s.days >= 60 ? '#3fbf8f' : s.days >= 14 ? '#f0b357' : '#e2574c'};` +
            'border-radius:5px',
        })));
  });

  render(intro,
    el('div', { className: 'card', style: 'margin-top:15px' },
      el('h3', {}, 'Retention by source'),
      el('p', { className: 'small muted', style: 'margin:0 0 4px' },
        'Each bar is placed on the timeline below, not measured from the left. ' +
        'Every log runs up to the moment the support file was made, so they all ' +
        'finish at the right-hand edge and a short bar means the log only ' +
        'reaches back a little way.'),
      axis, ...bars),
    table);
}


function sanitiseBlock() {
  const s = state.sanitise;
  const box = el('div', { className: 'card', style: 'margin-top:15px' },
    el('h3', {}, 'Make a copy that is safe to send'),
    el('p', { className: 'small muted' },
      'Writes a new support file with the private parts taken out, so you can ' +
      'send it to Ubiquiti or attach it to a forum post. Passwords, keys and ' +
      'tokens are removed outright. Addresses, hardware addresses, email ' +
      'addresses and domains are swapped for stand-ins from ranges reserved ' +
      'for documentation, and the same real value always becomes the same ' +
      'stand-in, so a device can still be followed from one log line to the ' +
      'next. Local addresses such as 10.x and 192.168.x are left alone, since ' +
      'they reveal nothing and the logs stop making sense without them.'));

  const keep = state.sanitiseKeep || {};
  const opts = [
    ['public_ip', 'Keep public addresses'],
    ['mac_address', 'Keep hardware addresses'],
    ['domain', 'Keep domain names'],
  ];
  box.append(el('div', { className: 'row', style: 'flex-wrap:wrap' },
    ...opts.map(([k, label]) => el('label',
      { className: 'small', style: 'display:flex;align-items:center;gap:6px' },
      el('input', {
        type: 'checkbox', checked: !!keep[k],
        onchange: e => {
          state.sanitiseKeep = { ...(state.sanitiseKeep || {}), [k]: e.target.checked };
        },
      }), label))));
  box.append(el('p', { className: 'small muted', style: 'margin:8px 0 0' },
    'Tick anything a support engineer has specifically asked to see. ' +
    'Passwords and keys are always removed and cannot be kept.'));

  box.append(el('div', { className: 'row', style: 'margin-top:11px' },
    el('button', {
      className: 'primary', textContent: 'Create cleaned copy',
      // Disabled from state, not from the click. `e.target.disabled` only ever
      // reached the one node that was clicked, and this whole block is rebuilt
      // every time the tab is drawn - so coming back to Privacy mid-run gave
      // you a spinner and a live button side by side, and a second run that
      // rewrites every file in the bundle again.
      disabled: !!s?.running,
      onclick: async () => {
        if (state.sanitise?.running) return;
        const bid = state.bid;
        state.sanitise = { running: true };
        repaintIf('privacy', viewPrivacy);
        let done = null, failure = null;
        try {
          const kept = Object.entries(state.sanitiseKeep || {})
            .filter(([, v]) => v).map(([k]) => k);
          done = await api(
            `/api/bundle/${encodeURIComponent(bid)}/sanitise`,
            { method: 'POST', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ keep: kept }) });
        } catch (err) {
          failure = err.message;
        }
        // A cleaned copy of another bundle is not this bundle's to offer.
        if (state.bid !== bid) return;
        state.sanitise = failure !== null ? { error: failure } : done;
        repaintIf('privacy', viewPrivacy);
      },
    })));

  if (s?.running) {
    box.append(el('p', { className: 'small' }, el('span', { className: 'spin' }),
      ' Rewriting every file, including compressed ones. This takes about as ' +
      'long as the scan did.'));
  } else if (s?.error) {
    box.append(el('p', { className: 'small', style: 'color:var(--crit)' },
      'Failed: ' + s.error));
  } else if (s?.archive) {
    const r = s.replacements || {};
    box.append(el('div', { className: 'finding info', style: 'margin-top:11px' },
      el('h4', {}, el('span', { className: 'badge info' }, 'ready'),
        'Cleaned copy created'),
      el('p', {}, `${s.files} files processed, ${s.rewritten} of them rewritten. ` +
        `Replaced ${r.public_ip || 0} public addresses, ` +
        `${r.mac_address || 0} hardware addresses, ${r.email || 0} email ` +
        `addresses and ${r.domain || 0} domains, each with a consistent ` +
        `stand-in.` +
        (s.kept?.length ? ` Left untouched at your request: ${s.kept.join(', ')}.` : '')),
      el('p', { className: 'small muted' },
        'Check it before sending. The Privacy tab can be pointed at the cleaned ' +
        'copy by loading it as a support file of its own.'),
      el('a', { className: 'button primary', href: s.download,
                textContent: `Download (${fmtKB(Math.round(s.archive_bytes / 1024))})` })));
  }
  return box;
}

async function viewPrivacy() {
  // A finished scan is cached server-side; show it without re-running.
  if (state.pii === null) {
    state.pii = undefined;  // "asked once, don't loop"
    try {
      const got = await api(`/api/bundle/${encodeURIComponent(state.bid)}/pii` +
        `?only_cached=true&reveal=${state.piiReveal ? 'true' : 'false'}`);
      if (!got.pending) { state.pii = got; }
    } catch { /* fall through to the run button */ }
    return viewPrivacy();
  }
  const p = state.pii || null;
  const intro = el('div', { className: 'card' },
    el('h3', {}, 'What leaves with this file'),
    el('p', { className: 'small muted' },
      `A support file is normally uploaded to Ubiquiti or attached to a forum ` +
      `post, and it carries far more than diagnostics, private keys, the WAN ` +
      `address, every DHCP hostname on your network, the domains those devices ` +
      `resolved, and whatever password or token fields the running config holds. ` +
      `This scan finds them so sharing is an informed decision.`),
    el('p', { className: 'small muted' },
      el('strong', {}, 'Counts are of distinct values. '),
      `One address repeated through a log is one exposure, not thousands, ` +
      `occurrence counts are shown alongside but are the less meaningful number.`),
    el('p', { className: 'small muted', style: 'margin:0' },
      el('strong', {}, 'Every value below is masked. '),
      `The scan reports where secrets are, never what they are, a report you ` +
      `had to handle as carefully as the file it describes would not help. ` +
      `It reads every text file in the bundle, so it runs only when you ask.`));

  if (!p) {
    // That a scan is running has to live in state, not only in the markup the
    // click happened to leave behind. Disabling the button that was clicked
    // says nothing about the button drawn the next time this tab is opened, so
    // without this a reader who stepped away and came back mid-scan was shown
    // a fresh Run button, as though nothing were happening, and clicking it
    // started a second scan of every file in the bundle.
    if (state.piiRunning) {
      render(intro, el('div', { className: 'card' },
        el('span', { className: 'spin' }),
        state.piiRunning === true
          ? ' Scanning every file in the bundle, this takes a couple of minutes.'
          : state.piiRunning));
      return;
    }

    // A failure is kept in state rather than painted straight out, for the
    // same reason the success is: by the time it arrives the user may be
    // reading another tab, and it should be waiting here when they return.
    const failed = state.piiError
      ? [el('div', { className: 'finding critical', style: 'margin-top:15px' },
          el('h4', {}, 'Scan failed'), el('p', {}, state.piiError))]
      : [];
    render(intro, ...failed,
      el('div', { className: 'card', style: 'margin-top:15px' },
        el('button', {
          className: 'primary', textContent: 'Run privacy scan',
          onclick: async () => {
            // Which bundle asked. The selector is live throughout, and a
            // report belongs to the bundle it was scanned from - showing one
            // bundle's secrets under another's name is the worst version of
            // this mistake, so a result that outlives its bundle is dropped
            // rather than stored.
            const bid = state.bid;
            state.piiRunning = true;
            state.piiError = null;
            repaintIf('privacy', viewPrivacy);
            let got = null, failure = null;
            try {
              got = await api(`/api/bundle/${encodeURIComponent(bid)}/pii` +
                `?reveal=${state.piiReveal ? 'true' : 'false'}`);
            } catch (err) {
              failure = err.message;
            }
            if (state.bid !== bid) return;
            state.piiRunning = false;
            if (failure !== null) state.piiError = failure; else state.pii = got;
            repaintIf('privacy', viewPrivacy);
          },
        }),
        el('span', { className: 'small muted', style: 'margin-left:11px' },
          'Results are cached per bundle.')));
    return;
  }

  const nodes = [intro];
  const crit = p.categories.filter(c => c.severity === 'critical');
  nodes.push(el('div', { className: 'grid', style: 'margin-top:15px' },
    el('div', { className: 'card' }, el('h3', {}, 'Files with findings'),
      el('div', { className: 'stat' }, String(p.file_count)),
      el('div', { className: 'muted small' }, `of ${p.scanned_files} scanned`)),
    el('div', { className: 'card' }, el('h3', {}, 'Distinct secrets'),
      el('div', { className: 'stat', style: crit.length ? 'color:var(--crit)' : '' },
        String(crit.reduce((n, c) => n + c.distinct, 0))),
      el('div', { className: 'muted small' }, 'keys, hashes, credential fields')),
    el('div', { className: 'card' }, el('h3', {}, 'Distinct identifiers'),
      el('div', { className: 'stat' },
        String(p.categories.filter(c => c.severity !== 'critical')
          .reduce((n, c) => n + c.distinct, 0))),
      el('div', { className: 'muted small' }, 'IPs, emails, MACs, domains')),
    el('div', { className: 'card' }, el('h3', {}, 'Skipped'),
      el('div', { className: 'stat' }, String(p.skipped_files)),
      el('div', { className: 'muted small' }, 'binary or non-text'))));

  nodes.push(el('h2', { style: 'font-size:17px;margin:24px 0 6px' }, 'By category'));
  nodes.push(el('p', { className: 'small muted', style: 'margin:0 0 10px' },
    'Select a row to list only the files containing that kind of finding.'));
  nodes.push(el('div', { className: 'table-wrap' }, el('table', { className: 'clickable' },
    el('thead', {}, el('tr', {},
      ...[['Category', ''], ['Severity', ''],
          ['Distinct values', 'How many different values would leave with the file'],
          ['Occurrences', 'How often they appear; one value repeated in a log inflates this'],
          ['Files', '']]
        .map(([h, t]) => el('th', t ? { title: t } : {}, h)))),
    el('tbody', {}, ...p.categories.map(c => {
      const active = state.piiFilter === c.key;
      const tr = el('tr', {
        style: 'cursor:pointer',
        title: `Show only the ${c.files} file(s) containing ${c.label}`,
        onclick: () => { state.piiFilter = active ? null : c.key; viewPrivacy(); },
      },
        el('td', {},
          el('span', { style: 'color:var(--accent);margin-right:7px' },
            active ? '▾' : '▸'),
          el('span', {
            style: 'text-decoration:underline;text-decoration-style:dotted;' +
              'text-underline-offset:3px',
          }, c.label)),
        el('td', {}, el('span', { className: 'badge ' + c.severity }, c.severity)),
        el('td', { className: 'num' }, c.distinct.toLocaleString()),
        el('td', { className: 'num muted' }, c.count.toLocaleString()),
        el('td', { className: 'num' }, String(c.files)));
      if (active) tr.className = 'warn';
      else if (c.severity === 'critical') tr.className = 'bad';
      return tr;
    })))));

  if (p.top_domains?.length) {
    nodes.push(el('h2', { style: 'font-size:17px;margin:24px 0 12px' },
      'Most-referenced external domains'));
    nodes.push(el('div', { className: 'card' },
      el('p', { className: 'small muted', style: 'margin-top:0' },
        'Registrable domain only, counted across the bundle. These reveal which ' +
        'services the network talks to.'),
      el('div', { className: 'small', style: 'font-family:var(--mono);line-height:1.9' },
        p.top_domains.map(([d, n]) => `${d} (${n})`).join('  ·  '))));
  }

  const filt = state.piiFilter;
  const catLabel = filt
    ? (p.categories.find(c => c.key === filt)?.label || filt) : null;
  const q = (state.piiQuery || '').trim().toLowerCase();
  let shown = filt
    ? p.files.filter(f => f.categories.some(c => c.key === filt))
    : p.files;
  if (q) {
    shown = shown.filter(f => f.path.toLowerCase().includes(q) ||
      f.categories.some(c => c.label.toLowerCase().includes(q) ||
        c.samples.some(s => s.toLowerCase().includes(q))));
  }
  // Everything renders: a cap meant Ctrl+F could not find a file the summary
  // said existed, which is worse than a long page.
  const limit = shown.length;

  nodes.push(el('div', { className: 'card', style: 'margin-top:15px' },
    el('div', { className: 'row' },
      el('input', {
        type: 'search', value: state.piiQuery || '', style: 'flex:1',
        placeholder: 'Filter by file path, category, or value…',
        oninput: e => { state.piiQuery = e.target.value; },
        onchange: e => { state.piiQuery = e.target.value; viewPrivacy(); },
        onkeydown: e => { if (e.key === 'Enter') { state.piiQuery = e.target.value; viewPrivacy(); } },
      }),
      el('button', {
        textContent: 'Search',
        onclick: () => viewPrivacy(),
      }),
      el('label', { className: 'small', style: 'display:flex;align-items:center;gap:6px' },
        el('input', {
          type: 'checkbox', checked: !!state.piiReveal,
          // The same scan, reached by a different control, so it has to be
          // held the same way: this one re-reads the whole bundle too, and
          // painting its result unconditionally is the very thing repaintIf
          // exists to stop.
          onchange: async e => {
            const bid = state.bid;
            state.piiReveal = e.target.checked;
            state.pii = undefined;
            state.piiError = null;
            // Truthy either way; the string is what the spinner says, since
            // this control's wait means something different to the reader.
            state.piiRunning = state.piiReveal
              ? ' Re-scanning with values revealed…'
              : ' Loading masked results…';
            repaintIf('privacy', viewPrivacy);
            let got = null, failure = null;
            try {
              got = await api(
                `/api/bundle/${encodeURIComponent(bid)}/pii` +
                `?reveal=${state.piiReveal ? 'true' : 'false'}`);
            } catch (err) { failure = err.message; }
            if (state.bid !== bid) return;
            state.piiRunning = false;
            if (failure !== null) state.piiError = failure; else state.pii = got;
            repaintIf('privacy', viewPrivacy);
          },
        }),
        'Reveal actual values')),
    el('p', { className: 'small muted', style: 'margin:9px 0 0' },
      state.piiReveal
        ? '⚠ Real secrets are on screen now. Do not screenshot or paste this view.'
        : 'Values are masked, so searching for an actual address or password will ' +
          'not match. Tick “Reveal actual values” to search for a real one, it ' +
          'stays on this machine.')));

  nodes.push(el('h2', { style: 'font-size:17px;margin:24px 0 12px' },
    filt ? `Files containing ${catLabel} (${shown.length})`
         : q ? `Files matching “${q}” (${shown.length})`
             : `Files containing sensitive data (${shown.length})`));

  if (filt) {
    nodes.push(el('div', { className: 'card', style: 'margin-bottom:11px' },
      el('span', {}, `Filtered to ${catLabel}. `),
      el('button', {
        textContent: 'Clear filter',
        onclick: () => { state.piiFilter = null; viewPrivacy(); },
      })));
  }
  for (const f of shown.slice(0, limit)) {
    nodes.push(el('div', { className: 'finding ' + f.severity, style: 'margin-top:11px' },
      el('h4', {}, el('span', { className: 'badge ' + f.severity }, f.severity), f.path),
      el('ul', { style: 'margin:8px 0 0;padding-left:19px' },
        ...f.categories.map(c => el('li', { className: 'small' },
          el('strong', {}, `${c.label}, ${c.distinct} distinct` +
            (c.count > c.distinct ? ` (${c.count} occurrences)` : '')),
          c.samples.length ? el('span', { className: 'muted' },
            ', ' + c.samples.join(', ')) : ''))),
      f.truncated ? el('p', { className: 'small muted', style: 'margin:7px 0 0' },
        `Only the first ${(p.max_bytes_per_file / 1048576).toFixed(0)} MB scanned; ` +
        'counts for this file are a lower bound.') : ''));
  }

  nodes.splice(1, 0, sanitiseBlock());
  render(nodes);
}


const CONF_LABEL = {
  high: 'strong evidence', medium: 'some evidence',
  low: 'little evidence', none: 'no records',
};

function viewForensics() {
  const f = state.data.forensics;
  if (!f || !f.reboots.length) {
    render(el('div', { className: 'card' }, 'No restarts recorded in this file.'));
    return;
  }
  const nodes = [];

  nodes.push(el('div', { className: 'grid' },
    el('div', { className: 'card' }, el('h3', {}, 'Restarts examined'),
      el('div', { className: 'stat' }, String(f.total)),
      el('div', { className: 'muted small' }, 'every restart in the file')),
    el('div', { className: 'card' }, el('h3', {}, 'With a likely cause'),
      el('div', { className: 'stat' }, String(f.explained)),
      el('div', { className: 'muted small' }, 'evidence points somewhere')),
    el('div', { className: 'card' }, el('h3', {}, 'Distinct patterns'),
      el('div', { className: 'stat' }, String(f.groups.length)),
      el('div', { className: 'muted small' }, 'more than one means more than one fault')),
    el('div', { className: 'card' }, el('h3', {}, 'Window examined'),
      el('div', { className: 'stat' }, f.window_hours + ' h'),
      el('div', { className: 'muted small' }, 'before each restart'))));

  nodes.push(el('div', { className: 'card', style: 'margin-top:15px' },
    el('h3', {}, 'How to read this'),
    el('p', { className: 'small muted', style: 'margin:0' },
      `For every restart, this gathers what the device recorded in the ` +
      `${f.window_hours} hours beforehand: warning signs in the logs, free memory, ` +
      `processor load, and how the Network application was coping. Restarts are ` +
      `then grouped by what the evidence suggests. If several groups appear, more ` +
      `than one thing is wrong, and fixing one will not stop the others. ` +
      `"Nothing was being recorded" is a statement about the logs, not the device: ` +
      `older restarts fall outside what the logs still reach, so nothing can be ` +
      `concluded about them either way.`)));

  nodes.push(el('h2', { style: 'font-size:17px;margin:24px 0 6px' }, 'Grouped by cause'));
  nodes.push(el('p', { className: 'small muted', style: 'margin:0 0 10px' },
    'Select a group to see only those restarts.'));
  nodes.push(el('div', { className: 'table-wrap' }, el('table', { className: 'clickable' },
    el('thead', {}, el('tr', {}, ...['Pattern', 'Restarts', 'Dates'].map(h => el('th', {}, h)))),
    el('tbody', {}, ...f.groups.map(g => {
      const active = state.fxFilter === g.pattern;
      const tr = el('tr', {
        style: 'cursor:pointer',
        title: `Show the ${g.count} restart(s) in this group`,
        onclick: () => { state.fxFilter = active ? null : g.pattern; viewForensics(); },
      },
        el('td', {},
          el('span', { style: 'color:var(--accent);margin-right:7px' }, active ? '▾' : '▸'),
          el('span', { style: 'text-decoration:underline;text-decoration-style:dotted;text-underline-offset:3px' }, g.pattern)),
        el('td', { className: 'num' }, String(g.count)),
        el('td', { className: 'num small muted' },
          g.times.slice(0, 4).map(t => t.slice(0, 10)).join(', ') +
          (g.times.length > 4 ? ` +${g.times.length - 4} more` : '')));
      if (active) tr.className = 'warn';
      return tr;
    })))));

  const shown = state.fxFilter
    ? f.reboots.filter(r => r.pattern === state.fxFilter) : f.reboots;
  nodes.push(el('h2', { style: 'font-size:17px;margin:24px 0 12px' },
    state.fxFilter ? `${state.fxFilter} (${shown.length})`
                   : `Every restart (${shown.length})`));
  if (state.fxFilter) {
    nodes.push(el('div', { className: 'card', style: 'margin-bottom:11px' },
      el('button', { textContent: 'Show all restarts',
        onclick: () => { state.fxFilter = null; viewForensics(); } })));
  }

  for (const r of shown) {
    const sev = r.confidence === 'high' ? 'critical'
      : r.confidence === 'medium' ? 'major'
      : r.confidence === 'low' ? 'minor' : 'info';
    const node = el('div', { className: 'finding ' + sev, style: 'margin-top:11px' },
      el('h4', {}, el('span', { className: 'badge ' + sev }, r.pattern),
        fmtTime(r.time),
        el('span', { className: 'muted small' },
          `  ${r.uptime_s ? 'ran ' + fmtDur(r.uptime_s) : 'still running at capture'}` + ` · ${CONF_LABEL[r.confidence]}`)));
    if (r.evidence.length) {
      node.append(el('ul', { style: 'margin:8px 0 0;padding-left:19px' },
        ...r.evidence.map(e => el('li', { className: 'small' },
          el('strong', {}, e.kind === 'log' ? `${e.title} × ${e.count}` : e.title),
          e.detail ? el('span', { className: 'muted' }, ': ' + e.detail) : ''))));
      const lines = r.evidence.flatMap(e => e.lines || []);
      if (lines.length) {
        node.append(el('details', { className: 'evidence' },
          el('summary', {}, 'Log lines from before this restart'),
          el('pre', {}, lines.map(l =>
            `${(l.time || '').slice(0, 19)}  ${l.line}`).join('\n'))));
      }
    } else {
      node.append(el('p', { className: 'small muted' },
        'No evidence in the window. The logs covering this date had already been ' +
        'rotated away, so this restart cannot be explained from this file.'));
    }
    nodes.push(node);
  }
  render(nodes);
}

async function viewCompare() {
  const nodes = [];
  nodes.push(el('div', { className: 'card' },
    el('h3', {}, 'Compare two captures'),
    el('p', { className: 'small muted', style: 'margin:0' },
      'A single support file is one moment. To tell whether a change actually ' +
      'helped, compare a capture from before it with one from after: restart ' +
      'frequency, memory trend, processor load, how the Network application is ' +
      'coping, and anything new that has appeared.')));

  let list = state.bundleList;
  if (!list) {
    try { list = state.bundleList = await api('/api/bundles'); }
    catch { list = []; }
  }
  if (list.length < 2) {
    nodes.push(el('div', { className: 'card', style: 'margin-top:15px' },
      el('p', {}, `Only ${list.length} support file is loaded. Add a second one ` +
        `(drag it onto the page, or drop it in the project folder and restart) ` +
        `to compare.`)));
    render(nodes);
    return;
  }

  const ids = list.map(b => b.id);
  state.cmpA = state.cmpA && ids.includes(state.cmpA) ? state.cmpA : ids[0];
  state.cmpB = state.cmpB && ids.includes(state.cmpB) ? state.cmpB : ids[ids.length - 1];

  const mk = (which) => el('select', {
    onchange: e => { state[which] = e.target.value; state.cmp = null; viewCompare(); },
  }, ...ids.map(id => el('option', { value: id, selected: state[which] === id, textContent: id })));

  nodes.push(el('div', { className: 'card', style: 'margin-top:15px' },
    el('div', { className: 'row' },
      el('span', { className: 'small muted' }, 'Earlier'), mk('cmpA'),
      el('span', { className: 'small muted' }, 'Later'), mk('cmpB'),
      el('button', { className: 'primary', textContent: 'Compare',
        onclick: async () => {
          render(el('div', { className: 'card' }, el('span', { className: 'spin' }),
            ' Comparing (analysing either file for the first time takes longer) ...'));
          try {
            state.cmp = await api(`/api/compare?a=${encodeURIComponent(state.cmpA)}` +
              `&b=${encodeURIComponent(state.cmpB)}`);
          } catch (e) {
            state.cmp = { error: e.message };
          }
          viewCompare();
        } }))));

  const c = state.cmp;
  if (c && !c.error) {
    if (!c.same_device) {
      nodes.push(el('div', { className: 'finding major', style: 'margin-top:15px' },
        el('h4', {}, el('span', { className: 'badge major' }, 'careful'),
          'These captures are from different devices'),
        el('p', {}, 'Serial numbers do not match, so differences below may just be ' +
          'differences between two machines.')));
    }
    if (c.firmware_changed) {
      nodes.push(el('div', { className: 'card', style: 'margin-top:15px' },
        el('h3', {}, 'Firmware changed between captures'),
        el('p', { className: 'small muted', style: 'margin:0' },
          `${c.a.firmware || 'unknown'} → ${c.b.firmware || 'unknown'}. ` +
          'Anything that improved or worsened may be down to this rather than ' +
          'to a change you made.')));
    }

    nodes.push(el('div', { className: 'grid', style: 'margin-top:15px' },
      el('div', { className: 'card' }, el('h3', {}, 'Overall'),
        el('div', { className: 'stat', style: c.verdict === 'Worse overall'
          ? 'color:var(--crit)' : c.verdict === 'Better overall' ? 'color:#3fbf8f' : '' },
          c.verdict),
        el('div', { className: 'muted small' }, `${c.better} better, ${c.worse} worse`))));

    nodes.push(el('h2', { style: 'font-size:17px;margin:24px 0 12px' }, 'Measurements'));
    nodes.push(el('div', { className: 'table-wrap' }, el('table', {},
      el('thead', {}, el('tr', {}, ...['Measurement', 'Earlier', 'Later', 'Change']
        .map(h => el('th', {}, h)))),
      el('tbody', {}, ...c.metrics.map(m => {
        const fmt = v => m.unit === 'seconds' ? fmtDur(v)
          : m.unit === 'kB' ? fmtKB(v)
          : `${Math.round(v * 10) / 10}${m.unit ? ' ' + m.unit : ''}`;
        const tr = el('tr', { title: m.note || '' },
          el('td', {}, m.label, m.note ? el('div', { className: 'small muted' }, m.note) : ''),
          el('td', { className: 'num' }, fmt(m.before)),
          el('td', { className: 'num' }, fmt(m.after)),
          el('td', { className: 'num' },
            m.direction === 'same' ? 'no change'
              : `${m.change > 0 ? '+' : ''}${fmt(m.change)} ${m.direction}`));
        if (m.direction === 'worse') tr.className = 'bad';
        else if (m.direction === 'better') tr.className = 'warn';
        return tr;
      })))));

    const listBlock = (title, items, empty) =>
      el('div', { className: 'card', style: 'margin-top:15px' },
        el('h3', {}, title),
        items.length
          ? el('ul', { style: 'margin:0;padding-left:19px' },
              ...items.map(t => el('li', { className: 'small' }, t)))
          : el('p', { className: 'small muted', style: 'margin:0' }, empty));

    nodes.push(listBlock('Problems that appeared', c.new_findings, 'None.'));
    nodes.push(listBlock('Problems that went away', c.fixed_findings, 'None.'));
    nodes.push(listBlock('Processes that appeared', c.processes_appeared, 'None.'));
    nodes.push(listBlock('Processes that are gone', c.processes_gone, 'None.'));
  } else if (c && c.error) {
    nodes.push(el('div', { className: 'finding critical', style: 'margin-top:15px' },
      el('h4', {}, 'Comparison failed'), el('p', {}, c.error)));
  }
  render(nodes);
}

async function viewRamoops() {
  if (!state.data.has_ramoops) {
    render(el('div', { className: 'card' }, 'No ramoops capture in this bundle.'));
    return;
  }
  render(el('div', { className: 'card' }, el('span', { className: 'spin' }), ' Loading…'));
  const txt = await api(`/api/bundle/${encodeURIComponent(state.bid)}/ramoops`);
  render(
    el('div', { className: 'card' }, el('h3', {}, 'Kernel ramoops'),
      el('p', { className: 'small muted', style: 'margin:0' },
        'The kernel console preserved across the last reboot in persistent RAM. This is the ' +
        'only place a panic or the final shutdown sequence survives, the regular logs are ' +
        'already gone by then.')),
    el('pre', { className: 'tall' }, txt));
}

async function viewBrowse() {
  render(el('div', { className: 'card' }, el('span', { className: 'spin' }), ' Listing files…'));
  const files = await api(`/api/bundle/${encodeURIComponent(state.bid)}/files`);

  const search = el('input', { type: 'text', placeholder: 'Filter file paths…' });
  const grep = el('input', { type: 'text', placeholder: 'Search within file (optional)' });
  const out = el('pre', { className: 'tall' }, 'Select a file on the left.');
  const listBox = el('div', { className: 'filelist' });
  let current = null;

  const openFile = async (path) => {
    current = path;
    out.textContent = 'Loading…';
    const q = grep.value.trim();
    try {
      out.textContent = await api(`/api/bundle/${encodeURIComponent(state.bid)}/file`
        + `?path=${encodeURIComponent(path)}&tail=3000${q ? '&q=' + encodeURIComponent(q) : ''}`);
    } catch (e) { out.textContent = 'Could not read this file.\n' + e.message; }
  };

  const paint = () => {
    const f = search.value.toLowerCase();
    const shown = files.filter(x => !f || x.path.toLowerCase().includes(f)).slice(0, 600);
    listBox.replaceChildren(...shown.map(x =>
      el('button', {
        textContent: x.path, title: `${x.path}, ${(x.size / 1024).toFixed(0)} KB`,
        onclick: () => openFile(x.path),
      })));
    if (!shown.length) listBox.replaceChildren(el('div', { className: 'muted small' }, 'No matches.'));
  };
  search.oninput = paint;
  grep.onchange = () => current && openFile(current);
  paint();

  render(el('div', { className: 'split' },
    el('div', { className: 'card' },
      el('div', { className: 'row' }, search),
      el('div', { className: 'row' }, grep),
      el('div', { className: 'muted small', style: 'margin-bottom:7px' },
        `${files.length} files, showing last 3000 lines of any file. .gz and .zst are decompressed.`),
      listBox),
    el('div', { className: 'card' }, out)));
}

// ---------- upload ----------
async function upload(file) {
  render(el('div', { className: 'card' }, el('span', { className: 'spin' }),
    ` Uploading and extracting ${file.name}…`));
  const fd = new FormData();
  fd.append('file', file);
  try {
    const r = await api('/api/upload', { method: 'POST', body: fd });
    await loadBundles(r.id);
    await loadAnalysis(r.id);
  } catch (e) {
    render(el('div', { className: 'finding critical' },
      el('h4', {}, 'Upload failed'), el('p', {}, e.message)));
  }
}

function emptyState() {
  const drop = el('div', { className: 'drop' },
    el('div', { style: 'font-size:16px;margin-bottom:6px' }, 'Drop a UniFi support file here'),
    el('div', { className: 'small' }, 'a support-XXXX-*.tgz downloaded from your console, or click "Add file"'));
  render(drop);
  return drop;
}

// ---------- wiring ----------
$('#addBtn').onclick = () => $('#fileInput').click();
$('#fileInput').onchange = e => e.target.files[0] && upload(e.target.files[0]);
$('#bundleSel').onchange = e => loadAnalysis(e.target.value);
$('#reanalyze').onclick = () => state.bid && loadAnalysis(state.bid, true);

document.addEventListener('dragover', e => {
  e.preventDefault();
  document.querySelector('.drop')?.classList.add('over');
});
document.addEventListener('dragleave', () => document.querySelector('.drop')?.classList.remove('over'));
document.addEventListener('drop', e => {
  e.preventDefault();
  document.querySelector('.drop')?.classList.remove('over');
  const f = e.dataTransfer.files[0];
  if (f) upload(f);
});

(async () => {
  const bid = await loadBundles();
  if (bid) loadAnalysis(bid); else { $('#tabs').replaceChildren(); emptyState(); }
})();
