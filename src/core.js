'use strict';
// Detection Rule Atlas core: YARA and Sigma rule reading, syntax, metadata, quality and ATT&CK coverage reports.

const esc = (s) => String(s).replace(/[\r\n]+/g, ' ').replace(/([\\`*_{}\[\]()#+!|<>~&$])/g, '\\$1')
  .split('://').join('\\:\\/\\/').replace(/(^|[^A-Za-z0-9])www\./gi, (m, pre) => pre + m.slice(pre.length, pre.length + 3) + '\\.');
const cell = (s) => { s = String(s == null ? '' : s); return s === '' ? '-' : esc(s); };
const pl = (n, w) => n + ' ' + w + (n === 1 ? '' : 's');
const byText = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// ---------------------------------------------------------------- kind of file
function ruleKind(text) {
  const s = String(text == null ? '' : text).replace(/^\uFEFF/, '');
  if (/^(title|detection)\s*:/m.test(s) && /^detection\s*:/m.test(s)) return 'sigma';
  if (/(^|\n)\s*((private|global)\s+)*rule\s+[A-Za-z_]\w*/.test(blankYara(s))) return 'yara';
  return '';
}

// ---------------------------------------------------------------- YARA
// Comments (// and /* */) become spaces, line breaks kept; text strings, hex strings and regexes are kept as written.
// Built from slices (a 50 MB file built one character at a time would exhaust memory); same output as reading character by character.
function blankYara(s) {
  const out = []; let i = 0; const n = s.length; const SPECIAL = /[\/"]/g;
  while (i < n) {
    SPECIAL.lastIndex = i; const m = SPECIAL.exec(s); const j = m ? m.index : n;
    if (j > i) { out.push(s.slice(i, j)); i = j; if (i >= n) break; }
    const c = s[i], d = s[i + 1];
    if (c === '/' && d === '/') { const e = s.indexOf('\n', i); const end = e < 0 ? n : e; out.push(' '.repeat(end - i)); i = end; continue; }
    if (c === '/' && d === '*') { out.push('  '); i += 2; const e = s.indexOf('*/', i); const end = e < 0 ? n : e; if (end > i) out.push(s.slice(i, end).replace(/[^\n]/g, ' ')); i = end; if (i < n) { out.push('  '); i += 2; } continue; }
    if (c === '"') {                                    // a quoted string is kept as written, up to its closing quote or the end of the line
      const start = i; i++;
      while (i < n && s[i] !== '"' && s[i] !== '\n') { if (s[i] === '\\' && i + 1 < n) { i += 2; continue; } i++; }
      if (i < n && s[i] === '"') i++;
      out.push(s.slice(start, i)); continue;
    }
    out.push(c); i++;
  }
  return out.join('');
}
// Line numbers: the line starts of a text are indexed once, then a position is found by binary search.
function lineStarts(s) { const st = [0]; for (let p = s.indexOf('\n'); p >= 0; p = s.indexOf('\n', p + 1)) st.push(p + 1); return st; }
function lineFrom(st, idx) { let lo = 0, hi = st.length - 1; while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (st[mid] <= idx) lo = mid; else hi = mid - 1; } return lo + 1; }

function parseYara(text) {
  const raw = String(text == null ? '' : text).replace(/^\uFEFF/, '');
  const s = blankYara(raw);
  const imports = []; let m; const reI = /(^|\n)\s*import\s+"([^"]*)"/g;
  while ((m = reI.exec(s))) imports.push(m[2]);
  const starts = lineStarts(s); const lineAt = (idx) => lineFrom(starts, idx);
  const rules = []; const problems = [];
  const reR = /(^|[\s;}])((?:(?:private|global)\s+)*)rule\s+([A-Za-z_]\w*)\s*(?::\s*([A-Za-z_0-9\s]*?))?\s*\{/g;
  while ((m = reR.exec(s))) {
    const start = m.index + m[1].length; const open = reR.lastIndex - 1;
    let depth = 0, j = open, inStr = false;
    for (; j < s.length; j++) {
      const c = s[j];
      if (inStr) { if (c === '\\') { j++; continue; } if (c === '"' || c === '\n') inStr = false; continue; }
      if (c === '"') { inStr = true; continue; }
      if (c === '{') depth++; else if (c === '}') { depth--; if (!depth) break; }
    }
    const closed = j < s.length;
    const body = s.slice(open + 1, closed ? j : s.length);
    const r = { name: m[3], line: lineAt(start), modifiers: m[2].trim() ? m[2].trim().split(/\s+/) : [], tags: m[4] ? m[4].trim().split(/\s+/).filter(Boolean) : [],
      meta: [], strings: [], condition: '', hasCondition: false, closed, sections: [] };
    // Sections are found by position (a rule may be written on one line); quoted text is masked so 'condition:' inside a string is not a section.
    const masked = body.replace(/"(?:\\.|[^"\\\n])*"/g, (q) => '"' + ' '.repeat(q.length - 2) + '"');
    const secRe = /(^|[\s{;])(meta|strings|condition)\s*:/g; const secs = []; let sm;
    while ((sm = secRe.exec(masked))) secs.push({ name: sm[2], at: sm.index + sm[1].length, from: secRe.lastIndex });
    const lineAtBody = (idx) => lineAt(open + 1 + idx);   // body is a slice of s starting at open + 1
    secs.forEach((sec, k) => {
      const end = k + 1 < secs.length ? secs[k + 1].at : body.length;
      const part = body.slice(sec.from, end);
      r.sections.push(sec.name);
      if (sec.name === 'meta') {
        const re = /([A-Za-z_]\w*)\s*=\s*("(?:\\.|[^"\\\n])*"|-?\d+|true|false)/g; let mm;
        while ((mm = re.exec(part))) r.meta.push({ key: mm[1], value: mm[2].replace(/^"(.*)"$/, '$1'), line: lineAtBody(sec.from + mm.index) });
      } else if (sec.name === 'strings') {
        const re = /(\$[A-Za-z0-9_]*)\s*=\s*("(?:\\.|[^"\\\n])*"|\{[^}]*\}|\/(?:\\.|[^\/\\\n])*\/[is]*)((?:[ \t]+(?:nocase|wide|ascii|fullword|private|xor(?:\([^)]*\))?|base64wide(?:\("(?:\\.|[^"\\])*"\))?|base64(?:\("(?:\\.|[^"\\])*"\))?))*)/g; let mm;
        while ((mm = re.exec(part))) {
          const v = mm[2]; let kind = 'text', value = v;
          if (v.startsWith('{')) kind = 'hex';
          else if (v.startsWith('/')) { kind = 'regex'; value = v.replace(/[is]*$/, ''); }
          else value = v.slice(1, -1);
          r.strings.push({ id: mm[1], kind, value, modifiers: mm[3].trim().split(/\s+/).filter(Boolean), line: lineAtBody(sec.from + mm.index) });
        }
      } else if (sec.name === 'condition') { r.condition = part.trim().replace(/\s+/g, ' '); r.hasCondition = true; }
    });
    rules.push(r); r.span = [start, closed ? j : s.length];
    if (closed) reR.lastIndex = j + 1;
  }
  // 'rule <name>' outside every rule that was read: its header could not be read (for example a tag with '.' or '-').
  // (rules and candidates are both in file order, so one forward pointer over the rule spans is enough)
  const reH = /(^|[\s;}])((?:(?:private|global)\s+)*)rule\s+([A-Za-z_]\w*)/g; let h, k = 0;
  while ((h = reH.exec(s))) {
    const at = h.index + h[1].length;
    while (k < rules.length && rules[k].span[1] < at) k++;
    if (!(k < rules.length && at >= rules[k].span[0] && at <= rules[k].span[1])) problems.push({ line: lineAt(at), name: h[3] });
  }
  rules.forEach((x) => { delete x.span; });
  return { imports, rules, problems };
}

// Which defined strings a condition uses: $a, $a*, #a, @a, !a, 'them', '($a*, $b)'.
function referencedStrings(condition, ids) {
  const c = String(condition || ''); const used = new Set();
  if (/\bthem\b/.test(c)) ids.forEach((i) => used.add(i));
  const re = /[$#@!]([A-Za-z0-9_]*)(\*)?/g; let m;
  while ((m = re.exec(c))) {
    const name = '$' + m[1];
    if (m[2]) ids.filter((i) => i.startsWith(name)).forEach((i) => used.add(i));
    else if (m[1] === '' ) { /* anonymous $ inside 'for ... of' loops refers to the loop's set */ }
    else used.add(name);
  }
  return used;
}
function undefinedRefs(condition, ids) {
  ids = Array.isArray(ids) ? ids.map(String) : [];
  const out = []; const re = /[$#@!]([A-Za-z0-9_]*)(\*)?/g; let m; const c = String(condition || '');
  while ((m = re.exec(c))) {
    if (!m[1]) continue;
    const name = '$' + m[1];
    if (m[2]) { if (!ids.some((i) => i.startsWith(name))) out.push(name + '*'); }
    else if (!ids.includes(name)) out.push(name);
  }
  return [...new Set(out)];
}
const textBytes = (v) => v.replace(/\\x[0-9A-Fa-f]{2}|\\./g, 'x').length;
const hexBytes = (v) => (v.replace(/[{}\s]/g, '').replace(/\[[^\]]*\]|\([^)]*\)/g, '').match(/[0-9A-Fa-f?]{2}/g) || []).length;

// ---------------------------------------------------------------- Sigma (one or more documents separated by '---')
function parseSigma(text) {
  const raw = String(text == null ? '' : text).replace(/^\uFEFF/, '');
  const lines = raw.split('\n').map((l) => l.replace(/\r$/, ''));
  const docs = []; let cur = null;
  const start = (n) => { cur = { line: n, keys: new Map(), detection: [], condition: '', tags: [], falsepositives: false }; docs.push(cur); };
  let section = '', inDetection = false;
  lines.forEach((l, i) => {
    const n = i + 1;
    if (/^---\s*$/.test(l)) { cur = null; section = ''; inDetection = false; return; }
    if (/^\s*#/.test(l) || !l.trim()) return;
    if (!cur) start(n);
    const top = /^([A-Za-z_][\w-]*)\s*:\s*(.*)$/.exec(l);
    if (top) {
      section = top[1]; inDetection = section === 'detection';
      cur.keys.set(top[1], { value: top[2].trim().replace(/^['"](.*)['"]$/, '$1'), line: n });
      if (top[1] === 'tags' && top[2].trim().startsWith('[')) cur.tags.push(...top[2].replace(/[[\]]/g, '').split(',').map((x) => x.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean));
      if (top[1] === 'falsepositives' && top[2].trim() && top[2].trim() !== '[]') cur.falsepositives = true;
      return;
    }
    const item = /^\s+-\s*(.*)$/.exec(l);
    if (section === 'tags' && item) cur.tags.push(item[1].trim().replace(/^['"]|['"]$/g, ''));
    if (section === 'falsepositives' && item) cur.falsepositives = true;
    if (inDetection) {
      const sub = /^(\s+)([^\s:][^:]*?)\s*:\s*(.*)$/.exec(l);
      if (sub && sub[1].length <= 4 && !/^\s+-/.test(l)) {
        if (sub[2] === 'condition') cur.condition = sub[3].trim().replace(/^['"](.*)['"]$/, '$1');
        else if (sub[2] !== 'timeframe') cur.detection.push({ name: sub[2], line: n, fields: [] });
      } else if (cur.detection.length) {
        const f = /^\s+-?\s*([^\s:][^:]*?)\s*:\s*(.*)$/.exec(l);
        const last = cur.detection[cur.detection.length - 1];
        if (f) last.fields.push({ field: f[1], value: f[2].trim(), line: n });
        else if (item) last.fields.push({ field: '', value: item[1].trim(), line: n });
      }
    }
  });
  return docs;
}
const sv = (d, k) => (d.keys.has(k) ? d.keys.get(k).value : '');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const STATUS = ['stable', 'test', 'experimental', 'deprecated', 'unsupported'];
const LEVELS = ['informational', 'low', 'medium', 'high', 'critical'];
function conditionNames(cond, names) {
  names = Array.isArray(names) ? names.map(String) : [];
  const out = []; const toks = String(cond).replace(/[()|]/g, ' ').split(/\s+/).filter(Boolean);
  const KW = new Set(['and', 'or', 'not', 'of', 'them', 'all', '1', 'any', 'near', 'by', 'count', 'min', 'max', 'avg', 'sum']);
  for (const t of toks) {
    if (KW.has(t) || /^\d+$/.test(t) || /^[<>=]+$/.test(t)) continue;
    if (t.endsWith('*')) { if (!names.some((n) => n.startsWith(t.slice(0, -1)))) out.push(t); }
    else if (!names.includes(t)) out.push(t);
  }
  return [...new Set(out)];
}

// ---------------------------------------------------------------- reports
const NONE = (h) => '# ' + h + '\n\nThis file contains no YARA or Sigma rules.';

function reportSummary(text) {
  const k = ruleKind(text); const H = 'Rule Summary';
  if (k === 'yara') {
    const y = parseYara(text);
    let md = '# ' + H + '\n\nYARA file with ' + pl(y.rules.length, 'rule') + '.\n\nImports: ' + (y.imports.length ? y.imports.map(esc).join(', ') : 'none') + '.';
    md += '\n\n| Line | Rule | Modifiers | Tags | Strings | Meta fields |\n| ---: | --- | --- | --- | ---: | ---: |\n' +
      y.rules.map((r) => '| ' + r.line + ' | ' + cell(r.name) + ' | ' + cell(r.modifiers.join(' ')) + ' | ' + cell(r.tags.join(' ')) + ' | ' + r.strings.length + ' | ' + r.meta.length + ' |').join('\n');
    return md;
  }
  if (k === 'sigma') {
    const docs = parseSigma(text);
    return '# ' + H + '\n\nSigma file with ' + pl(docs.length, 'rule') + '.\n\n| Line | Title | Status | Level | Log source |\n| ---: | --- | --- | --- | --- |\n' +
      docs.map((d) => { const ls = ['category', 'product', 'service'].map((x) => logsourceValue(text, d, x)).filter(Boolean).join(' / ');
        return '| ' + d.line + ' | ' + cell(sv(d, 'title')) + ' | ' + cell(sv(d, 'status')) + ' | ' + cell(sv(d, 'level')) + ' | ' + cell(ls) + ' |'; }).join('\n');
  }
  return NONE(H);
}
// logsource sub-keys of one Sigma document (category, product, service)
function logsourceValue(text, d, key) {
  if (!d.keys.has('logsource')) return '';
  const lines = String(text).replace(/^\uFEFF/, '').split('\n'); const from = d.keys.get('logsource').line;
  for (let i = from; i < lines.length; i++) {
    const l = lines[i].replace(/\r$/, '');
    if (/^\S/.test(l) || /^---/.test(l)) break;
    const m = /^\s+([\w-]+)\s*:\s*(.*)$/.exec(l); if (m && m[1] === key) return m[2].trim().replace(/^['"](.*)['"]$/, '$1');
  }
  return '';
}

function yaraProblems(y, raw) {
  const p = []; const seen = new Map();
  y.problems.forEach((x) => p.push([x.line, 'the header of rule ' + x.name + ' cannot be read: expected rule <name> [: tags] { with tags made of letters, digits and _']));
  y.rules.forEach((r) => {
    if (seen.has(r.name)) p.push([r.line, 'rule ' + r.name + ' is defined twice (first on line ' + seen.get(r.name) + ')']); else seen.set(r.name, r.line);
    if (!r.closed) p.push([r.line, 'rule ' + r.name + ' is not closed with }']);
    if (!r.hasCondition) p.push([r.line, 'rule ' + r.name + ' has no condition section']);
    const ids = new Map();
    r.strings.forEach((s) => { if (s.id !== '$' && ids.has(s.id)) p.push([s.line, 'string ' + s.id + ' is defined twice in rule ' + r.name]); else ids.set(s.id, s.line);
      if (s.kind === 'text' && s.value === '') p.push([s.line, 'string ' + s.id + ' is empty']);
      if (s.kind === 'hex' && !/^\{[\s0-9A-Fa-f?~\[\]\-()|]*\}$/.test(s.value)) p.push([s.line, 'hex string ' + s.id + ' contains characters that are not hex digits, ?, jumps or alternatives']); });
    if (r.hasCondition) undefinedRefs(r.condition, [...ids.keys()]).forEach((u) => p.push([r.line, 'condition of rule ' + r.name + ' uses ' + u + ', which is not defined']));
  });
  return p;
}
function sigmaProblems(docs) {
  const p = []; const ids = new Map();
  docs.forEach((d, k) => {
    const name = sv(d, 'title') || 'rule ' + (k + 1);
    ['title', 'logsource', 'detection'].forEach((key) => { if (!d.keys.has(key)) p.push([d.line, name + ': required field ' + key + ' is missing']); });
    if (d.keys.has('detection') && !d.condition) p.push([d.keys.get('detection').line, name + ': detection has no condition']);
    if (d.condition) conditionNames(d.condition, d.detection.map((x) => x.name)).forEach((u) => p.push([d.keys.get('detection').line, name + ': condition uses ' + u + ', which is not a search identifier of this rule']));
    if (sv(d, 'status') && !STATUS.includes(sv(d, 'status'))) p.push([d.keys.get('status').line, name + ': status ' + sv(d, 'status') + ' is not one of ' + STATUS.join(', ')]);
    if (sv(d, 'level') && !LEVELS.includes(sv(d, 'level'))) p.push([d.keys.get('level').line, name + ': level ' + sv(d, 'level') + ' is not one of ' + LEVELS.join(', ')]);
    const id = sv(d, 'id'); if (id) { if (ids.has(id)) p.push([d.keys.get('id').line, name + ': id ' + id + ' is also used on line ' + ids.get(id)]); else ids.set(id, d.keys.get('id').line); }
  });
  return p;
}
function table(p, head, cols) { return head + '\n\n' + pl(p.length, cols) + ' found.\n\n| Line | Problem |\n| ---: | --- |\n' + p.slice().sort((a, b) => a[0] - b[0]).map((x) => '| ' + x[0] + ' | ' + cell(x[1]) + ' |').join('\n'); }

function reportSyntax(text) {
  const k = ruleKind(text); const H = '# Syntax Check';
  if (!k) return NONE('Syntax Check');
  const p = k === 'yara' ? yaraProblems(parseYara(text), text) : sigmaProblems(parseSigma(text));
  return p.length ? table(p, H, 'problem') : H + '\n\nNo problems found.';
}

function reportMetadata(text) {
  const k = ruleKind(text); const H = '# Metadata Check';
  if (!k) return NONE('Metadata Check');
  const rows = [];
  if (k === 'yara') {
    parseYara(text).rules.forEach((r) => {
      const keys = new Set(r.meta.map((m) => m.key.toLowerCase()));
      const missing = ['author', 'description', 'date', 'reference'].filter((x) => !keys.has(x) && !(x === 'reference' && keys.has('references')));
      if (missing.length) rows.push([r.line, r.name, 'missing meta: ' + missing.join(', ')]);
      const dt = r.meta.find((m) => m.key.toLowerCase() === 'date');
      if (dt && !/^\d{4}[-/]\d{2}[-/]\d{2}$/.test(dt.value)) rows.push([dt.line, r.name, 'date ' + dt.value + ' is not YYYY-MM-DD']);
    });
  } else {
    parseSigma(text).forEach((d, k2) => {
      const name = sv(d, 'title') || 'rule ' + (k2 + 1);
      const missing = ['id', 'status', 'description', 'author', 'date', 'level', 'tags', 'falsepositives'].filter((x) => !d.keys.has(x));
      if (missing.length) rows.push([d.line, name, 'missing: ' + missing.join(', ')]);
      if (sv(d, 'id') && !UUID.test(sv(d, 'id'))) rows.push([d.keys.get('id').line, name, 'id ' + sv(d, 'id') + ' is not a UUID']);
      for (const key of ['date', 'modified']) if (sv(d, key) && !/^\d{4}([-/])\d{2}\1\d{2}$/.test(sv(d, key))) rows.push([d.keys.get(key).line, name, key + ' ' + sv(d, key) + ' is not YYYY-MM-DD']);
    });
  }
  if (!rows.length) return H + '\n\nEvery rule has complete metadata.';
  return H + '\n\n' + pl(rows.length, 'finding') + '.\n\n| Line | Rule | Finding |\n| ---: | --- | --- |\n' + rows.sort((a, b) => a[0] - b[0]).map((x) => '| ' + x[0] + ' | ' + cell(x[1]) + ' | ' + cell(x[2]) + ' |').join('\n');
}

function reportQuality(text) {
  const k = ruleKind(text); const H = '# Quality Review';
  if (!k) return NONE('Quality Review');
  const f = [];
  if (k === 'yara') {
    parseYara(text).rules.forEach((r) => {
      const ids = r.strings.map((s) => s.id);
      const used = r.hasCondition ? referencedStrings(r.condition, ids) : new Set(ids);
      r.strings.forEach((s) => {
        if (s.id !== '$' && !used.has(s.id)) f.push([s.line, r.name, 'unused_string', 'string ' + s.id + ' is never used in the condition']);
        if (s.kind === 'text' && s.value !== '' && textBytes(s.value) < 4) f.push([s.line, r.name, 'short_atom', 'text string ' + s.id + ' has fewer than 4 bytes, which slows scanning and matches often']);
        if (s.kind === 'hex' && hexBytes(s.value) < 4) f.push([s.line, r.name, 'short_atom', 'hex string ' + s.id + ' has fewer than 4 fixed bytes, which slows scanning and matches often']);
        if (s.kind === 'regex' && /^\/(\.\*|\.\+)/.test(s.value)) f.push([s.line, r.name, 'slow_regex', 'regex ' + s.id + ' starts with .* or .+, which makes scanning slow']);
      });
      if (r.hasCondition && r.strings.length && !/[$#@!]|\bthem\b/.test(r.condition)) f.push([r.line, r.name, 'strings_ignored', 'the condition uses none of the strings']);
    });
  } else {
    parseSigma(text).forEach((d, k2) => {
      const name = sv(d, 'title') || 'rule ' + (k2 + 1);
      d.detection.forEach((sel) => sel.fields.forEach((fl) => {
        const v = fl.value.replace(/^['"](.*)['"]$/, '$1');
        if (/^\*+$/.test(v)) f.push([fl.line, name, 'wildcard_only', 'value of ' + (fl.field || sel.name) + ' is only a wildcard and matches everything']);
        if (/\|(contains|startswith|endswith)\b/.test(fl.field) && v && v.replace(/[*?]/g, '').length < 3) f.push([fl.line, name, 'short_value', fl.field + ' with a value shorter than 3 characters matches far too much']);
      }));
      if (['high', 'critical'].includes(sv(d, 'level')) && !d.falsepositives) f.push([d.line, name, 'no_falsepositives', 'level ' + sv(d, 'level') + ' without falsepositives: say when the rule is known to fire on benign activity']);
      if (sv(d, 'status') === 'deprecated') f.push([d.keys.get('status').line, name, 'deprecated', 'the rule is marked deprecated']);
    });
  }
  if (!f.length) return H + '\n\nNo findings.';
  f.sort((a, b) => a[0] - b[0] || byText(a[2], b[2]));
  return H + '\n\n' + pl(f.length, 'finding') + '.\n\n| Line | Rule | Check | Finding |\n| ---: | --- | --- | --- |\n' + f.map((x) => '| ' + x[0] + ' | ' + cell(x[1]) + ' | ' + x[2] + ' | ' + cell(x[3]) + ' |').join('\n');
}

const TACTICS = ['reconnaissance', 'resource_development', 'initial_access', 'execution', 'persistence', 'privilege_escalation', 'defense_evasion', 'credential_access',
  'discovery', 'lateral_movement', 'collection', 'command_and_control', 'exfiltration', 'impact'];
function reportAttack(text) {
  const k = ruleKind(text); const H = '# ATT&CK Coverage';
  if (!k) return NONE('ATT&CK Coverage');
  const rules = [];
  if (k === 'yara') parseYara(text).rules.forEach((r) => {
    const vals = r.tags.concat(r.meta.filter((m) => /mitre|att(ack|&ck)|technique|tactic/i.test(m.key)).map((m) => m.value));
    rules.push({ name: r.name, items: vals.join(' ').split(/[\s,;]+/).filter(Boolean) });
  });
  else parseSigma(text).forEach((d, k2) => rules.push({ name: sv(d, 'title') || 'rule ' + (k2 + 1), items: d.tags.filter((t) => /^attack\./i.test(t)).map((t) => t.slice(7)) }));
  const tech = new Map(), tac = new Map(), none = [];
  rules.forEach((r) => {
    let any = false;
    r.items.forEach((x) => {
      const t = /^t(\d{4})(?:[._](\d{3}))?$/i.exec(x);           // T1505.003, or T1505_003 (YARA tags cannot hold '.')
      if (t) { const key = 'T' + t[1] + (t[2] ? '.' + t[2] : ''); if (!tech.has(key)) tech.set(key, new Set()); tech.get(key).add(r.name); any = true; return; }
      const ta = x.toLowerCase().replace(/-/g, '_');
      if (TACTICS.includes(ta)) { if (!tac.has(ta)) tac.set(ta, new Set()); tac.get(ta).add(r.name); any = true; }
    });
    if (!any) none.push(r.name);
  });
  let md = H + '\n\n' + pl(rules.length, 'rule') + ', ' + pl(tech.size, 'technique') + ', ' + pl(tac.size, 'tactic') + '.';
  md += '\n\n## Techniques\n\n' + (tech.size ? '| Technique | Rules |\n| --- | ---: |\n' + [...tech.entries()].sort((a, b) => byText(a[0], b[0])).map(([t, s]) => '| ' + t + ' | ' + s.size + ' |').join('\n') : 'No technique tags.');
  md += '\n\n## Tactics\n\n' + (tac.size ? '| Tactic | Rules |\n| --- | ---: |\n' + TACTICS.filter((t) => tac.has(t)).map((t) => '| ' + t + ' | ' + tac.get(t).size + ' |').join('\n') : 'No tactic tags.');
  md += '\n\n## Rules without ATT&CK tags\n\n' + (none.length ? none.map((n) => '- ' + esc(n)).join('\n') : 'Every rule has an ATT&CK tag.');
  return md;
}

// The strings a YARA condition uses (sorted), from the identifiers defined in the rule.
function usedStrings(condition, ids) { return [...referencedStrings(condition, Array.isArray(ids) ? ids.map(String) : [])].sort(); }
module.exports = { ruleKind, usedStrings, undefinedRefs, conditionNames, reportSummary, reportSyntax, reportMetadata, reportQuality, reportAttack };

// Caps every Markdown table of a report at 500 rows and says how many there were.
function capTables(md) {
  if (typeof md !== 'string') return md;
  const lines = md.split('\n'), out = [];
  for (let i = 0; i < lines.length; i++) {
    out.push(lines[i]);
    if (lines[i].startsWith('|') && /^\|[ :-]+\|/.test(lines[i + 1] || '')) {
      out.push(lines[++i]);
      let n = 0;
      while (i + 1 < lines.length && lines[i + 1].startsWith('|')) { i++; n++; if (n <= 500) out.push(lines[i]); }
      if (n > 500) { out.push(''); out.push('Showing the first 500 of ' + n + ' rows.'); }
    }
  }
  return out.join('\n');
}
for (const k of Object.keys(module.exports)) {
  if (k.startsWith('report')) { const f = module.exports[k]; module.exports[k] = function (text) { return capTables(f(text)); }; }
}
