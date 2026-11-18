'use strict';
// Contract tests: written from the specification examples. Do not edit; fix src/core.js instead.
const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('../src/core');

const plain = (v) => JSON.parse(JSON.stringify(v === undefined ? null : v));

test('core exports every specified function', () => {
  for (const n of ["ruleKind", "usedStrings", "undefinedRefs", "conditionNames", "reportSummary", "reportSyntax", "reportMetadata", "reportQuality", "reportAttack"]) assert.equal(typeof core[n], 'function', n);
});

test("ruleKind example 1", () => {
  assert.deepStrictEqual(plain(core.ruleKind("import \"pe\"\nimport \"math\"\n\n/* invented test rules */\nrule Suspicious_Loader : loader windows\n{\n    meta:\n        author = \"Example Team\"\n        description = \"Loader with injected shellcode\"\n        date = \"2026-02-11\"\n        mitre_attack = \"T1055 T1027\"\n    strings:\n        $mz = { 4D 5A }\n        $s1 = \"VirtualAllocEx\" ascii wide\n        $s2 = \"ab\"\n        $re = /.*cmd\\.exe/ nocase\n        $unused = \"never referenced\"\n    condition:\n        uint16(0) == 0x5A4D and $mz and ($s1 or $s2) and #re > 0 and pe.number_of_sections > 3\n}\n\nprivate rule Helper { strings: $a = \"helper\" condition: $a }\n\nrule Broken {\n    meta:\n        date = \"11/02/2026\"\n    strings:\n        $x = \"x1x2\"\n        $x = \"dup\"\n    condition:\n        $x and $y and any of ($z*)\n}\n")), "yara");
});

test("ruleKind example 2", () => {
  assert.deepStrictEqual(plain(core.ruleKind("title: Suspicious PowerShell Encoded Command\nid: 6f1c2b8e-3d4a-4b5c-9e7f-1a2b3c4d5e6f\nstatus: experimental\ndescription: Detects PowerShell started with an encoded command\nauthor: Example Team\ndate: 2026/02/11\ntags:\n    - attack.execution\n    - attack.t1059.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith: '\\powershell.exe'\n    selection_cli:\n        CommandLine|contains: ' -e'\n    condition: selection_img and selection_cli\nfalsepositives:\n    - Administrative scripts\nlevel: high\n---\ntitle: Anything at all\nstatus: wip\nlogsource:\n    product: linux\ndetection:\n    sel:\n        CommandLine: '*'\n    condition: sel and filter\nlevel: critical\n")), "sigma");
});

test("ruleKind example 3", () => {
  assert.deepStrictEqual(plain(core.ruleKind("hello world")), "");
});

test("ruleKind example 4", () => {
  assert.deepStrictEqual(plain(core.ruleKind("")), "");
});

test("usedStrings example 1", () => {
  assert.deepStrictEqual(plain(core.usedStrings("$a and #b > 2 and any of ($c*)", ["$a", "$b", "$c1", "$c2", "$d"])), ["$a", "$b", "$c1", "$c2"]);
});

test("usedStrings example 2", () => {
  assert.deepStrictEqual(plain(core.usedStrings("all of them", ["$x", "$y"])), ["$x", "$y"]);
});

test("usedStrings example 3", () => {
  assert.deepStrictEqual(plain(core.usedStrings("uint16(0) == 0x5A4D", ["$a"])), []);
});

test("undefinedRefs example 1", () => {
  assert.deepStrictEqual(plain(core.undefinedRefs("$a and $x and any of ($z*)", ["$a"])), ["$x", "$z*"]);
});

test("undefinedRefs example 2", () => {
  assert.deepStrictEqual(plain(core.undefinedRefs("$a or #a > 1", ["$a"])), []);
});

test("undefinedRefs example 3", () => {
  assert.deepStrictEqual(plain(core.undefinedRefs("$q and $q", [])), ["$q"]);
});

test("conditionNames example 1", () => {
  assert.deepStrictEqual(plain(core.conditionNames("sel and not 1 of filter_*", ["sel", "filter_a"])), []);
});

test("conditionNames example 2", () => {
  assert.deepStrictEqual(plain(core.conditionNames("selection and filter", ["selection"])), ["filter"]);
});

test("conditionNames example 3", () => {
  assert.deepStrictEqual(plain(core.conditionNames("all of them", [])), []);
});

test("reportSummary example 1", () => {
  const md = core.reportSummary("import \"pe\"\nimport \"math\"\n\n/* invented test rules */\nrule Suspicious_Loader : loader windows\n{\n    meta:\n        author = \"Example Team\"\n        description = \"Loader with injected shellcode\"\n        date = \"2026-02-11\"\n        mitre_attack = \"T1055 T1027\"\n    strings:\n        $mz = { 4D 5A }\n        $s1 = \"VirtualAllocEx\" ascii wide\n        $s2 = \"ab\"\n        $re = /.*cmd\\.exe/ nocase\n        $unused = \"never referenced\"\n    condition:\n        uint16(0) == 0x5A4D and $mz and ($s1 or $s2) and #re > 0 and pe.number_of_sections > 3\n}\n\nprivate rule Helper { strings: $a = \"helper\" condition: $a }\n\nrule Broken {\n    meta:\n        date = \"11/02/2026\"\n    strings:\n        $x = \"x1x2\"\n        $x = \"dup\"\n    condition:\n        $x and $y and any of ($z*)\n}\n");
  assert.equal(typeof md, 'string');
  for (const s of ["YARA file with 3 rules.", "Imports: pe, math.", "| 5 | Suspicious\\_Loader | - | loader windows | 5 | 4 |", "| 22 | Helper | private | - | 1 | 0 |", "| 24 | Broken | - | - | 2 | 1 |"]) assert.ok(md.includes(s), 'missing: ' + s);
});

test("reportSummary example 2", () => {
  const md = core.reportSummary("title: Suspicious PowerShell Encoded Command\nid: 6f1c2b8e-3d4a-4b5c-9e7f-1a2b3c4d5e6f\nstatus: experimental\ndescription: Detects PowerShell started with an encoded command\nauthor: Example Team\ndate: 2026/02/11\ntags:\n    - attack.execution\n    - attack.t1059.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith: '\\powershell.exe'\n    selection_cli:\n        CommandLine|contains: ' -e'\n    condition: selection_img and selection_cli\nfalsepositives:\n    - Administrative scripts\nlevel: high\n---\ntitle: Anything at all\nstatus: wip\nlogsource:\n    product: linux\ndetection:\n    sel:\n        CommandLine: '*'\n    condition: sel and filter\nlevel: critical\n");
  assert.equal(typeof md, 'string');
  for (const s of ["Sigma file with 2 rules.", "| 1 | Suspicious PowerShell Encoded Command | experimental | high | process\\_creation / windows |", "| 23 | Anything at all | wip | critical | linux |"]) assert.ok(md.includes(s), 'missing: ' + s);
});

test("reportSummary example 3", () => {
  const md = core.reportSummary("hello");
  assert.equal(typeof md, 'string');
  for (const s of ["# Rule Summary", "This file contains no YARA or Sigma rules."]) assert.ok(md.includes(s), 'missing: ' + s);
});

test("reportSyntax example 1", () => {
  const md = core.reportSyntax("import \"pe\"\nimport \"math\"\n\n/* invented test rules */\nrule Suspicious_Loader : loader windows\n{\n    meta:\n        author = \"Example Team\"\n        description = \"Loader with injected shellcode\"\n        date = \"2026-02-11\"\n        mitre_attack = \"T1055 T1027\"\n    strings:\n        $mz = { 4D 5A }\n        $s1 = \"VirtualAllocEx\" ascii wide\n        $s2 = \"ab\"\n        $re = /.*cmd\\.exe/ nocase\n        $unused = \"never referenced\"\n    condition:\n        uint16(0) == 0x5A4D and $mz and ($s1 or $s2) and #re > 0 and pe.number_of_sections > 3\n}\n\nprivate rule Helper { strings: $a = \"helper\" condition: $a }\n\nrule Broken {\n    meta:\n        date = \"11/02/2026\"\n    strings:\n        $x = \"x1x2\"\n        $x = \"dup\"\n    condition:\n        $x and $y and any of ($z*)\n}\n");
  assert.equal(typeof md, 'string');
  for (const s of ["3 problems found.", "| 24 | condition of rule Broken uses \\$y, which is not defined |", "| 24 | condition of rule Broken uses \\$z\\*, which is not defined |", "| 29 | string \\$x is defined twice in rule Broken |"]) assert.ok(md.includes(s), 'missing: ' + s);
});

test("reportSyntax example 2", () => {
  const md = core.reportSyntax("title: Suspicious PowerShell Encoded Command\nid: 6f1c2b8e-3d4a-4b5c-9e7f-1a2b3c4d5e6f\nstatus: experimental\ndescription: Detects PowerShell started with an encoded command\nauthor: Example Team\ndate: 2026/02/11\ntags:\n    - attack.execution\n    - attack.t1059.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith: '\\powershell.exe'\n    selection_cli:\n        CommandLine|contains: ' -e'\n    condition: selection_img and selection_cli\nfalsepositives:\n    - Administrative scripts\nlevel: high\n---\ntitle: Anything at all\nstatus: wip\nlogsource:\n    product: linux\ndetection:\n    sel:\n        CommandLine: '*'\n    condition: sel and filter\nlevel: critical\n");
  assert.equal(typeof md, 'string');
  for (const s of ["2 problems found.", "| 24 | Anything at all: status wip is not one of stable, test, experimental, deprecated, unsupported |", "| 27 | Anything at all: condition uses filter, which is not a search identifier of this rule |"]) assert.ok(md.includes(s), 'missing: ' + s);
});

test("reportSyntax example 3", () => {
  const md = core.reportSyntax("rule A { strings: $a = \"abcd\" condition: $a }");
  assert.equal(typeof md, 'string');
  for (const s of ["# Syntax Check", "No problems found."]) assert.ok(md.includes(s), 'missing: ' + s);
});

test("reportMetadata example 1", () => {
  const md = core.reportMetadata("import \"pe\"\nimport \"math\"\n\n/* invented test rules */\nrule Suspicious_Loader : loader windows\n{\n    meta:\n        author = \"Example Team\"\n        description = \"Loader with injected shellcode\"\n        date = \"2026-02-11\"\n        mitre_attack = \"T1055 T1027\"\n    strings:\n        $mz = { 4D 5A }\n        $s1 = \"VirtualAllocEx\" ascii wide\n        $s2 = \"ab\"\n        $re = /.*cmd\\.exe/ nocase\n        $unused = \"never referenced\"\n    condition:\n        uint16(0) == 0x5A4D and $mz and ($s1 or $s2) and #re > 0 and pe.number_of_sections > 3\n}\n\nprivate rule Helper { strings: $a = \"helper\" condition: $a }\n\nrule Broken {\n    meta:\n        date = \"11/02/2026\"\n    strings:\n        $x = \"x1x2\"\n        $x = \"dup\"\n    condition:\n        $x and $y and any of ($z*)\n}\n");
  assert.equal(typeof md, 'string');
  for (const s of ["4 findings.", "| 5 | Suspicious\\_Loader | missing meta: reference |", "| 22 | Helper | missing meta: author, description, date, reference |", "| 24 | Broken | missing meta: author, description, reference |", "| 26 | Broken | date 11/02/2026 is not YYYY-MM-DD |"]) assert.ok(md.includes(s), 'missing: ' + s);
});

test("reportMetadata example 2", () => {
  const md = core.reportMetadata("title: Suspicious PowerShell Encoded Command\nid: 6f1c2b8e-3d4a-4b5c-9e7f-1a2b3c4d5e6f\nstatus: experimental\ndescription: Detects PowerShell started with an encoded command\nauthor: Example Team\ndate: 2026/02/11\ntags:\n    - attack.execution\n    - attack.t1059.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith: '\\powershell.exe'\n    selection_cli:\n        CommandLine|contains: ' -e'\n    condition: selection_img and selection_cli\nfalsepositives:\n    - Administrative scripts\nlevel: high\n---\ntitle: Anything at all\nstatus: wip\nlogsource:\n    product: linux\ndetection:\n    sel:\n        CommandLine: '*'\n    condition: sel and filter\nlevel: critical\n");
  assert.equal(typeof md, 'string');
  for (const s of ["1 finding.", "| 23 | Anything at all | missing: id, description, author, date, tags, falsepositives |"]) assert.ok(md.includes(s), 'missing: ' + s);
});

test("reportQuality example 1", () => {
  const md = core.reportQuality("import \"pe\"\nimport \"math\"\n\n/* invented test rules */\nrule Suspicious_Loader : loader windows\n{\n    meta:\n        author = \"Example Team\"\n        description = \"Loader with injected shellcode\"\n        date = \"2026-02-11\"\n        mitre_attack = \"T1055 T1027\"\n    strings:\n        $mz = { 4D 5A }\n        $s1 = \"VirtualAllocEx\" ascii wide\n        $s2 = \"ab\"\n        $re = /.*cmd\\.exe/ nocase\n        $unused = \"never referenced\"\n    condition:\n        uint16(0) == 0x5A4D and $mz and ($s1 or $s2) and #re > 0 and pe.number_of_sections > 3\n}\n\nprivate rule Helper { strings: $a = \"helper\" condition: $a }\n\nrule Broken {\n    meta:\n        date = \"11/02/2026\"\n    strings:\n        $x = \"x1x2\"\n        $x = \"dup\"\n    condition:\n        $x and $y and any of ($z*)\n}\n");
  assert.equal(typeof md, 'string');
  for (const s of ["5 findings.", "| 13 | Suspicious\\_Loader | short_atom | hex string \\$mz has fewer than 4 fixed bytes, which slows scanning and matches often |", "| 15 | Suspicious\\_Loader | short_atom | text string \\$s2 has fewer than 4 bytes, which slows scanning and matches often |", "| 16 | Suspicious\\_Loader | slow_regex | regex \\$re starts with .\\* or .\\+, which makes scanning slow |", "| 17 | Suspicious\\_Loader | unused_string | string \\$unused is never used in the condition |", "| 29 | Broken | short_atom | text string \\$x has fewer than 4 bytes, which slows scanning and matches often |"]) assert.ok(md.includes(s), 'missing: ' + s);
});

test("reportQuality example 2", () => {
  const md = core.reportQuality("title: Suspicious PowerShell Encoded Command\nid: 6f1c2b8e-3d4a-4b5c-9e7f-1a2b3c4d5e6f\nstatus: experimental\ndescription: Detects PowerShell started with an encoded command\nauthor: Example Team\ndate: 2026/02/11\ntags:\n    - attack.execution\n    - attack.t1059.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith: '\\powershell.exe'\n    selection_cli:\n        CommandLine|contains: ' -e'\n    condition: selection_img and selection_cli\nfalsepositives:\n    - Administrative scripts\nlevel: high\n---\ntitle: Anything at all\nstatus: wip\nlogsource:\n    product: linux\ndetection:\n    sel:\n        CommandLine: '*'\n    condition: sel and filter\nlevel: critical\n");
  assert.equal(typeof md, 'string');
  for (const s of ["2 findings.", "| 23 | Anything at all | no_falsepositives | level critical without falsepositives: say when the rule is known to fire on benign activity |", "| 29 | Anything at all | wildcard_only | value of CommandLine is only a wildcard and matches everything |"]) assert.ok(md.includes(s), 'missing: ' + s);
});

test("reportAttack example 1", () => {
  const md = core.reportAttack("import \"pe\"\nimport \"math\"\n\n/* invented test rules */\nrule Suspicious_Loader : loader windows\n{\n    meta:\n        author = \"Example Team\"\n        description = \"Loader with injected shellcode\"\n        date = \"2026-02-11\"\n        mitre_attack = \"T1055 T1027\"\n    strings:\n        $mz = { 4D 5A }\n        $s1 = \"VirtualAllocEx\" ascii wide\n        $s2 = \"ab\"\n        $re = /.*cmd\\.exe/ nocase\n        $unused = \"never referenced\"\n    condition:\n        uint16(0) == 0x5A4D and $mz and ($s1 or $s2) and #re > 0 and pe.number_of_sections > 3\n}\n\nprivate rule Helper { strings: $a = \"helper\" condition: $a }\n\nrule Broken {\n    meta:\n        date = \"11/02/2026\"\n    strings:\n        $x = \"x1x2\"\n        $x = \"dup\"\n    condition:\n        $x and $y and any of ($z*)\n}\n");
  assert.equal(typeof md, 'string');
  for (const s of ["3 rules, 2 techniques, 0 tactics.", "| Technique | Rules |", "| T1027 | 1 |", "| T1055 | 1 |", "- Helper", "- Broken"]) assert.ok(md.includes(s), 'missing: ' + s);
});

test("reportAttack example 2", () => {
  const md = core.reportAttack("title: Suspicious PowerShell Encoded Command\nid: 6f1c2b8e-3d4a-4b5c-9e7f-1a2b3c4d5e6f\nstatus: experimental\ndescription: Detects PowerShell started with an encoded command\nauthor: Example Team\ndate: 2026/02/11\ntags:\n    - attack.execution\n    - attack.t1059.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith: '\\powershell.exe'\n    selection_cli:\n        CommandLine|contains: ' -e'\n    condition: selection_img and selection_cli\nfalsepositives:\n    - Administrative scripts\nlevel: high\n---\ntitle: Anything at all\nstatus: wip\nlogsource:\n    product: linux\ndetection:\n    sel:\n        CommandLine: '*'\n    condition: sel and filter\nlevel: critical\n");
  assert.equal(typeof md, 'string');
  for (const s of ["2 rules, 1 technique, 1 tactic.", "| Technique | Rules |", "| T1059.001 | 1 |", "| Tactic | Rules |", "| execution | 1 |", "- Anything at all"]) assert.ok(md.includes(s), 'missing: ' + s);
});
