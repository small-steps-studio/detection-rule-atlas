'use strict';
// The sample files of the Open Sample commands. All data is invented for this product; it names no real company, person or system.

const SAMPLES = {
 "openSample": {
  "title": "Open Sample File",
  "fileName": "lab-rules.yar",
  "languageId": "plaintext",
  "text": "import \"pe\"\n\n/* Invented example rules for a small malware lab. */\nrule Lab_Loader_Injection : windows loader\n{\n    meta:\n        author = \"Example Lab\"\n        description = \"Loader that injects code into another process\"\n        date = \"2026-02-11\"\n        mitre_attack = \"T1055, T1027\"\n    strings:\n        $api1 = \"VirtualAllocEx\" ascii wide\n        $api2 = \"WriteProcessMemory\" ascii wide\n        $mz = { 4D 5A }\n        $cfg = /.*config\\.bin/ nocase\n        $old = \"LegacyMarker\"\n    condition:\n        uint16(0) == 0x5A4D and $mz and all of ($api*) and $cfg\n}\n\nrule Lab_Webshell : webshell T1505_003\n{\n    meta:\n        author = \"Example Lab\"\n        date = \"11/02/2026\"\n    strings:\n        $p1 = \"eval(\" nocase\n        $p2 = \"base64_decode\" nocase\n    condition:\n        $p1 and $p3\n}\n"
 },
 "openSampleSigma": {
  "title": "Open Sample Sigma File",
  "fileName": "lab-rules.yml",
  "languageId": "plaintext",
  "text": "title: Encoded PowerShell Command Line\nid: 3b9a7c2e-5d4f-4e8a-9b1c-2d3e4f5a6b7c\nstatus: test\ndescription: Detects PowerShell started with an encoded command (invented example)\nauthor: Example Lab\ndate: 2026/02/11\ntags:\n    - attack.execution\n    - attack.t1059.001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        Image|endswith: '\\powershell.exe'\n    selection_cli:\n        CommandLine|contains: ' -enc '\n    condition: selection_img and selection_cli\nfalsepositives:\n    - Software deployment scripts\nlevel: high\n---\ntitle: Any Network Tool\nstatus: stable\nlogsource:\n    category: network_connection\n    product: linux\ndetection:\n    selection:\n        Image: '*'\n        CommandLine|contains: 'nc'\n    condition: selection and not filter\nlevel: critical\n"
 }
};

/** The sample with the given id, or null. */
function sampleFor(id) { return SAMPLES[id] || null; }

module.exports = { sampleFor: sampleFor, SAMPLE_IDS: Object.keys(SAMPLES) };
