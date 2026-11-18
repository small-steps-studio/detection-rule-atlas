'use strict';
// Hostile and odd rule files for the adversarial test (invented; payloads must come out as plain escaped text).
const PAY = ['x|y', '<b>y</b>', '[link](https://evil.test)', '<img src=https://evil.test/i.png>', '*b*', '$x$', 'www.evil.test', '`code`'];
const cases = [];
PAY.forEach((p, i) => {
  const q = JSON.stringify(p);
  cases.push({ name: 'yara ' + i, text: 'import ' + q + '\nrule R' + i + ' : t' + i + ' { meta: author = ' + q + ' mitre_attack = ' + q + ' date = ' + q + ' strings: $a = ' + q + ' condition: $a and $' + i + 'zz }\n' });
  cases.push({ name: 'sigma ' + i, text: 'title: ' + p + '\nid: ' + p + '\nstatus: ' + p + '\nlevel: ' + p + '\ntags:\n    - attack.' + p + '\nlogsource:\n    product: ' + p + '\ndetection:\n    sel:\n        ' + p + ': ' + p + '\n    condition: sel and ' + p + '\n' });
});
cases.push({ name: 'prototype names', text: 'rule constructor { strings: $__proto__ = "abcd" $toString = "efgh" condition: $__proto__ and $hasOwnProperty }\nrule __proto__ { condition: true }\nrule constructor { condition: true }\n' });
cases.push({ name: 'sigma prototype', text: 'title: __proto__\nid: constructor\nlogsource:\n    product: x\ndetection:\n    __proto__:\n        a: b\n    constructor:\n        c: d\n    condition: __proto__ and toString\n' });
cases.push({ name: 'deep braces', text: 'rule Deep { strings: $a = { ' + '( '.repeat(5000) + '01' + ' )'.repeat(5000) + ' } condition: $a }\n' + '{'.repeat(20000) });
cases.push({ name: 'unclosed string', text: 'rule U { strings: $a = "never closed\n condition: $a }\nrule V { condition: true' });
cases.push({ name: 'many separators', text: '---\n'.repeat(20000) + 'title: x\ndetection:\n    condition: y\n' });
cases.push({ name: 'huge rule', text: 'rule Huge { strings: ' + Array.from({ length: 20000 }, (_, i) => '$s' + i + ' = "v' + i + '"').join(' ') + ' condition: any of them }\n' });
module.exports = { cases };
