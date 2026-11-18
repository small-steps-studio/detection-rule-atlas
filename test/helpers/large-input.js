'use strict';
// Builds a YARA text of about `bytes` characters for the large-file test (invented rules).
function make(bytes) {
  const parts = ['import "pe"\n']; let size = parts[0].length, i = 0;
  while (size < bytes) {
    const s = 'rule Large_' + i + ' : windows\n{\n    meta:\n        author = "Example Lab"\n        description = "' + 'x'.repeat(60) + '"\n    strings:\n        $a = "marker' + i + '"\n        $b = { 4D 5A 90 00 03 00 }\n        $c = "ab"\n    condition:\n        $a and $b\n}\n';
    parts.push(s); size += s.length; i++;
  }
  return parts.join('');
}
module.exports = { make };
