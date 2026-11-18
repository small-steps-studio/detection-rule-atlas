global private rule FileSize { condition: filesize < 2MB }
private rule Ransom_920
{
    meta:
        date = "2025/12/01"
        reference = "https://example.test/r/920"
    strings:
        $s0 = "http://example.test/p" wide ascii
    condition:
        $s0
}
