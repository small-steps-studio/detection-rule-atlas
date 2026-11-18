rule Loader_910
{
    meta:
        date = "2025/12/01"
        reference = "https://example.test/r/910"
    strings:
        $h0 = { 84 0F 5C 0F 16 82 }
        $s1 = "xyz" fullword
        $s2 = "xyz" fullword
}
