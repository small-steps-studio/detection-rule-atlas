rule Ransom_911
{
    meta:
        author = "Example Team"
        description = "Invented rule 911"
        reference = "https://example.test/r/911"
        mitre_attack = "T1071.001"
    strings:
        $r0 = /https?:\/\/[a-z]+\.test/i
        $s1 = "VirtualAlloc" wide ascii
        $h2 = { ED 36 A5 E5 AA BD [2-4] 0C 3F ( 01 | 02 ) ??  }
    condition:
        uint16(0) == 0x5A4D and $r0

