
// invented rules
rule Ransom_100
{
    meta:
        author = "Example Team"
        description = "Invented rule 100"
        date = "2026-02-11"
        reference = "https://example.test/r/100"
        mitre_attack = "T1027"
    strings:
        $s0 = "ab" ascii
        $r1 = /.*evil[0-9]+/is
        $s2 = "xyz" fullword
        $r3 = /https?:\/\/[a-z]+\.test/i
    condition:
        $s0 and $r1 and $s2 and $r3
}

rule Stealer_101 : T1505.003
{
    meta:
        author = "Example Team"
        description = "Invented rule 101"
        date = "2025/12/01"
    strings:
        $s0 = "ab" nocase
        $s1 = "xyz" ascii
    condition:
        $s0 and $missing
}

rule Stealer_102
{
    meta:
        description = "Invented rule 102"
        date = "2025/12/01"
        mitre_attack = "T1486, T1055"
    strings:
        $s0 = "http://example.test/p"
        $s1 = "cmd.exe /c"
        $r2 = /pass(word)?=/is
        $h3 = { 0F 29 }
        $s4 = "xyz" fullword
    condition:
        any of them
}

rule Loader_103
{
    meta:
        reference = "https://example.test/r/103"
    strings:
        $h0 = { C5 8E 35 17 A0 C3 }
        $s1 = "xyz" fullword
        $s2 = "cmd.exe /c"
        $r3 = /.*evil[0-9]+/
        $h4 = { 75 87 }
    condition:
        any of them
}
