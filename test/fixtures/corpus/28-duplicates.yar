rule Dup_Rule
{
    meta:
        author = "Example Team"
        description = "Invented rule 1"
        date = "2026-02-11"
        mitre_attack = "T1003, T1059.001"
    strings:
        $s0 = "cmd.exe /c" nocase
        $s1 = "xyz" nocase
    condition:
        any of them
}

rule Dup_Rule : linux
{
    meta:
        author = "Example Team"
        description = "Invented rule 2"
        mitre_attack = "T1059.001"
    strings:
        $s0 = "http://example.test/p" fullword
    condition:
        $s0
}
rule DupStr { strings: $a = "abcd" $a = "efgh" condition: $a }
