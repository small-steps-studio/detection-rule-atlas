import "pe"

// invented rules
rule Dropper_40 : execution
{
    meta:
        description = "Invented rule 40"
    strings:
        $s0 = "ab" ascii
    condition:
        2 of ($s*)
}

rule Dropper_41 : webshell
{
    meta:
        author = "Example Team"
        description = "Invented rule 41"
        date = "2026-02-11"
        reference = "https://example.test/r/41"
    strings:
        $h0 = { 89 91 }
        $s1 = "http://example.test/p" ascii
        $h2 = { 25 3F C2 6B 3E B0 }
        $s3 = "cmd.exe /c" nocase
        $s4 = "VirtualAlloc" wide ascii
    condition:
        any of them
}

rule Loader_42
{
    meta:
        description = "Invented rule 42"
        date = "2026-02-11"
        reference = "https://example.test/r/42"
    strings:
        $r0 = /pass(word)?=/i
    condition:
        2 of ($r*)
}

rule Ransom_43
{
    meta:
        author = "Example Team"
        description = "Invented rule 43"
    strings:
        $h0 = { 85 CF }
        $r1 = /.*evil[0-9]+/
        $s2 = "http://example.test/p" fullword
    condition:
        $h0
}
