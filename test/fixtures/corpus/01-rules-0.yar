import "pe"

// invented rules
rule Webshell_0
{
    meta:
        author = "Example Team"
        date = "11.02.2026"
    strings:
        $r0 = /.*evil[0-9]+/
    condition:
        2 of ($r*)
}

rule Ransom_1
{
    meta:
        author = "Example Team"
        description = "Invented rule 1"
        date = "2025/12/01"
        mitre_attack = "T1027"
    strings:
        $h0 = { C6 04 }
        $r1 = /.*evil[0-9]+/
        $r2 = /https?:\/\/[a-z]+\.test/i
    condition:
        $h0 and $r1 and $r2
}

rule Dropper_2 : windows
{
    meta:
        author = "Example Team"
        description = "Invented rule 2"
        date = "2025/12/01"
        reference = "https://example.test/r/2"
    strings:
        $s0 = "ab" wide ascii
        $r1 = /pass(word)?=/is
        $s2 = "cmd.exe /c" ascii
        $s3 = "VirtualAlloc" nocase
        $r4 = /pass(word)?=/i
    condition:
        $s0
}

rule Ransom_3
{
    meta:
        author = "Example Team"
        reference = "https://example.test/r/3"
        mitre_attack = "T1003, T1059.001"
    strings:
        $h0 = { 1A 49 15 A7 84 31 [2-4] 21 B7 }
        $h1 = { 35 76 }
        $s2 = "GetProcAddress"
        $h3 = { D3 B3 8A 5F 7A 87 }
        $s4 = "http://example.test/p" wide ascii
    condition:
        $h0 and $h1 and $s2 and $h3 and $s4
}

rule Stealer_4 : webshell
{
    meta:
        author = "Example Team"
        description = "Invented rule 4"
        date = "2026-02-11"
        reference = "https://example.test/r/4"
    strings:
        $r0 = /pass(word)?=/is
        $s1 = "GetProcAddress" ascii
    condition:
        $r0
}

rule Loader_5
{
    meta:
        author = "Example Team"
        description = "Invented rule 5"
        date = "2025/12/01"
    strings:
        $r0 = /.*evil[0-9]+/is
        $h1 = { AA AF AB B5 E5 95 [2-4] AB D2 }
        $r2 = /pass(word)?=/i
        $h3 = { 2A 03 }
    condition:
        $r0 and $h1 and $r2 and $h3
}
