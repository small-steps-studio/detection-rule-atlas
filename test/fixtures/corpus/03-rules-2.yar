import "pe"

// invented rules
rule Webshell_20
{
    meta:
        author = "Example Team"
        description = "Invented rule 20"
        date = "2026-02-11"
        mitre_attack = "T1105"
    strings:
        $h0 = { 17 3F 32 D8 70 5B [2-4] CC 15 }
    condition:
        2 of ($h*)
}
