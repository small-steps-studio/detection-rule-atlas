rule Ransom_941 : linux
{
    meta:
        author = "Example Team"
        description = "Invented rule 941"
        date = "2025/12/01"
    strings:
        $h0 = { 71 11 }
        $r1 = /.*evil[0-9]+/
        $s2 = "GetProcAddress"
        $r3 = /https?:\/\/[a-z]+\.test/
    condition:
        all of them
}
