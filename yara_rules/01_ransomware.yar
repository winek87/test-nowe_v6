rule Ransomware_Generic_Note {
    meta:
        description = "Wykrywa generyczne notatki z żądaniem okupu (Ransomware Notes)"
        author = "Weryfikator Kryminalistyczny"
    strings:
        $s1 = "YOUR FILES ARE ENCRYPTED" ascii nocase
        $s2 = "All your files have been encrypted" ascii nocase
        $s3 = "pay the ransom" ascii nocase
        $s4 = "decrypt your files" ascii nocase
        $s5 = "Tor Browser" ascii nocase
        $s6 = ".onion/" ascii
    condition:
        2 of them
}

rule Ransomware_WannaCry_Artifacts {
    meta:
        description = "Wykrywa artefakty pozostawione przez WannaCry"
    strings:
        $w1 = "WannaDecryptor" ascii wide
        $w2 = "WNcry@2ol7" ascii
        $w3 = ".wnry" ascii
    condition:
        any of them
}
