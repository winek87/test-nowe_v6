rule Advanced_Ransomware_Note {
    meta:
        description = "Wykrywa notatki okupowe z dużą precyzją (słowa kluczowe + portfele krypto)"
        author = "Weryfikator Kryminalistyczny"
    strings:
        // Fraz kluczowe
        $msg1 = "All your files are encrypted" nocase ascii wide
        $msg2 = "pay the ransom" nocase ascii wide
        $msg3 = "decrypt your files" nocase ascii wide
        $msg4 = "your personal id" nocase ascii wide
        
        // Wyrażenia regularne dla portfeli kryptowalut
        $btc_legacy = /1[a-km-zA-HJ-NP-Z1-9]{25,34}/        // Bitcoin (stary format)
        $btc_segwit = /bc1[a-zA-HJ-NP-Z0-9]{25,39}/         // Bitcoin (nowy format SegWit)
        $xmr_monero = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/    // Monero (ulubiona waluta hakerów)
    condition:
        // [ZABEZPIECZENIE PRZED FAŁSZYWYM ALARMEM]
        // Plik musi zawierać przynajmniej jedną groźbę ORAZ (adres krypto LUB kolejną groźbę).
        // Dzięki temu Twój prywatny plik z adresem BTC nie zostanie uznany za wirusa!
        any of ($msg*) and (any of ($btc_legacy, $btc_segwit, $xmr_monero) or #msg1 + #msg2 + #msg3 + #msg4 >= 2)
}

rule Embedded_Hidden_Executable {
    meta:
        description = "Wykrywa programy Windows (EXE/DLL) wstrzyknięte wewnątrz innych plików"
        author = "Weryfikator Kryminalistyczny"
    strings:
        $mz = { 4D 5A }             // Sygnatura 'M' 'Z' (Początek pliku DOS)
        $pe = { 50 45 00 00 }       // Sygnatura 'P' 'E' \0 \0 (Właściwy nagłówek Windows)
        $dos_stub = "This program cannot be run in DOS mode" ascii wide nocase
    condition:
        // [ZABEZPIECZENIE PRZED FAŁSZYWYM ALARMEM]
        // Szukamy sygnatury MZ, ale NIE na początku pliku (offset > 0).
        // Oznacza to, że plik EXE został doklejony do środka innego pliku (np. do zdjęcia JPG).
        // Dodatkowo upewniamy się, że zaraz za MZ znajduje się nagłówek PE lub tekst DOS.
        $mz in (1..filesize) and ($pe in (@mz[1]..@mz[1]+1024) or $dos_stub in (@mz[1]..@mz[1]+1024))
}

rule Suspicious_Powershell_Execution {
    meta:
        description = "Wykrywa złośliwe komendy PowerShell często używane przez Malware"
        author = "Weryfikator Kryminalistyczny"
    strings:
        $ps1 = "powershell" nocase ascii wide
        $ps2 = "pwsh" nocase ascii wide
        
        $bad1 = "-ExecutionPolicy Bypass" nocase ascii wide
        $bad2 = "-ep bypass" nocase ascii wide
        $bad3 = "-WindowStyle Hidden" nocase ascii wide
        $bad4 = "-w hidden" nocase ascii wide
        $bad5 = "DownloadString" nocase ascii wide
        $bad6 = "FromBase64String" nocase ascii wide
    condition:
        // Wykrywa wywołanie powershella z próbą ukrycia okna lub ominięcia zabezpieczeń
        1 of ($ps*) and 1 of ($bad*)
}
