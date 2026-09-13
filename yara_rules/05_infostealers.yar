rule InfoStealer_Discord_Browser {
    meta:
        description = "Wykrywa malware kradnący tokeny Discorda i hasła z przeglądarek"
    strings:
        $path1 = "AppData\\Roaming\\discord\\Local Storage\\leveldb" ascii wide nocase
        $path2 = "Google\\Chrome\\User Data\\Default\\Login Data" ascii wide nocase
        $path3 = "Mozilla\\Firefox\\Profiles" ascii wide nocase
        
        $action1 = "api/webhooks/" ascii wide
        $action2 = "multipart/form-data" ascii wide
    condition:
        2 of ($path*) and 1 of ($action*)
}
