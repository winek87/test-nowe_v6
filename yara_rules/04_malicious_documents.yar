rule Office_Malicious_Macro_AutoOpen {
    meta:
        description = "Wykrywa dokumenty Office z makrami automatycznie uruchamiającymi kod"
    strings:
        $auto1 = "AutoOpen" ascii nocase
        $auto2 = "Document_Open" ascii nocase
        $auto3 = "Workbook_Open" ascii nocase
        
        $sus1 = "WScript.Shell" ascii nocase
        $sus2 = "powershell.exe -ExecutionPolicy Bypass" ascii nocase
        $sus3 = "CreateObject(\"MSXML2.XMLHTTP\")" ascii nocase
    condition:
        1 of ($auto*) and 1 of ($sus*)
}
