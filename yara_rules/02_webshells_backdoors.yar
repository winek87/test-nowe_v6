rule Webshell_PHP_Generic {
    meta:
        description = "Wykrywa złośliwe skrypty PHP (Webshells) wykonujące komendy systemowe"
    strings:
        $php = "<?php" ascii
        $cmd1 = "eval(base64_decode(" ascii
        $cmd2 = "system($_GET[" ascii
        $cmd3 = "shell_exec($_POST[" ascii
        $cmd4 = "passthru(" ascii
    condition:
        $php at 0 and any of ($cmd*)
}

rule Webshell_ASPX_Generic {
    meta:
        description = "Wykrywa złośliwe skrypty ASP.NET"
    strings:
        $s1 = "System.Diagnostics.Process.Start" ascii
        $s2 = "Request.Item[\"cmd\"]" ascii
        $s3 = "eval(" ascii
    condition:
        2 of them
}
