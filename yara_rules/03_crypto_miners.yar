rule CryptoMiner_Stratum_Protocol {
    meta:
        description = "Wykrywa protokół Stratum używany przez koparki kryptowalut (np. XMRig)"
    strings:
        $pool1 = "stratum+tcp://" ascii nocase
        $pool2 = "stratum+ssl://" ascii nocase
        $algo1 = "cryptonight" ascii nocase
        $algo2 = "rx/0" ascii nocase
        $wallet = "\"user\":" ascii
        $pass = "\"pass\":" ascii
    condition:
        1 of ($pool*) and 1 of ($algo*) and $wallet and $pass
}
