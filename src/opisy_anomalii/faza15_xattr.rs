// src/opisy_anomalii/faza15_xattr.rs

//! Wyjaśnienia etykiet z panelu bocznego Fazy 15 —
//! `phases::phase15::build_source_block`. Treść jest bezpośrednim opisem
//! REALNYCH kryteriów z `extract_metadata`/`classify_url_marker`/
//! `xattr_namespace`/`is_large_xattr`/`parse_capability_names` — nie ma tu
//! niczego zgadywanego.
//!
//! Pominięte celowo (generyczne, ten sam wybór co w innych modułach tego
//! katalogu): "Prędkość", "Wątki odczytu xattr (Wariant A)", "Błędy I/O".

use super::OpisAnomalii;

pub fn opisy() -> Vec<OpisAnomalii> {
    vec![
        OpisAnomalii {
            etykieta: "XATTR znalezione",
            wyjasnienie: "Liczba plików tej strony z co najmniej jednym rozszerzonym atrybutem (xattr), rozbita wspólne/unikalne, plus łączna waga wszystkich xattr w nawiasie. Rozszerzone atrybuty to metadane systemowe przechowywane OBOK treści pliku (nie wliczają się do jego rozmiaru) — flagi kwarantanny, etykiety pochodzenia, uprawnienia.",
        },
        OpisAnomalii {
            etykieta: "Śr. rozmiar xattr (pliki z atrybutami)",
            wyjasnienie: "Łączna waga xattr podzielona przez liczbę plików, które MAJĄ co najmniej jeden atrybut (0 B, gdy żaden plik z xattr jeszcze nie znaleziony). Szybki ogląd, czy korpus zbliża się do progu anomalii \"Anomalia rozmiaru (>64KB)\" niżej, bez liczenia w głowie.",
        },
        OpisAnomalii {
            etykieta: "Top rozszerzenia (xattr)",
            wyjasnienie: "Trzy rozszerzenia plików najczęściej niosące xattr, z liczbą wystąpień (nie wagą — to metadane, nie transfer danych).",
        },
        OpisAnomalii {
            etykieta: "Top właściciele (UID:GID)",
            wyjasnienie: "Dwaj najczęściej występujący właściciele POSIX (UID:GID odczytane z i-node) wśród WSZYSTKICH przetworzonych plików tej strony, niezależnie od tego, czy mają xattr.",
        },
        OpisAnomalii {
            etykieta: "Przestrzenie nazw xattr",
            wyjasnienie: "Pełny rozkład kluczy xattr po przestrzeni nazw POSIX (część klucza przed pierwszą kropką) — standardowe to \"user\"/\"security\"/\"system\"/\"trusted\", wszystko inne trafia do \"other\". Przestrzenie \"trusted\"/\"system\" zwykle wymagają podwyższonych uprawnień do odczytu/zapisu — ich obecność jest sama w sobie sygnałem wartym odnotowania.",
        },
        OpisAnomalii {
            etykieta: "Zone.Identifier (Windows)",
            wyjasnienie: "Klucz xattr zawierający \"zone.identifier\" — dopisywany przez przeglądarki/Eksplorator Windows przy pobieraniu pliku z internetu (Mark-of-the-Web). Zawiera oryginalny URL źródłowy i strefę zabezpieczeń — cenny dowód pochodzenia pliku.",
        },
        OpisAnomalii {
            etykieta: "Quarantine (macOS)",
            wyjasnienie: "Klucz xattr zawierający \"quarantine\" (`com.apple.quarantine`) — flaga Gatekeepera macOS ustawiana przy pobraniu pliku z internetu. Zawiera znacznik czasu pobrania i aplikację, która go pobrała.",
        },
        OpisAnomalii {
            etykieta: "WhereFroms (macOS)",
            wyjasnienie: "Klucz xattr zawierający \"wherefroms\" (`com.apple.metadata:kMDItemWhereFroms`, indeksowany przez Spotlight) — zawiera BEZPOŚREDNIO oryginalny adres URL, z którego plik pochodzi. Najbardziej wartościowy z czterech sygnałów sieciowych tej fazy.",
        },
        OpisAnomalii {
            etykieta: "URL ogólne",
            wyjasnienie: "Zbiorczy licznik: dowolny z czterech sygnałów sieciowych (Zone.Identifier/Quarantine/WhereFroms/dowolny inny klucz zawierający \"url\" w nazwie), rozbity wspólne/unikalne. Patrz trzy powyższe etykiety dla rozbicia na konkretne źródło.",
        },
        OpisAnomalii {
            etykieta: "Anomalia rozmiaru (>64KB)",
            wyjasnienie: "INFORMACYJNE, nie błąd: suma rozmiarów wszystkich xattr JEDNEGO pliku przekracza 64 KB. Normalne metadane systemowe to zwykle pojedyncze bajty/kilobajty — znacznie większy blob to potencjalny wektor przemycania danych (steganografia w metadanych systemu plików).",
        },
        OpisAnomalii {
            etykieta: "Linux Capabilities (security.capability)",
            wyjasnienie: "Liczba plików z kluczem `security.capability` (rozbita wspólne/unikalne), plus do 5 najczęściej występujących nazw uprawnień w nawiasie — zdekodowanych wprost z binarnej maski bitowej `vfs_cap_data` (standard jądra Linux). Plik wykonywalny z ustawionym np. CAP_SYS_ADMIN/CAP_SETUID/CAP_NET_RAW, który przetrwał odzysk z tym mechanizmem eskalacji uprawnień nienaruszonym, jest wart priorytetowej analizy bezpieczeństwa — to alternatywa dla SUID, często pomijana przy standardowym przeglądzie uprawnień.",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jedenascie_wpisow_z_unikalnymi_etykietami() {
        let lista = opisy();
        assert_eq!(lista.len(), 11, "panel Fazy 15 ma dokładnie 11 etykiet wymagających wyjaśnienia (bez generycznych)");

        let mut etykiety: Vec<&str> = lista.iter().map(|o| o.etykieta).collect();
        etykiety.sort_unstable();
        etykiety.dedup();
        assert_eq!(etykiety.len(), 11, "etykiety muszą być unikalne, inaczej znajdz_opis znajdzie losowo pierwszą pasującą");
    }

    #[test]
    fn test_zadne_wyjasnienie_nie_jest_puste() {
        for o in opisy() {
            assert!(!o.wyjasnienie.trim().is_empty(), "etykieta \"{}\" nie ma treści wyjaśnienia", o.etykieta);
        }
    }

    /// Etykiety MUSZĄ być bajt-w-bajt zgodne z tym, co faktycznie wysyła
    /// `phase15.rs::build_source_block` — inaczej `znajdz_opis` nigdy nie
    /// znajdzie dopasowania dla prawdziwego wiersza panelu.
    #[test]
    fn test_etykiety_zgadzaja_sie_z_formatem_wysylanym_przez_faze_15() {
        let oczekiwane = [
            "XATTR znalezione", "Śr. rozmiar xattr (pliki z atrybutami)", "Top rozszerzenia (xattr)",
            "Top właściciele (UID:GID)", "Przestrzenie nazw xattr", "Zone.Identifier (Windows)",
            "Quarantine (macOS)", "WhereFroms (macOS)", "URL ogólne", "Anomalia rozmiaru (>64KB)",
            "Linux Capabilities (security.capability)",
        ];
        let lista = opisy();
        for e in oczekiwane {
            assert!(lista.iter().any(|o| o.etykieta == e), "brak opisu dla realnej etykiety Fazy 15: \"{}\"", e);
        }
    }
}
