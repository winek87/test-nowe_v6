// src/opisy_anomalii/faza5_metadane_inode.rs

//! Wyjaśnienia etykiet z panelu bocznego Fazy 5 —
//! `phases::phase5::build_source_block`. Treść jest bezpośrednim opisem
//! REALNYCH kryteriów wykrywania z `phase5.rs` (funkcja `process_side_stream`,
//! linie ok. 373-393 tamtego pliku, oraz `format_permissions`) — nie ma tu
//! niczego zgadywanego. Jeśli kryteria detekcji się zmienią, ten plik musi
//! zostać zaktualizowany razem z nimi.
//!
//! Pominięte celowo (generyczne, nie wymagają wyjaśnienia — ten sam wybór co
//! w `faza3_anomalie_klastra.rs` dla "Top format"/"Prędkość"/"Błędy I/O"):
//! "Prędkość", "Top format", "Wątki lstat (Wariant A)", "Błędy I/O".

use super::OpisAnomalii;

pub fn opisy() -> Vec<OpisAnomalii> {
    vec![
        OpisAnomalii {
            etykieta: "Dowiązania miękkie",
            wyjasnienie: "Plik jest dowiązaniem symbolicznym (symlink) — wykryte przez lstat(), które celowo NIE podąża za odnośnikiem. Po odzysku z uszkodzonego nośnika symlink często wskazuje na ścieżkę, która już nie istnieje albo prowadzi donikąd — sam wpis jest tylko skrótem, nie właściwymi danymi.",
        },
        OpisAnomalii {
            etykieta: "Dowiązania twarde",
            wyjasnienie: "Plik ma więcej niż jedno dowiązanie twarde (licznik nlink > 1) — kilka różnych wpisów katalogowych wskazuje na te same fizyczne dane na dysku. Ważne dla deduplikacji: usunięcie jednej nazwy NIE kasuje danych, dopóki istnieje choć jedno inne dowiązanie.",
        },
        OpisAnomalii {
            etykieta: "Właściciel root",
            wyjasnienie: "Plik należy do UID 0 (root/superużytkownik). W korpusie odzyskanych plików użytkownika to nietypowe — może być plikiem systemowym, który przypadkiem trafił do zrzutu, albo śladem podniesienia uprawnień.",
        },
        OpisAnomalii {
            etykieta: "SUID/SGID",
            wyjasnienie: "Ustawiony bit SUID (0o4000) i/lub SGID (0o2000) w uprawnieniach pliku — uruchomienie takiego pliku wykonywalnego nadaje procesowi prawa WŁAŚCICIELA (albo grupy) pliku, nie użytkownika, który go uruchomił. Krytyczne ryzyko bezpieczeństwa, jeśli plik jest wykonywalny i kontrolowany przez atakującego.",
        },
        OpisAnomalii {
            etykieta: "Pliki wykonywalne",
            wyjasnienie: "Plik ma ustawiony choć jeden bit wykonywalności (użytkownik/grupa/inni, maska 0o111) i nie jest symlinkiem. Sam bit nie mówi nic o TREŚCI pliku (skrypt, binarka, czy zwykły dokument z przypadkowo ustawionym bitem) — to tylko flaga systemu plików.",
        },
        OpisAnomalii {
            etykieta: "Epoka zerowa (1970)",
            wyjasnienie: "Czas modyfikacji pliku wynosi zero lub mniej (1 stycznia 1970 UTC albo wcześniej) — klasyczny ślad zniszczonego pola czasu i-node albo odzysku, który nie zdołał odtworzyć oryginalnego znacznika czasu.",
        },
        OpisAnomalii {
            etykieta: "Przepełnienie znacznika czasu",
            wyjasnienie: "Pole czasu modyfikacji i-node zawiera wartość tak uszkodzoną, że po przeliczeniu na nanosekundy nie mieści się już w 64-bitowej liczbie całkowitej — fizyczne zniszczenie bitów pola czasu, nie zwykłe zero. mtime zostaje NULL w bazie zamiast fałszywej, zawiniętej daty.",
        },
        OpisAnomalii {
            etykieta: "Top UID",
            wyjasnienie: "Najczęściej występujący właściciel (UID) plików w tej próbce, z liczbą wystąpień. Dominujący, spójny UID zwykle oznacza normalne konto użytkownika; rozproszenie po wielu różnych UID-ach może wskazywać na wymieszane pochodzenie plików albo uszkodzone metadane.",
        },
        OpisAnomalii {
            etykieta: "Top uprawnienia",
            wyjasnienie: "Najczęściej występujący zestaw uprawnień (format jak w poleceniu ls -l, np. -rw-r--r--) w tej próbce. Pierwszy znak to typ (- plik, d katalog, l symlink), kolejne dziewięć to prawa właściciela/grupy/innych (czytanie/pisanie/wykonywanie).",
        },
        OpisAnomalii {
            etykieta: "Top GID",
            wyjasnienie: "Najczęściej występująca grupa (GID) plików w tej próbce, z liczbą wystąpień — analogicznie do Top UID, ale dla właściciela grupowego zamiast użytkownika.",
        },
        OpisAnomalii {
            etykieta: "Epoka zerowa ctime (1970)",
            wyjasnienie: "Czas zmiany metadanych i-node (ctime) wynosi zero lub mniej — różny od mtime (\"Epoka zerowa (1970)\" wyżej opisuje czas zmiany TREŚCI pliku). ctime jest zmieniany automatycznie przez system przy KAŻDEJ zmianie i-node (w tym samych uprawnień czy właściciela) i nie da się go ustawić ręcznie jak mtime — epoka zerowa tutaj to zwykle ślad tego samego uszkodzenia metadanych, tyle że w innym polu.",
        },
        OpisAnomalii {
            etykieta: "Przepełnienie znacznika ctime",
            wyjasnienie: "Ten sam mechanizm co \"Przepełnienie znacznika czasu\" wyżej (fizyczne uszkodzenie pola czasu, którego nie da się już zapisać jako precyzyjny znacznik nanosekundowy), zastosowany do ctime zamiast mtime.",
        },
        OpisAnomalii {
            etykieta: "Pliki rzadkie (sparse)",
            wyjasnienie: "Realnie zaalokowane bloki dysku (blocks() × 512 B) są wyraźnie mniejsze (poniżej połowy) niż zadeklarowany logiczny rozmiar pliku (len()) — plik ma dziury nigdy fizycznie nie zapisane na nośniku. Normalne dla niektórych formatów (obrazy dysków, pliki bazodanowe), ale warte odnotowania przy odzysku: logiczny rozmiar pliku nie odpowiada ilości realnie zajmowanego miejsca.",
        },
        OpisAnomalii {
            etykieta: "Pliki specjalne (FIFO/socket/urządzenie)",
            wyjasnienie: "Plik jest kolejką FIFO, gniazdem sieciowym (socket) albo węzłem urządzenia znakowego/blokowego, nie zwykłym plikiem z danymi. Takie obiekty są tworzone przez system w czasie działania i nie niosą trwałych danych użytkownika — ich obecność w korpusie odzyskanym z nośnika jest z definicji nietypowa.",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_czternascie_wpisow_z_unikalnymi_etykietami() {
        let lista = opisy();
        assert_eq!(lista.len(), 14, "panel Fazy 5 ma dokładnie 14 etykiet wymagających wyjaśnienia (bez generycznych)");

        let mut etykiety: Vec<&str> = lista.iter().map(|o| o.etykieta).collect();
        etykiety.sort_unstable();
        etykiety.dedup();
        assert_eq!(etykiety.len(), 14, "etykiety muszą być unikalne, inaczej znajdz_opis znajdzie losowo pierwszą pasującą");
    }

    #[test]
    fn test_zadne_wyjasnienie_nie_jest_puste() {
        for o in opisy() {
            assert!(!o.wyjasnienie.trim().is_empty(), "etykieta \"{}\" nie ma treści wyjaśnienia", o.etykieta);
        }
    }

    /// Etykiety MUSZĄ być bajt-w-bajt zgodne z tym, co faktycznie wysyła
    /// `phase5.rs::build_source_block` — inaczej `znajdz_opis` nigdy nie
    /// znajdzie dopasowania dla prawdziwego wiersza panelu.
    #[test]
    fn test_etykiety_zgadzaja_sie_z_formatem_wysylanym_przez_faze_5() {
        let oczekiwane = [
            "Dowiązania miękkie", "Dowiązania twarde", "Właściciel root", "SUID/SGID",
            "Pliki wykonywalne", "Epoka zerowa (1970)", "Przepełnienie znacznika czasu",
            "Top UID", "Top uprawnienia", "Top GID", "Epoka zerowa ctime (1970)",
            "Przepełnienie znacznika ctime", "Pliki rzadkie (sparse)",
            "Pliki specjalne (FIFO/socket/urządzenie)",
        ];
        let lista = opisy();
        for e in oczekiwane {
            assert!(lista.iter().any(|o| o.etykieta == e), "brak opisu dla realnej etykiety Fazy 5: \"{}\"", e);
        }
    }
}
