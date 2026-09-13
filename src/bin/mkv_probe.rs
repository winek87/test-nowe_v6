// src/bin/mkv_probe.rs
//
// NARZĘDZIE DIAGNOSTYCZNE - do jednorazowego uruchomienia, potem usuń.
//
// Sprawdza, czy crate `matroska` nadaje się do diagnostyki MKV/WebM w tym
// projekcie. NIE mogłem tego zweryfikować u siebie: `matroska` wymaga
// Rusta >= 1.79, a moje środowisko testowe ma 1.75. Ty masz nowszy, więc
// to uruchomienie zastępuje moją empiryczną weryfikację.
//
// Sprawdzamy DOKŁADNIE to samo, co przy rawloader/libheif/mp4:
//   1. Czy w ogóle się kompiluje z Twoją wersją Rusta.
//   2. Jakie ma realne API (czy nazwy metod zgadują się z dokumentacją).
//   3. **Czy panikuje na uszkodzonych danych, czy bezpiecznie zwraca Err** -
//      to najważniejsze pytanie, bo przy `rawloader` właśnie ten test
//      uratował nas przed paniką rozwalającą ekran TUI w trakcie skanowania.
//
// Wymaga w Cargo.toml: matroska = "0.29"
// Uruchom:  cargo run --bin mkv_probe
//   opcjonalnie z prawdziwym plikiem:  cargo run --bin mkv_probe -- sciezka/do/pliku.mkv

fn probe(label: &str, data: &[u8]) {
    let result = std::panic::catch_unwind(|| {
        matroska::Matroska::open(std::io::Cursor::new(data.to_vec()))
    });
    match result {
        Ok(Ok(m)) => {
            println!("  {label} -> OK");
            println!("      ścieżek: {}", m.tracks.len());
            if let Some(d) = m.info.duration {
                println!("      czas trwania: {:?}", d);
            }
            for t in m.tracks.iter().take(3) {
                println!("      [{}] typ={:?} kodek={}", t.number, t.tracktype, t.codec_id);
            }
        }
        Ok(Err(e)) => println!("  {label} -> Err (BEZPIECZNY): {e}"),
        Err(_) => println!("  {label} -> !!! PANIKA - wymaga catch_unwind jak rawloader !!!"),
    }
}

fn main() {
    println!("=== Weryfikacja crate `matroska` dla MKV/WebM ===\n");
    println!("[ 1 ] Odporność na uszkodzone dane:");

    probe("śmieci", b"to na pewno nie jest plik MKV");
    probe("pusty bufor", b"");

    // Poprawny magiczny nagłówek EBML, ale nic dalej - typowy ucięty plik.
    let ebml_header: &[u8] = &[0x1A, 0x45, 0xDF, 0xA3, 0x00, 0x00, 0x00, 0x00];
    probe("sam nagłówek EBML (ucięty)", ebml_header);

    // Nagłówek EBML + absurdalna deklaracja rozmiaru
    let mut bogus = ebml_header.to_vec();
    bogus.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    probe("EBML + absurdalny rozmiar", &bogus);

    println!("\n[ 2 ] Prawdziwy plik (jeśli podano argument):");
    match std::env::args().nth(1) {
        Some(path) => match std::fs::read(&path) {
            Ok(data) => {
                println!("  Wczytano {} ({} bajtów)", path, data.len());
                probe("prawdziwy plik", &data);
            }
            Err(e) => println!("  Nie udało się odczytać {path}: {e}"),
        },
        None => println!("  (pominięto - podaj ścieżkę jako argument, żeby przetestować)"),
    }

    println!("\n=== KONIEC ===");
    println!("Kluczowe pytanie: czy WYŻEJ pojawiło się gdziekolwiek '!!! PANIKA !!!'?");
    println!("  NIE  -> mogę napisać moduł MKV tak jak `video_image` dla MP4.");
    println!("  TAK  -> moduł będzie musiał mieć catch_unwind + flagę panic hooka,");
    println!("          dokładnie jak `raw_image` dla DNG.");
}
