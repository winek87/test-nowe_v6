// mp4_engines/src/lib.rs

//! # Rdzeń Naprawy Kontenerów ISOBMFF (MP4/MOV/M4V + HEIC/HEIF/AVIF)
//!
//! Wspólny crate dla Weryfikatora i `mp4_doctor` — patrz `Cargo.toml` co do
//! tego, dlaczego powstał i w którą stronę scalono rozjechane kopie.
//!
//! Zakres jest szerszy niż sama nazwa „MP4": HEIC to ten sam kontener
//! ISOBMFF, więc naprawa przeszczepem mieszka tu obok — patrz [`heic_clone`].
//!
//! Trzy NIEZALEŻNE strategie naprawy kontenera ISOBMFF, próbowane w kolejności
//! od najmocniejszej gwarancji do najsłabszej, plus rygorystyczny walidator
//! wyniku.
//!
//! | strategia | na czym polega | czego wymaga |
//! |---|---|---|
//! | [`engine_native`] | **Zero-Donor** — skanuje jednostki NAL strumienia Annex B, grupuje w klatki, wykrywa keyframe'y i odbudowuje CAŁE drzewo `moov` (H.264 + AAC) od zera | nic (czysty Rust + mmap) |
//! | [`engine_clone`] | przeszczep `moov` od dawcy, Z PRZESUNIĘCIEM tablic `stco`/`co64` pod nową pozycję `mdat` | pliku dawcy |
//! | [`engine_recontainer`] | przepakowanie przez `ffmpeg` z flagami korygującymi i korektą dryfu A/V | `ffmpeg` w systemie |
//!
//! ## Dlaczego to zastąpiło poprzedni moduł `mp4_moov`
//!
//! Poprzedni moduł potrafił JEDNĄ rzecz — przeszczep `moov` od dawcy o
//! identycznym `mdat` — i to w wersji słabszej: sprawdzał tylko, czy offsety z
//! tablic dawcy PRZYPADKIEM mieszczą się w pliku wynikowym, bez ich
//! przepisywania. [`engine_clone`] przesuwa te tablice, więc działa także gdy
//! `mdat` wylądował pod innym offsetem, a [`engine_native`] nie potrzebuje
//! dawcy w ogóle. Prymitywy parsowania boxów i walidacja offsetów z tamtego
//! modułu przeżyły — są w [`boxes`], razem ze swoimi testami.
//!
//! ## Weryfikacja wyniku
//!
//! [`validator::is_healthy_video`] to najmocniejszy dostępny dowód dla wideo:
//! pełne dekodowanie klatek, z wykrywaniem plików „pustych" (kontener
//! naprawiony, ale obraz się nie ładuje). Wpięte w obowiązkowy hook
//! `RepairModule::verify` Fazy 17 — patrz `phases::repair_modules::mp4`.

pub mod boxes;
pub mod engine_clone;
pub mod heic_clone;
pub mod heic_native;
pub mod engine_native;
pub mod engine_recontainer;
pub mod validator;

// ============================================================================
// MATERIAŁ TESTOWY
// ============================================================================

/// Ścieżka do pliku z korpusu fixture'ów (`image/` w korzeniu workspace'u).
///
/// # Dlaczego nie wystarcza ścieżka względna
///
/// `cargo test -p mp4_engines` ustawia katalog roboczy na katalog TEGO crate'a,
/// a fixture'y leżą w korzeniu workspace'u — wspólne dla Weryfikatora i dla
/// tych silników. Dopóki kod mieszkał w `src/mp4_repair`, katalogi się
/// pokrywały i `"image/..."` działało; po wydzieleniu przestało.
///
/// Rozwiązujemy to względem `CARGO_MANIFEST_DIR`, więc test zadziała niezależnie
/// od tego, z którego katalogu uruchomiono `cargo`.
#[cfg(test)]
pub(crate) fn sciezka_fixture(nazwa: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate leży w workspace, więc katalog nadrzędny istnieje")
        .join("image")
        .join(nazwa)
}
