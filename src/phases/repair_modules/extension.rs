// src/phases/repair_modules/extension.rs

//! Moduł naprawczy: korekta fałszywego rozszerzenia (na podstawie MIME z Fazy 12).
//!
//! NAPRAWIONY BUG SPRZED MODULARYZACJI: oryginalny `RepairTask.true_mime`
//! był zawsze ustawiany na `None` (nigdy nie wypełniany z bazy) — warunek
//! `task.true_mime.is_some()` był więc zawsze fałszywy i CAŁA naprawa
//! fałszywych rozszerzeń nigdy się nie uruchamiała, mimo że
//! `repair_extension()` wyglądała na w pełni działającą. Prawdziwy MIME
//! jest w rzeczywistości już zaszyty w tekście `media_reason` z Fazy 12
//! (`"Fałszywe rozszerzenie (Wewnątrz to: {mime})"`) — [`extract_true_mime`]
//! go stamtąd wyciąga.

use super::{RepairContext, RepairModule};
use std::fs;
use std::path::{Path, PathBuf};

/// Wyciąga prawdziwy MIME z tekstu powodu Fazy 12, np. z
/// `"Fałszywe rozszerzenie (Wewnątrz to: video/mp4)"` zwraca `Some("video/mp4")`.
/// Zwraca `None`, gdy tekst nie pasuje do oczekiwanego wzorca.
fn extract_true_mime(reason: &str) -> Option<&str> {
    let start = reason.find("Wewnątrz to: ")? + "Wewnątrz to: ".len();
    let rest = &reason[start..];
    let end = rest.find(')')?;
    Some(&rest[..end])
}

pub struct ExtensionModule;

impl RepairModule for ExtensionModule {
    fn id(&self) -> &'static str { "extension" }
    fn display_name(&self) -> &'static str { "Korekta fałszywego rozszerzenia" }

    /// Stosuje się, gdy Faza 12 zgłosiła powód zawierający `"Fałszywe"`
    /// (niezgodność MIME z deklarowanym rozszerzeniem) ORAZ udaje się z
    /// niego wyciągnąć prawdziwy MIME — inaczej nie ma jak dobrać nowego
    /// rozszerzenia.
    fn applies_to(&self, ctx: &RepairContext) -> bool {
        ctx.media_reason
            .is_some_and(|r| r.contains("Fałszywe") && extract_true_mime(r).is_some())
    }

    /// Kopiuje plik pod nową nazwą z rozszerzeniem wywiedzionym z
    /// prawdziwego MIME wyciągniętego z `ctx.media_reason`. Zwraca `None`
    /// dla MIME spoza rozpoznawanej listy.
    fn repair(&self, source: &Path, ctx: &RepairContext, _twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let true_mime = extract_true_mime(ctx.media_reason?)?;
        let stem = source.file_stem()?.to_str()?;

        let new_ext = match true_mime {
            m if m.contains("jpeg") => "jpg",
            m if m.contains("png") => "png",
            m if m.contains("pdf") => "pdf",
            m if m.contains("mp4") => "mp4",
            m if m.contains("zip") => "zip",
            _ => return None,
        };

        let new_name = format!("{}_repaired.{}", stem, new_ext);
        let target = katalog_wyjsciowy.join(&new_name);

        if fs::copy(source, &target).is_ok() {
            Some((target, format!("Poprawiono fałszywe rozszerzenie na .{}", new_ext)))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_extract_true_mime_parses_reason_string() {
        assert_eq!(extract_true_mime("Fałszywe rozszerzenie (Wewnątrz to: video/mp4)"), Some("video/mp4"));
        assert_eq!(extract_true_mime("Fałszywe rozszerzenie (Wewnątrz to: image/png)"), Some("image/png"));
    }

    #[test]
    fn test_extract_true_mime_returns_none_for_unrelated_text() {
        assert_eq!(extract_true_mime("Zniszczony Nagłówek (Brak Wymiarów X/Y)"), None);
    }

    #[test]
    fn test_applies_to_fake_extension_reason_with_parseable_mime() {
        let m = ExtensionModule;
        let ctx = RepairContext { ext: "jpg", media_reason: Some("Fałszywe rozszerzenie (Wewnątrz to: video/mp4)"), utf8_ok: None, is_oneliner: None, eof_ok: None, match_type: None , video_ok: None, structure_ok: None };
        assert!(m.applies_to(&ctx));
    }

    #[test]
    fn test_does_not_apply_without_fake_reason() {
        let m = ExtensionModule;
        let ctx = RepairContext { ext: "jpg", media_reason: Some("Zniszczony Nagłówek"), utf8_ok: None, is_oneliner: None, eof_ok: None, match_type: None , video_ok: None, structure_ok: None };
        assert!(!m.applies_to(&ctx));
    }

    #[test]
    fn test_repair_renames_to_correct_extension() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("plik.jpg");
        std::fs::write(&path, b"tak naprawde to png").unwrap();

        let m = ExtensionModule;
        let ctx = RepairContext { ext: "jpg", media_reason: Some("Fałszywe rozszerzenie (Wewnątrz to: image/png)"), utf8_ok: None, is_oneliner: None, eof_ok: None, match_type: None , video_ok: None, structure_ok: None };
        let (target, log) = m.repair(&path, &ctx, None, dir.path()).expect("naprawa powinna się powieść");
        assert!(target.to_string_lossy().ends_with("_repaired.png"));
        assert!(log.contains(".png"));
    }

    #[test]
    fn test_repair_returns_none_for_unrecognized_mime() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("plik.dat");
        std::fs::write(&path, b"cokolwiek").unwrap();

        let m = ExtensionModule;
        let ctx = RepairContext { ext: "dat", media_reason: Some("Fałszywe rozszerzenie (Wewnątrz to: application/octet-stream)"), utf8_ok: None, is_oneliner: None, eof_ok: None, match_type: None , video_ok: None, structure_ok: None };
        assert!(m.repair(&path, &ctx, None, dir.path()).is_none());
    }

    #[test]
    fn test_repair_returns_none_without_reason() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("plik.jpg");
        std::fs::write(&path, b"cokolwiek").unwrap();

        let m = ExtensionModule;
        let ctx = RepairContext { ext: "jpg", media_reason: None, utf8_ok: None, is_oneliner: None, eof_ok: None, match_type: None , video_ok: None, structure_ok: None };
        assert!(m.repair(&path, &ctx, None, dir.path()).is_none());
    }
}

