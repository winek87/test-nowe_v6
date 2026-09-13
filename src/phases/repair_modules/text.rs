// src/phases/repair_modules/text.rs

//! Moduł naprawczy: sanityzacja plików tekstowych (usuwanie NULL, normalizacja EOL).

use super::{RepairContext, RepairModule};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub struct TextModule;

impl RepairModule for TextModule {
    fn id(&self) -> &'static str { "text" }
    fn display_name(&self) -> &'static str { "Sanityzacja tekstu (usunięcie NULL, normalizacja EOL)" }

    /// Stosuje się do plików `.txt`/`.py`/`.csv`, które Faza 10 oznaczyła
    /// jako niepoprawny UTF-8 LUB jako podejrzany one-liner.
    fn applies_to(&self, ctx: &RepairContext) -> bool {
        (ctx.utf8_ok == Some(false) || ctx.is_oneliner == Some(true))
            && (ctx.ext == "txt" || ctx.ext == "py" || ctx.ext == "csv")
    }

    /// Usuwa twarde bajty `0x00`, wymusza reprezentację UTF-8 (bajty
    /// niepoprawne zastępowane znakiem zastępczym przez
    /// `String::from_utf8_lossy`) i normalizuje zakończenia linii CRLF→LF.
    fn repair(&self, source: &Path, _ctx: &RepairContext, _twin: Option<&Path>, katalog_wyjsciowy: &Path) -> Option<(PathBuf, String)> {
        let mut file = File::open(source).ok()?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).ok()?;

        buffer.retain(|&b| b != 0x00);

        let safe_string = String::from_utf8_lossy(&buffer).into_owned();
        let normalized = safe_string.replace("\r\n", "\n");

        let stem = source.file_stem()?.to_str()?;
        let ext = source.extension().and_then(|e| e.to_str()).unwrap_or("txt");

        let target = katalog_wyjsciowy.join(format!("{}_repaired.{}", stem, ext));

        let mut out_file = File::create(&target).ok()?;
        out_file.write_all(normalized.as_bytes()).ok()?;

        Some((target, "Usunięto zupę binarną (NULL). Wymuszono czysty UTF-8 i LF.".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn dummy_ctx() -> RepairContext<'static> {
        RepairContext { ext: "txt", media_reason: None, utf8_ok: None, is_oneliner: None, eof_ok: None, match_type: None , video_ok: None, structure_ok: None }
    }

    #[test]
    fn test_applies_to_bad_utf8_txt() {
        let m = TextModule;
        let ctx = RepairContext { ext: "txt", media_reason: None, utf8_ok: Some(false), is_oneliner: None, eof_ok: None, match_type: None , video_ok: None, structure_ok: None };
        assert!(m.applies_to(&ctx));
    }

    #[test]
    fn test_applies_to_oneliner_py() {
        let m = TextModule;
        let ctx = RepairContext { ext: "py", media_reason: None, utf8_ok: Some(true), is_oneliner: Some(true), eof_ok: None, match_type: None , video_ok: None, structure_ok: None };
        assert!(m.applies_to(&ctx));
    }

    #[test]
    fn test_does_not_apply_to_healthy_text() {
        let m = TextModule;
        let ctx = RepairContext { ext: "txt", media_reason: None, utf8_ok: Some(true), is_oneliner: Some(false), eof_ok: None, match_type: None , video_ok: None, structure_ok: None };
        assert!(!m.applies_to(&ctx));
    }

    #[test]
    fn test_does_not_apply_to_unrelated_extension() {
        let m = TextModule;
        let ctx = RepairContext { ext: "jpg", media_reason: None, utf8_ok: Some(false), is_oneliner: None, eof_ok: None, match_type: None , video_ok: None, structure_ok: None };
        assert!(!m.applies_to(&ctx));
    }

    #[test]
    fn test_repair_removes_null_bytes_and_normalizes_eol() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("brudny.txt");
        std::fs::write(&path, b"linia1\r\n\x00linia2\r\n").unwrap();

        let m = TextModule;
        let (target, _log) = m.repair(&path, &dummy_ctx(), None, dir.path()).expect("naprawa powinna się powieść");
        let content = std::fs::read_to_string(&target).unwrap();
        assert!(!content.contains('\0'));
        assert!(!content.contains("\r\n"));
        assert_eq!(content, "linia1\nlinia2\n");
    }

    /// REGRESJA: naprawiony plik NIE MOŻE trafić obok oryginału. Korpus
    /// źródłowy jest materiałem dowodowym tylko do odczytu, a pliki
    /// `*_repaired.*` leżące w nim były przy kolejnym mapowaniu struktury
    /// zliczane jako samodzielne pliki korpusu.
    #[test]
    fn test_zapisuje_do_wskazanego_katalogu_nie_obok_zrodla() {
        let zrodlo = tempdir().unwrap();
        let wynik = tempdir().unwrap();

        let path = zrodlo.path().join("brudny.txt");
        std::fs::write(&path, b"linia1\r\n\x00linia2\r\n").unwrap();

        let m = TextModule;
        let (target, _) = m.repair(&path, &dummy_ctx(), None, wynik.path()).expect("naprawa powinna się powieść");

        assert!(target.starts_with(wynik.path()), "Wynik musi leżeć we wskazanym katalogu, dostałem: {}", target.display());

        let w_zrodle: Vec<String> = std::fs::read_dir(zrodlo.path()).unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(w_zrodle, vec!["brudny.txt".to_string()], "Katalog źródłowy musi zostać nietknięty, znalazłem: {:?}", w_zrodle);
    }
}
