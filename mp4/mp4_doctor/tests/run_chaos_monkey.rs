use std::path::Path;
use mp4_doctor::workspace::Workspace;
use mp4_doctor::training_ground;
use mp4_doctor::event;

/// Trening na PRAWDZIWYM materiale operatora, jeśli katalog istnieje.
///
/// `run_training` tylko CZYTA katalog źródłowy — dawców zapisuje do
/// `ws.donors_dir`, więc materiał operatora nie jest ruszany.
///
/// Przestrzeń robocza powstaje w katalogu tymczasowym (`init_testowy`) i jest
/// usuwana na końcu. Wcześniej lądowała w `mp4/mp4_doctor/workspaces/` i rosła
/// o kilkanaście megabajtów dawców przy KAŻDYM przebiegu testów, bo nikt jej
/// nie sprzątał.
#[test]
fn test_chaos_monkey_live() {
    let ws = Workspace::init_testowy("test_ws_chaos").unwrap();
    let target = "/media/NEXTCLOUD/winek/files";
    if Path::new(target).exists() {
        let (tx, _rx) = event::channel();
        training_ground::run_training(&ws, target, &tx).unwrap();
    }
    let _ = std::fs::remove_dir_all(&ws.root_dir);
}
