use mp4_doctor::workspace::Workspace;
use mp4_doctor::db::sync_with_cloud_standalone;

/// Synchronizacja z Kolektywnym Rojem — wymaga DZIAŁAJĄCEJ usługi.
///
/// `sync_with_cloud_standalone` strzela curlem do
/// `http://127.0.0.1:3000/v1/swarm/donor/{dna}`, czyli do serwera z projektu
/// `mp4_swarm_server`. Bez niego test kończy się na
/// `.expect("Failed to sync with cloud")` i KAŻDY przebieg `cargo test` wygląda
/// na regresję, mimo że kod jest sprawny — sprawdzone: po wystartowaniu
/// serwera test przechodzi („Successfully synced 2 files").
///
/// Stąd `#[ignore]`: zależność od zewnętrznej usługi jest teraz WIDOCZNA w
/// wyniku (`1 ignored`), a nie ukryta pod cichym przejściem. To świadome
/// odejście od wzorca użytego w `run_chaos_monkey.rs`, gdzie brakujący katalog
/// powoduje po prostu pustą, „zieloną" próbę — tam nie widać różnicy między
/// „przetestowano" i „pominięto".
///
/// Uruchomienie:
/// ```text
/// cargo run --bin mp4_swarm_server &          # w katalogu ../mp4_swarm_server
/// cargo test --test integration -- --ignored
/// ```
#[test]
#[ignore = "Wymaga działającego mp4_swarm_server na http://127.0.0.1:3000. Uruchom z --ignored."]
fn test_sync_with_cloud_server() {
    println!("Starting test_sync_with_cloud_server...");
    
    // Initialize workspace
    let ws = Workspace::init_testowy("test_ws_cloud_sync").expect("Failed to initialize workspace");
    
    // Call the sync function
    let count = sync_with_cloud_standalone(&ws).expect("Failed to sync with cloud");
    
    println!("Successfully synced {} files.", count);
}
