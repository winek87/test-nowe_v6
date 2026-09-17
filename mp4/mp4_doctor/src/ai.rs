//! Prawdziwe Modele Predykcyjne i Algorytmy Klastrowania (Enterprise ML)

use std::collections::HashMap;

/// Wektor Cech reprezentujący plik (Feature Vector).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct FeatureVector {
    pub file_size_mb: f64,
    pub entropy: f64,              // Entropia Shannona (0.0 - 8.0)
    pub h264_profile: f64,         // Znormalizowany profile_idc
    pub aac_freq: f64,             // Znormalizowana częstotliwość próbkowania
    pub video_audio_ratio: f64,    // Szacowany stosunek wideo do audio (na podstawie pierwszych 5MB)
}

impl FeatureVector {
    /// Oblicza dystans Euklidesowy między dwoma wektorami
    pub fn distance(&self, other: &Self) -> f64 {
        ((self.file_size_mb - other.file_size_mb).powi(2)
            + (self.entropy - other.entropy).powi(2)
            + (self.h264_profile - other.h264_profile).powi(2)
            + (self.aac_freq - other.aac_freq).powi(2)
            + (self.video_audio_ratio - other.video_audio_ratio).powi(2))
            .sqrt()
    }
}

/// Klasyfikator K-Nearest Neighbors (KNN)
pub struct KnnClassifier {
    knowledge_base: Vec<(FeatureVector, String)>, // Wektor cech -> Nazwa najlepszego algorytmu
}

impl Default for KnnClassifier {
    fn default() -> Self {
        Self::new()
    }
}

impl KnnClassifier {
    pub fn new() -> Self {
        Self { knowledge_base: Vec::new() }
    }

    pub fn train(&mut self, features: FeatureVector, best_algo: String) {
        self.knowledge_base.push((features, best_algo));
    }

    /// Przewiduje algorytm dla nieznanego pliku (k=3)
    pub fn predict(&self, target: &FeatureVector, k: usize) -> Option<String> {
        if self.knowledge_base.is_empty() { return None; }

        let mut distances: Vec<(f64, &String)> = self.knowledge_base.iter()
            .map(|(feat, algo)| (target.distance(feat), algo))
            .collect();

        // Sortujemy rosnąco według dystansu.
        //
        // `total_cmp`, a NIE `partial_cmp(..).unwrap()`: dystans wychodzi z
        // cech liczonych na pliku, a te potrafią dać `NaN` (np. dzielenie
        // 0/0 przy szacowaniu stosunku wideo do audio na pustym buforze).
        // `partial_cmp` zwraca wtedy `None`, a `unwrap` PANIKUJE — sprawdzone
        // empirycznie. To kod działający pod interfejsem TUI, więc panika
        // oznaczałaby rozwalony ekran w środku pracy. `total_cmp` daje porządek
        // zupełny: wartości `NaN` lądują na końcu i po prostu nie wygrywają
        // głosowania.
        distances.sort_by(|a, b| a.0.total_cmp(&b.0));

        let top_k = distances.iter().take(k);
        let mut votes = HashMap::new();
        for (_, algo) in top_k {
            *votes.entry(algo.to_string()).or_insert(0) += 1;
        }

        // Zwraca algorytm z największą ilością głosów
        votes.into_iter().max_by_key(|&(_, count)| count).map(|(algo, _)| algo)
    }
}

/// Algorytm K-Means do grupowania (klastrowania) uszkodzonych plików
pub fn cluster_files(files: &[(String, FeatureVector)], k: usize) -> Vec<Vec<String>> {
    if files.is_empty() { return Vec::new(); }
    if files.len() <= k {
        return files.iter().map(|(f, _)| vec![f.clone()]).collect();
    }

    // Prosta inicjalizacja (wybierz pierwsze K elementów jako centroidy)
    let mut centroids: Vec<FeatureVector> = files.iter().take(k).map(|(_, feat)| feat.clone()).collect();
    let mut clusters: Vec<Vec<String>> = vec![Vec::new(); k];

    // Bardzo prosta implementacja (5 iteracji w zupełności wystarczy dla małych zbiorów)
    for _ in 0..5 {
        let mut new_clusters: Vec<Vec<(String, FeatureVector)>> = vec![Vec::new(); k];

        for (filename, feat) in files {
            let mut min_dist = f64::MAX;
            let mut best_cluster = 0;

            for (i, centroid) in centroids.iter().enumerate() {
                let dist = feat.distance(centroid);
                if dist < min_dist {
                    min_dist = dist;
                    best_cluster = i;
                }
            }
            new_clusters[best_cluster].push((filename.clone(), feat.clone()));
        }

        // Aktualizacja centroidów
        for (i, cluster_files) in new_clusters.iter().enumerate() {
            if cluster_files.is_empty() { continue; }
            let mut sum_feat = FeatureVector { file_size_mb: 0.0, entropy: 0.0, h264_profile: 0.0, aac_freq: 0.0, video_audio_ratio: 0.0 };
            for (_, feat) in cluster_files {
                sum_feat.file_size_mb += feat.file_size_mb;
                sum_feat.entropy += feat.entropy;
                sum_feat.h264_profile += feat.h264_profile;
                sum_feat.aac_freq += feat.aac_freq;
                sum_feat.video_audio_ratio += feat.video_audio_ratio;
            }
            let count = cluster_files.len() as f64;
            centroids[i] = FeatureVector {
                file_size_mb: sum_feat.file_size_mb / count,
                entropy: sum_feat.entropy / count,
                h264_profile: sum_feat.h264_profile / count,
                aac_freq: sum_feat.aac_freq / count,
                video_audio_ratio: sum_feat.video_audio_ratio / count,
            };
        }

        clusters = new_clusters.into_iter().map(|c| c.into_iter().map(|(n, _)| n).collect()).collect();
    }

    clusters
}

// ============================================================================
// TESTY JEDNOSTKOWE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn wektor(rozmiar: f64, entropia: f64) -> FeatureVector {
        FeatureVector {
            file_size_mb: rozmiar,
            entropy: entropia,
            h264_profile: 0.0,
            aac_freq: 0.0,
            video_audio_ratio: 0.0,
        }
    }

    // ------------------------------------------------------------------
    // DYSTANS
    // ------------------------------------------------------------------

    #[test]
    fn test_dystans_do_siebie_jest_zerowy() {
        let w = wektor(10.0, 7.5);
        assert_eq!(w.distance(&w), 0.0);
    }

    #[test]
    fn test_dystans_jest_symetryczny() {
        let a = wektor(10.0, 7.0);
        let b = wektor(20.0, 5.0);
        assert_eq!(a.distance(&b), b.distance(&a));
    }

    /// Dystans euklidesowy po jednej osi = różnica wartości bezwzględnych.
    #[test]
    fn test_dystans_po_jednej_osi() {
        let a = wektor(0.0, 0.0);
        let b = wektor(3.0, 4.0);
        assert!((a.distance(&b) - 5.0).abs() < 1e-9, "3-4-5: dystans powinien wynosić 5");
    }

    // ------------------------------------------------------------------
    // KLASYFIKATOR KNN
    // ------------------------------------------------------------------

    #[test]
    fn test_pusty_klasyfikator_nic_nie_przewiduje() {
        let k = KnnClassifier::new();
        assert!(k.predict(&wektor(1.0, 1.0), 3).is_none());
    }

    #[test]
    fn test_klasyfikator_wskazuje_najblizszego_sasiada() {
        let mut k = KnnClassifier::new();
        k.train(wektor(10.0, 7.0), "Clone".to_string());
        k.train(wektor(1000.0, 2.0), "Native".to_string());

        assert_eq!(k.predict(&wektor(11.0, 7.1), 1).as_deref(), Some("Clone"));
        assert_eq!(k.predict(&wektor(990.0, 2.1), 1).as_deref(), Some("Native"));
    }

    /// Sens `k > 1`: decyduje WIĘKSZOŚĆ z k najbliższych, a nie sam najbliższy.
    #[test]
    fn test_wieksza_liczba_sasiadow_decyduje_glosowaniem() {
        let mut k = KnnClassifier::new();
        // Najbliższy jest "Recontainer", ale dwaj kolejni to "Clone".
        k.train(wektor(10.0, 5.0), "Recontainer".to_string());
        k.train(wektor(12.0, 5.0), "Clone".to_string());
        k.train(wektor(13.0, 5.0), "Clone".to_string());

        assert_eq!(k.predict(&wektor(10.1, 5.0), 1).as_deref(), Some("Recontainer"));
        assert_eq!(
            k.predict(&wektor(10.1, 5.0), 3).as_deref(), Some("Clone"),
            "Przy k=3 wygrywa większość, nie najbliższy"
        );
    }

    #[test]
    fn test_k_wieksze_od_bazy_nie_wywraca_predykcji() {
        let mut k = KnnClassifier::new();
        k.train(wektor(1.0, 1.0), "Clone".to_string());
        assert_eq!(k.predict(&wektor(1.0, 1.0), 100).as_deref(), Some("Clone"));
    }

    /// `k = 0` to pusty zbiór głosujących — nie może dawać odpowiedzi
    /// wyssanej z palca ani panikować.
    #[test]
    fn test_zero_sasiadow_nie_daje_odpowiedzi() {
        let mut k = KnnClassifier::new();
        k.train(wektor(1.0, 1.0), "Clone".to_string());
        assert!(k.predict(&wektor(1.0, 1.0), 0).is_none());
    }

    // ------------------------------------------------------------------
    // KLASTROWANIE
    // ------------------------------------------------------------------

    #[test]
    fn test_klastrowanie_pustej_listy_daje_pusty_wynik() {
        assert!(cluster_files(&[], 3).is_empty());
    }

    #[test]
    fn test_mniej_plikow_niz_klastrow_daje_po_jednym() {
        let pliki = vec![
            ("a.mp4".to_string(), wektor(1.0, 1.0)),
            ("b.mp4".to_string(), wektor(2.0, 2.0)),
        ];
        let wynik = cluster_files(&pliki, 5);

        assert_eq!(wynik.len(), 2);
        assert!(wynik.iter().all(|k| k.len() == 1), "Każdy plik osobno");
    }

    /// Żaden plik nie może zginąć ani zostać zduplikowany — klastrowanie ma
    /// grupować materiał dowodowy, nie gubić go.
    #[test]
    fn test_klastrowanie_zachowuje_wszystkie_pliki() {
        let pliki: Vec<(String, FeatureVector)> = (0..20)
            .map(|i| (format!("plik_{}.mp4", i), wektor(i as f64, (i % 8) as f64)))
            .collect();

        let wynik = cluster_files(&pliki, 3);

        let mut wszystkie: Vec<String> = wynik.into_iter().flatten().collect();
        wszystkie.sort();
        let mut oczekiwane: Vec<String> = pliki.iter().map(|(n, _)| n.clone()).collect();
        oczekiwane.sort();

        assert_eq!(wszystkie, oczekiwane, "Klastrowanie zgubiło albo zdublowało pliki");
    }

    #[test]
    fn test_klastrowanie_rozdziela_wyraznie_rozne_grupy() {
        let pliki = vec![
            ("maly_1.mp4".to_string(), wektor(1.0, 7.0)),
            ("maly_2.mp4".to_string(), wektor(1.5, 7.1)),
            ("duzy_1.mp4".to_string(), wektor(5000.0, 2.0)),
            ("duzy_2.mp4".to_string(), wektor(5010.0, 2.1)),
        ];
        let wynik = cluster_files(&pliki, 2);

        let grupa_malych = wynik.iter().find(|g| g.contains(&"maly_1.mp4".to_string())).unwrap();
        assert!(
            grupa_malych.contains(&"maly_2.mp4".to_string()),
            "Podobne pliki muszą trafić do jednej grupy: {:?}", wynik
        );
        assert!(
            !grupa_malych.contains(&"duzy_1.mp4".to_string()),
            "Skrajnie różne pliki nie mogą trafić do jednej grupy: {:?}", wynik
        );
    }

    // ------------------------------------------------------------------
    // ODPORNOŚĆ NA NaN
    // ------------------------------------------------------------------

    /// Regresja na realną panikę: `partial_cmp(..).unwrap()` przy `NaN`
    /// wywracał cały interfejs. Cechy liczone na pliku potrafią dać `NaN`
    /// (dzielenie 0/0), więc to nie jest przypadek hipotetyczny.
    #[test]
    fn test_nan_w_cechach_nie_wywraca_predykcji() {
        let mut k = KnnClassifier::new();
        k.train(wektor(1.0, 1.0), "Clone".to_string());
        k.train(wektor(2.0, 2.0), "Native".to_string());

        let z_nan = FeatureVector {
            file_size_mb: f64::NAN,
            entropy: 1.0,
            h264_profile: 0.0,
            aac_freq: 0.0,
            video_audio_ratio: 0.0,
        };

        // Odpowiedź może być dowolna — liczy się to, że JEST, a nie panika.
        assert!(k.predict(&z_nan, 3).is_some(), "Predykcja z NaN musi zwrócić wynik, nie panikować");
    }

    #[test]
    fn test_nan_w_bazie_wiedzy_nie_wywraca_predykcji() {
        let mut k = KnnClassifier::new();
        k.train(wektor(f64::NAN, f64::NAN), "Zepsuty".to_string());
        k.train(wektor(1.0, 1.0), "Clone".to_string());

        assert!(k.predict(&wektor(1.0, 1.0), 2).is_some());
    }

    /// Klastrowanie nie panikuje na `NaN`, bo porównania z `NaN` są zawsze
    /// fałszywe — taki plik po prostu trafia do pierwszej grupy. Test pilnuje,
    /// żeby nie zginął.
    #[test]
    fn test_nan_w_klastrowaniu_nie_gubi_pliku() {
        let pliki = vec![
            ("zepsuty.mp4".to_string(), wektor(f64::NAN, f64::NAN)),
            ("zdrowy_1.mp4".to_string(), wektor(1.0, 1.0)),
            ("zdrowy_2.mp4".to_string(), wektor(100.0, 7.0)),
        ];
        let wynik = cluster_files(&pliki, 2);
        let wszystkie: Vec<String> = wynik.into_iter().flatten().collect();

        assert!(wszystkie.contains(&"zepsuty.mp4".to_string()), "Plik z NaN nie może zginąć");
        assert_eq!(wszystkie.len(), 3);
    }
}
