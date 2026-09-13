// src/mp4_repair/mod.rs

//! # Fasada nad wspólnym crate'em [`mp4_engines`]
//!
//! Silniki naprawy kontenerów ISOBMFF mieszkały tu do momentu, w którym
//! okazało się, że ISTNIEJĄ W DWÓCH KOPIACH — tu i w `mp4_doctor` — i zdążyły
//! się rozjechać: w tamtej kopii żyła nienaprawiona wada parsowania SPS, a
//! testów nie miała żadnych. Kod przeniósł się więc do osobnego crate'a
//! `mp4_engines`, od którego zależą oba projekty.
//!
//! Ten moduł pozostaje jako **fasada**, żeby setki istniejących odwołań
//! `crate::mp4_repair::...` w fazach i modułach naprawczych działały bez
//! zmiany. Nowy kod może wołać `mp4_engines::...` wprost — jedno i drugie
//! wskazuje na te same elementy.

pub use mp4_engines::{
    boxes, engine_clone, engine_native, engine_recontainer, heic_clone, heic_native, validator,
};
