
## Znane problemy do naprawy
(brak — problem z testami `menu/settings_actions.rs` nadpisującymi prawdziwy
`ustawienia.json` został naprawiony: zapis przyjmuje teraz ścieżkę jako
parametr, a testy przesłaniają `handle_key`, żeby pisać wyłącznie do pliku
tymczasowego — patrz `handle_key_do_pliku` i moduł `tests` w tym pliku).
