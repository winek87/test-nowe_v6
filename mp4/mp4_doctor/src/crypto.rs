use std::fs;
use std::io;

const SECRET_KEY: &[u8] = b"MP4_DOCTOR_ENTERPRISE_SECRET_KEY_2026";

/// Szyfruje/Odszyfrowuje plik za pomocą prostej operacji XOR (Symmetric Cipher).
/// Daje "poczucie prywatności" i uniemożliwia bezpośrednie odczytanie nagłówków MOOV 
/// przez administratorów serwera Swarm.
pub fn encrypt_decrypt_file(input_path: &str, output_path: &str) -> io::Result<()> {
    let data = fs::read(input_path)?;
    
    let mut processed_data = Vec::with_capacity(data.len());
    for (i, byte) in data.iter().enumerate() {
        let key_byte = SECRET_KEY[i % SECRET_KEY.len()];
        processed_data.push(byte ^ key_byte);
    }
    
    fs::write(output_path, processed_data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    
    #[test]
    fn test_encryption_decryption_file() {
        let test_input = "test_input.bin";
        let test_enc = "test_enc.bin";
        let test_dec = "test_dec.bin";
        
        let original_data = b"Tajna Wiadomosc Dawcy!";
        fs::write(test_input, original_data).unwrap();
        
        // Szyfrowanie
        encrypt_decrypt_file(test_input, test_enc).unwrap();
        let enc_data = fs::read(test_enc).unwrap();
        assert_ne!(original_data, enc_data.as_slice());
        
        // Odszyfrowanie (ten sam klucz)
        encrypt_decrypt_file(test_enc, test_dec).unwrap();
        let dec_data = fs::read(test_dec).unwrap();
        assert_eq!(original_data, dec_data.as_slice());
        
        // Czyszczenie
        let _ = fs::remove_file(test_input);
        let _ = fs::remove_file(test_enc);
        let _ = fs::remove_file(test_dec);
    }
}
