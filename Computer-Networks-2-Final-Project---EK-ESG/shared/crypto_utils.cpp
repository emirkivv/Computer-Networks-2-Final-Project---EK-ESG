#include "crypto_utils.h"
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <iostream>
#include <fstream>

// RSA imzalama
std::vector<unsigned char> sign_message(const std::string& private_key_path, const std::string& message)
{
    std::vector<unsigned char> signature;

    FILE* key_file = fopen(private_key_path.c_str(), "r"); // Private key acma kismi
    if (!key_file)
    {
        std::cerr << "Private key dosyasi bulunamadi.\n"; // Anahtar yoksa hata
        return signature;
    }

    EVP_PKEY* pkey = PEM_read_PrivateKey(key_file, nullptr, nullptr, nullptr); // Private key dosyadan okuma
    fclose(key_file);
    if (!pkey)
    {
        std::cerr << "Private key okunurken hata.\n"; // Anahtar okunamazsa hata
        return signature;
    }

    // Signature (imza) yapisi olusturma
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        EVP_PKEY_free(pkey); // Yapi olusmazsa hata
        return signature;
    }

    if (EVP_SignInit(ctx, EVP_sha256()) != 1 || // SHA-256 kullanarak imza kismi
            EVP_SignUpdate(ctx, message.c_str(), message.size()) != 1)
    {
        EVP_MD_CTX_free(ctx); // Hata olursa temizleyip cikma
        EVP_PKEY_free(pkey);
        return signature;
    }

    unsigned int sig_len = EVP_PKEY_size(pkey); // Imza icin yer acma
    signature.resize(sig_len);

    if (EVP_SignFinal(ctx, signature.data(), &sig_len, pkey) != 1)
    {
        std::cerr << "İmzalama başarısız.\n"; // Imzalama basarisiz ise hata
        signature.clear();
    }
    else
    {
        signature.resize(sig_len);
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return signature;
}

// RSA dogrulama
bool verify_signature(const std::string& public_key_path, const std::string& message, const std::vector<unsigned char>& signature)
{
    FILE* key_file = fopen(public_key_path.c_str(), "r"); // Public key acma kismi
    if (!key_file)
    {
        std::cerr << "Public key dosyası bulunamadı.\n"; // Anahtar yoksa hata
        return false;
    }

    EVP_PKEY* pkey = PEM_read_PUBKEY(key_file, nullptr, nullptr, nullptr); // Public key dosyadan okuma
    fclose(key_file);
    if (!pkey)
    {
        std::cerr << "Public key okunurken hata.\n"; // Anahtar okunamazsa hata
        return false;
    }

    // Verify (dogrulama) yapisi olusturma
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        EVP_PKEY_free(pkey); // Yapi olusmazsa hata
        return false;
    }

    // Verify islemi, SHA-256 kullaniliyor
    bool result = (EVP_VerifyInit(ctx, EVP_sha256()) == 1 && // Verify baslat
                   EVP_VerifyUpdate(ctx, message.c_str(), message.size()) == 1 && // Mesaji ekle
                   EVP_VerifyFinal(ctx, signature.data(), signature.size(), pkey) == 1); // Imzayi kontrol et

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return result; // Ustteki boolean kisimdaki her kisit saglaniyorsa true, aksi durumda false donduruluyor
}
