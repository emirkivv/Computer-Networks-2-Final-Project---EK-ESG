#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <string>
#include <vector>

// RSA imzalama
std::vector<unsigned char> sign_message(const std::string& private_key_path, const std::string& message);

// RSA dogrulama
bool verify_signature(const std::string& public_key_path, const std::string& message, const std::vector<unsigned char>& signature);

#endif
