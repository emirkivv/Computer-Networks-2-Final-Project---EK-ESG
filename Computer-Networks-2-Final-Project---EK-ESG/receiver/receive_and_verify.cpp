#include "../shared/crypto_utils.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <netinet/in.h>

#define PORT 50505
#define BUFFER_SIZE 4096

using namespace std;

// Base 64 sifre cozme fonksiyonu
string base64_decode(const string& encoded)
{
    BIO* bio, * b64;
    int decodeLen = encoded.length();
    vector<char> buffer(decodeLen);

    b64 = BIO_new(BIO_f_base64()); // Base64 yapisi olusturma
    bio = BIO_new_mem_buf(encoded.data(), encoded.length()); // Veri okuma
    bio = BIO_push(b64, bio); // Bellegi base64 yapisina ekleme

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // No newline

    int decoded_length = BIO_read(bio, buffer.data(), decodeLen); // Decode
    BIO_free_all(bio); // Bellek temizligi

    if (decoded_length <= 0)
    return ""; // Hata varsa bos dondur

    return string(buffer.data(), decoded_length);
}

// Imza vektoru icin base64 decode fonksiyonu
vector<unsigned char> base64_decode_vector(const string& encoded)
{
    string decoded = base64_decode(encoded);
    return vector<unsigned char>(decoded.begin(), decoded.end());
}

// Gelen dosyayi ayristirma (parsing) fonksiyonu
bool parse_signed_file(const string& path, string& encoded_message, vector<unsigned char>& signature)
{
    ifstream file(path); //Dosyayi ac
    if (!file) return false; // Dosya yoksa hata

    string line;
    bool in_message = false; // Mesaj kismi kontrolu icin boolean degisken
    stringstream msg_stream, sig_stream; // Mesaj ve imza icin tanimlamalar

    while (getline(file, line))
    {
        if (line.find("MESSAGE_START") != string::npos) // Mesaj basi
        {
            in_message = true;
            continue;
        }
        else if (line.find("MESSAGE_END") != string::npos) // Mesaj sonu
        {
            in_message = false;
            continue;
        }
        else if (line.find("SIGNATURE") != string::npos) // Imza kismi
        {
            break;
        }

        if (in_message) // Mesaj satirlarini al
        {
            msg_stream << line;
        }
    }

    string sig_line; // Imza satirlarini al
    while (getline(file, sig_line))
    {
        sig_stream << sig_line;
    }

    encoded_message = msg_stream.str(); // Mesaji string yapma
    string encoded_signature = sig_stream.str(); // Imzayi string yapma

    signature = base64_decode_vector(encoded_signature); // Imzayi base64 decode etme

    return !(encoded_message.empty() || signature.empty()); // Mesaj veya imzadan biri bos ise false, degilse true dondurme
}

int main()
{
    // TCP soket programlama kisimlari
    // Alici tarafin ilk oncelikle veriyi almasi lazim
    cout << "[*] Dinleniyor (port 50505)...\n";

    int server_fd, new_socket;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    char buffer[BUFFER_SIZE];

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0)
    {
        perror("socket");
        return 1;
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0)
    {
        perror("bind");
        return 1;
    }

    if (listen(server_fd, 5) < 0)
    {
        perror("listen");
        return 1;
    }

    while (true) // Sonsuz dongude baglanti bekleniyor
    {
        cout << "[*] Yeni bağlantı bekleniyor...\n";

        new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen);
        if (new_socket < 0)
        {
            perror("accept");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(address.sin_addr), client_ip, INET_ADDRSTRLEN);

        cout << "[*] Bağlantı alındı. Gönderen IP: " << client_ip << endl;

        ofstream outfile("receiver/output_signed.txt"); //Alinan dosyayi yazmak icin ac
        int valread;
        while ((valread = read(new_socket, buffer, BUFFER_SIZE)) > 0) // Veri gelmeye devam ettikce okumaya devam et
        {
            outfile.write(buffer, valread); // Okunan veriyi yaz
        }
        outfile.close();
        close(new_socket);

        cout << "[✓] Dosya alındı: output_signed.txt\n";

        string encoded_message;
        vector<unsigned char> signature;

        if (!parse_signed_file("receiver/output_signed.txt", encoded_message, signature)) // Ayristirma islemi
        {
            cerr << "[!] Dosya ayrıştırılamadı.\n"; // Ayristirma basarisiz olursa hata
            continue;
        }

        string decoded_message = base64_decode(encoded_message); //Base64 sifreli mesaji decode et

        bool valid = verify_signature("sender/sender_public.pem", decoded_message, signature); // Imza kontrolu
        if (valid)
        {
            cout << "[✓] İmza GEÇERLİ. Mesaj kaydedildi: received.txt\n";
        }
        else
        {
            cerr << "[✗] İmza GEÇERSİZ!\n";
        }

        ofstream encoded_out("receiver/received_base64.txt"); // Base64 decode mesaji kaydet
        encoded_out << encoded_message << endl;
        encoded_out.close();

        ofstream decoded_out("receiver/received.txt"); // Base64 encode mesaji kaydet
        decoded_out << "-------------------\n";
        decoded_out << decoded_message << "\n";
        decoded_out << "-------------------\n";
        decoded_out.close();

        cout << "[✉] Gelen Mesaj (" << client_ip << " adresinden):\n" << decoded_message << endl; // Command window'a mesaji yazdirma
    }

    close(server_fd);
    return 0;
}
