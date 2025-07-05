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
#define SERVER_IP "127.0.0.1" // Alicinin adresi, kullanima göre degistirilmeli

using namespace std;

// Byte to hex donusumu
string bytes_to_hex(const vector<unsigned char>& data)
{
    stringstream ss;
    for (unsigned char byte : data)
    {
        ss << hex << setw(2) << setfill('0') << (int)byte;
    }
    return ss.str();
}

// Base 64 sifreleme fonksiyonu
string base64_encode(const string& input)
{
    BIO* bio, * b64;
    BUF_MEM* buffer_ptr;

    b64 = BIO_new(BIO_f_base64()); //Base64 yapisi olusturma
    bio = BIO_new(BIO_s_mem()); // Bellekte yer acma
    bio = BIO_push(b64, bio); // Bellegi base64 yapisina ekleme

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // No newline

    BIO_write(bio, input.c_str(), input.length()); // Veri yazdirma
    BIO_flush(bio); // Buffer flush - temizleme
    BIO_get_mem_ptr(bio, &buffer_ptr); // Bellekten veriyi alma

    string encoded(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio); // Bellek temizligi ile bitirme

    return encoded;
}

//Imza vektoru icin base64 encode fonksiyonu
string base64_encode_vector(const vector<unsigned char>& input)
{
    return base64_encode(string(input.begin(), input.end()));
}

int main()
{
    string private_key_path = "sender/sender_private.pem";

    string message;
    cout << "[*] Göndermek istediğiniz mesajı girin:\n> ";
    getline(cin, message); //Mesaji command window'dan alma

    if (message.empty())
    {
        cerr << "[!] Mesaj boş olamaz.\n"; // Mesaj bos ise hata
        return 1;
    }

    cout << "[*] Mesaj imzalanıyor...\n";
    vector<unsigned char> signature = sign_message(private_key_path, message); //Mesaj imzalama
    if (signature.empty())
    {
        cerr << "[!] İmzalama başarısız.\n"; // Imzalayamaz ise hata
        return 1;
    }

    //Orijinal mesaji dosyaya yazdirma
    ofstream plain_out("sender/plaintext_normal.txt");
    plain_out << message << endl;
    plain_out.close();

    //Imzalı mesaji dosyaya yazdirma
    ofstream normal_signed_out("sender/output_signed_normal.txt");
    normal_signed_out << "MESSAGE_START\n" << message << "\nMESSAGE_END\n\n";
    normal_signed_out << "SIGNATURE (hex):\n" << bytes_to_hex(signature) << "\n";
    normal_signed_out.close();

    //Mesaj ve imzayi base64 encode etme
    string encoded_message = base64_encode(message);
    string encoded_signature = base64_encode_vector(signature);

    //Base64 mesaji dosyaya yazdirma
    ofstream plain_encoded_out("sender/plaintext.txt");
    plain_encoded_out << encoded_message << endl;
    plain_encoded_out.close();

    //Imzali mesaji base64 encode edip dosyaya yazdirma (bu dosyanin icerigi gonderilecek)
    ofstream out("sender/output_signed.txt");
    out << "MESSAGE_START\n" << encoded_message << "\nMESSAGE_END\n\n";
    out << "SIGNATURE (Base64):\n" << encoded_signature << "\n";
    out.close();

    // TCP soket programlama kisimlari
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("socket");
        return 1;
    }

    sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0)
    {
        cerr << "[!] IP adresi geçersiz.\n"; // IP hataliysa hata
        return 1;
    }

    cout << "[*] Bağlantı kuruluyor " << SERVER_IP << ":" << PORT << "...\n";

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("connect");
        return 1;
    }

    // Gonderilecek dosya aciliyor
    ifstream file("sender/output_signed.txt", ios::binary);
    if (!file)
    {
        cerr << "[!] Gönderilecek dosya bulunamadı.\n"; // Dosya yoksa hata
        return 1;
    }

    char buffer[BUFFER_SIZE];
    while (file.read(buffer, BUFFER_SIZE)) // While dongusu ile dosya bitene kadar okuma ve gonderme
    {
        send(sock, buffer, file.gcount(), 0);
    }

    if (file.gcount() > 0) // Dosyanin kalan kismini gonderme
    {
        send(sock, buffer, file.gcount(), 0);
    }

    file.close();
    close(sock);
    cout << "[✓] Dosya gönderildi.\n";

    return 0;
}
