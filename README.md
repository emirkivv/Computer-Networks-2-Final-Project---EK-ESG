# Computer-Networks-2-Final-Project---EK-ESG

EGE University EEE 2024-25 Computer Networks 2 Term Project - PGP SECURE EMAIL SYSTEM

Eray Samet Gündüz 052100000607@ogrenci.ege.edu.tr Emir Kıvrak 052000000484@ogrenci.ege.edu.tr

Developed and tested on Ubuntu using C++
Cryptography Library: OpenSSL

Sender:

Inputs a message.
Hashes the message (SHA-256) and generates a digital signature using the private RSA key.
Base64 encodes the message and the signature.
Sends the signed message to the receiver via TCP.

Receiver:

Listens for incoming TCP connections.
Parses the received file to extract the message and the signature.
Decodes the Base64 content.
Verifies the signature using the sender's public key.
Displays the message if the signature is valid.

[Sender Compilation](url)
g++ sender/sign_and_send.cpp shared/crypto_utils.cpp -o sender/send -lssl -lcrypto

[Receiver Compilation](url)
g++ receiver/receive_and_verify.cpp shared/crypto_utils.cpp -o receiver/receive -lssl -lcrypto
