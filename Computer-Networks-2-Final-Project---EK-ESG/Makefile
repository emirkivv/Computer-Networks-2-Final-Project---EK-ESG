# Derleyici ve bayraklar
CXX = g++
CXXFLAGS = -Wall -Wextra

# Ortak kütüphaneler
LIBS = -lssl -lcrypto

# Kaynak dosyalar
RECEIVER_SRC = receiver/receive_and_verify.cpp shared/crypto_utils.cpp
SENDER_SRC = sender/sign_and_send.cpp shared/crypto_utils.cpp

# Çıktı dosyaları
RECEIVER_BIN = receiver/receive
SENDER_BIN = sender/send

# Varsayılan hedef
all: $(RECEIVER_BIN) $(SENDER_BIN)

# Receiver derleme
$(RECEIVER_BIN): $(RECEIVER_SRC)
	$(CXX) $(CXXFLAGS) -o $(RECEIVER_BIN) $(RECEIVER_SRC) $(LIBS)

# Sender derleme
$(SENDER_BIN): $(SENDER_SRC)
	$(CXX) $(CXXFLAGS) -o $(SENDER_BIN) $(SENDER_SRC) $(LIBS)

# Temizleme komutu
clean:
	rm -f $(RECEIVER_BIN) $(SENDER_BIN)
