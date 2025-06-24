#include <iostream>
#include <string>
#include <fstream>
#include <cryptopp/rsa.h> // RSA
#include <cryptopp/files.h> // Para FileSource
#include <cryptopp/osrng.h> // Para el generador de numeros aleatorios
#include <cryptopp/base64.h> // Para Base64
#include <cryptopp/pssr.h> // Para el esquema de firma
#include <cryptopp/sha.h> // Para el hash SHA256
#include <cryptopp/pem.h>

using namespace CryptoPP;
using namespace std;

// Función para cargar una clave pública desde un archivo .pem
void LoadPublicKey(const string& filename, RSA::PublicKey& key) {
    FileSource file(filename.c_str(), true);
    PEM_Load(file, key);
}

// Función para cargar una clave privada desde un archivo .pem
void LoadPrivateKey(const string& filename, RSA::PrivateKey& key) {
    FileSource file(filename.c_str(), true);
    PEM_Load(file, key);
}

int main(){
    return 0;
}