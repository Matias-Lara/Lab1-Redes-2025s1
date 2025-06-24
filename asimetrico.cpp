#include <iostream>
#include <string>
#include <fstream>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/pem.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/pssr.h>

using namespace CryptoPP;
using namespace std;

// funciones para cargar las claves .pem
void LoadPublicKey(const string& filename, RSA::PublicKey& key) {
    FileSource file(filename.c_str(), true);
    PEM_Load(file, key);
}
void LoadPrivateKey(const string& filename, RSA::PrivateKey& key) {
    FileSource file(filename.c_str(), true);
    PEM_Load(file, key);
}

int main() {
    try {
        // nombre de los archivos .pem
        string gm_publica_file = "gm_publica.pem";
        string lyra_privada_file = "lyra_privada.pem";
        string mensaje = "Los archivos antiguos, código MPSH476, revelan la ubicación del séptimo pergamino perdido.";

        cout << "Mensaje original: " << mensaje << endl;

        // cargar las claves de lyra
        RSA::PublicKey gmPublicKey;
        LoadPublicKey(gm_publica_file, gmPublicKey);

        RSA::PrivateKey lyraPrivateKey;
        LoadPrivateKey(lyra_privada_file, lyraPrivateKey);

        // firmar el mensaje q lyra quiere enviar con su clave publica
        cout << "Firmando el mensaje con la clave privada de Lyra..." << endl;
        AutoSeededRandomPool rng;
        string firma;
        // motor para firmar con el esquema de cifrado OAEP
        RSASSA_PKCS1v15_SHA256_Signer signer(lyraPrivateKey);
        // pipeline donde el filtro firma el mensaje 
        StringSource(mensaje, true,
            new SignerFilter(rng, signer, 
                new StringSink(firma)
            )
        );

        // preparar el mensaje para cifrar
        string paquete = mensaje + firma;
        cout << "Tamanio del paquete (mensaje+firma): " << paquete.length() << " bytes." << endl;

        // cifrar el paquete con la clave publica del gm
        cout << "Cifrando el paquete con la clave publica del Gran Maestro..." << endl;

        // pipeline que cifra el mensaje con SHA
        string paquete_cifrado;
        RSAES_OAEP_SHA_Encryptor encriptador(gmPublicKey);
        StringSource(paquete, true,
            new PK_EncryptorFilter(rng, encriptador,
                new StringSink(paquete_cifrado)
            )
        );

        // este cout no aparecera si el paquete es dms grande por que entrara en el catch
        cout << "Paquete cifrado sin problemas." << endl;

    } catch (const CryptoPP::Exception& e) {
        // la ejecucion termina aqui cuando el PK_EncryptorFilter falla.
        cerr << "\nError en Crypto++: " << e.what() << endl;
        return 1;
    }
    return 0;
}