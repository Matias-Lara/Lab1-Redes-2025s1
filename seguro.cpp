#include <iostream>
#include <string>
#include <fstream>
#include <stdexcept>
#include <cryptopp/rsa.h>        
#include <cryptopp/osrng.h>      
#include <cryptopp/base64.h>     
#include <cryptopp/files.h>     
#include <cryptopp/pem.h>       
#include <cryptopp/sha.h>       
#include <cryptopp/filters.h>   
#include <cryptopp/aes.h>       
#include <cryptopp/modes.h>      
#include <cryptopp/hex.h>         

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
        string gm_publica_file = "gm_publica.pem";
        string gm_privada_file = "gm_privada.pem";
        string pg_publica_file = "pg_publica.pem";
        string pg_privada_file = "pg_privada.pem";

        // clave a crifrar
        string clave_hex = "6F708192A3B4C5D6E7F8A2";
        string rol = "2022040416";
        string clave_total = clave_hex + rol;

         // delimitador para separar el mensaje cifrado de la firma
        const string DELIMITADOR = "::FIRMA::";

        // contenedor para la clave en bytes
        CryptoPP::byte clave_bytes[AES::DEFAULT_KEYLENGTH];
        // pipeline para conviertir la clave a binario
        StringSource(clave_total, true,
            new HexDecoder(
                new ArraySink(clave_bytes, sizeof(clave_bytes))
            )
        );

        // vector inicializacion
        CryptoPP::byte iv[AES::BLOCKSIZE];
        // lo llenamos con 0's para la reproducibilidad del experimento (tambien se podria usar una semilla aleatoria)
        memset(iv, 0x00, AES::BLOCKSIZE);

        
        
        // cargamos clave publica de gran maestro para cifrar el mensaje (clave simetrica) 
        RSA::PublicKey gmPublicKey;
        LoadPublicKey(gm_publica_file, gmPublicKey);

        AutoSeededRandomPool rng;
        string clave_bytes_cifrada;

        // motor encriptador
        RSAES_OAEP_SHA_Encryptor rsa_encryptor(gmPublicKey);
        // pipeline donde el filtro encripta el mensaje
        StringSource(clave_bytes, sizeof(clave_bytes), true,
            new PK_EncryptorFilter(rng, rsa_encryptor,
                new StringSink(clave_bytes_cifrada)
            )
        );

        // cargamos clave privada de pedrius godoyius para firmar el mensaje (clave simetrica)
        RSA::PrivateKey pgPrivateKey;
        LoadPrivateKey(pg_privada_file, pgPrivateKey);

        string firma;
        // motor para firmar el HASH del mensaje
        RSASSA_PKCS1v15_SHA256_Signer signer(pgPrivateKey);
        // pipeline donde el filtro firma
        StringSource(clave_bytes_cifrada, true,
            new SignerFilter(rng, signer,
                new StringSink(firma)
            )
        );

        // unir las partes y luego codificar el paquete en base64 para el envio
        string paquete_clave = clave_bytes_cifrada + DELIMITADOR + firma;
        string paquete_final_b64;
        StringSource(paquete_clave, true,
            new Base64Encoder(
                new StringSink(paquete_final_b64), false)
        );

        cout << "\nClave simétrica cifrada + firma (Base64):\n" << paquete_final_b64 << endl;

        // decodificar el paquete de su base64
        string paquete_clave_recibido;
        StringSource(paquete_final_b64, true,
            new Base64Decoder(
                new StringSink(paquete_clave_recibido))
        );

        // separar el mensaje de la firma segun el delimitador usado
        size_t pos = paquete_clave_recibido.find(DELIMITADOR);
        if (pos == string::npos) 
            throw runtime_error("Error: delimitador de firma no encontrado.");

        string clave_cifrada_recibida = paquete_clave_recibido.substr(0, pos);
        string firma_recibida = paquete_clave_recibido.substr(pos + DELIMITADOR.length());

        // contenedor para la clave a recibir
        CryptoPP::byte clave_bytes_recuperada[AES::DEFAULT_KEYLENGTH];

        // cargamos clave privada de gran maestro para decifrar el mensaje
        RSA::PrivateKey gmPrivateKey;
        LoadPrivateKey(gm_privada_file, gmPrivateKey);

        // motor para descifrar
        RSAES_OAEP_SHA_Decryptor rsa_decryptor(gmPrivateKey);
        StringSource(clave_cifrada_recibida, true,
            new PK_DecryptorFilter(rng, rsa_decryptor,
                new ArraySink(clave_bytes_recuperada, sizeof(clave_bytes_recuperada))
            )
        );

        // cargamos clave privada de pedrius godoyius para verificar la firma digital
        RSA::PublicKey pgPublicKey;
        LoadPublicKey(pg_publica_file, pgPublicKey);

        // motor de verificación
        RSASSA_PKCS1v15_SHA256_Verifier verifier(pgPublicKey);
        StringSource(clave_cifrada_recibida + firma_recibida, true,
            new SignatureVerificationFilter(verifier, NULL, SignatureVerificationFilter::THROW_EXCEPTION)
        );
        cout << "Clave simétrica recuperada y firma verificada correctamente por el Gran Maestro." << endl;


        // interaccion de gran maestro y pedrius godoyius a traves de cifrado simetrico
        string mensaje_pedrius = "El pergamino está oculto dentro del cañon de casa central.";
        string mensaje_cifrado;
        // motor de cifrado AES en modo CBC
        CBC_Mode<AES>::Encryption cifrador;
        cifrador.SetKeyWithIV(clave_bytes, sizeof(clave_bytes), iv);

        // pipeline de cifrado 
        StringSource(mensaje_pedrius, true,
            new StreamTransformationFilter(cifrador,
                new StringSink(mensaje_cifrado)
            )
        );

        // codifica el mensaje cifrado en Base64 para enviarlo
        string mensaje_cifrado_b64;
        StringSource(mensaje_cifrado, true,
            new Base64Encoder(
                new StringSink(mensaje_cifrado_b64), false)
        );

        cout << "\nPedrius envía mensaje cifrado (Base64):\n" << mensaje_cifrado_b64 << endl;

        // decodifica el mensaje cifrado en Base64 para descifrarlo
        string mensaje_cifrado_recibido;
        StringSource(mensaje_cifrado_b64, true,
            new Base64Decoder( 
                new StringSink(mensaje_cifrado_recibido))
        );

        // descifrar el mensaje recibido con AES
        string mensaje_descifrado;
        CBC_Mode<AES>::Decryption descifrador;
        descifrador.SetKeyWithIV(clave_bytes_recuperada, sizeof(clave_bytes_recuperada), iv);
        // pipeline de descifrado 
        StringSource(mensaje_cifrado_recibido, true,
            new StreamTransformationFilter(descifrador,
                new StringSink(mensaje_descifrado)
            )
        );

        cout << "Gran Maestro descifra el mensaje: " << mensaje_descifrado << endl;


        // misma logica descrita anteriormente 
        string respuesta_gm = "Recibido. Procederé con cautela.";

        string respuesta_cifrada;
        CBC_Mode<AES>::Encryption cifrador_resp;
        cifrador_resp.SetKeyWithIV(clave_bytes_recuperada, sizeof(clave_bytes_recuperada), iv);

        StringSource(respuesta_gm, true,
            new StreamTransformationFilter(cifrador_resp,
                new StringSink(respuesta_cifrada)
            )
        );

        string respuesta_cifrada_b64;
        StringSource(respuesta_cifrada, true,
            new Base64Encoder(new StringSink(respuesta_cifrada_b64), false)
        );

        cout << "\nGran Maestro envía respuesta cifrada (Base64):\n" << respuesta_cifrada_b64 << endl;

        string respuesta_cifrada_recibida;
        StringSource(respuesta_cifrada_b64, true,
            new Base64Decoder(new StringSink(respuesta_cifrada_recibida))
        );

        string respuesta_descifrada;
        CBC_Mode<AES>::Decryption descifrador_resp;

        descifrador_resp.SetKeyWithIV(clave_bytes, sizeof(clave_bytes), iv);
        StringSource(respuesta_cifrada_recibida, true,
            new StreamTransformationFilter(descifrador_resp,
                new StringSink(respuesta_descifrada)
            )
        );
        cout << "Pedrius descifra la respuesta: " << respuesta_descifrada << endl;
    } catch (const CryptoPP::Exception& e) {
        cerr << "Error en Crypto++: " << e.what() << endl;
        return 1;
    } catch (const std::exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    return 0;
}
