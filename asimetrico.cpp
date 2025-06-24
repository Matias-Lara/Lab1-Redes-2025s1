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
        // necesario para envio
        string gm_publica_file = "gm_publica.pem";
        string lyra_privada_file = "lyra_privada.pem";
        // necesario para recepcion
        string gm_privada_file = "gm_privada.pem";    
        string lyra_publica_file = "lyra_publica.pem"; 
        
        string mensaje = "Los archivos antiguos, código MPSH476, revelan la ubicación del séptimo pergamino perdido."; // 
        
        // delimitador para separar el mensaje cifrado de la firma
        const string DELIMITADOR = "::FIRMA::";

        cout << "___________________________________________________________________" << endl;
        cout << "Proceso de codificar el mensaje (lyra)..." << endl;
        // PROCESO DE LYRA (EMISOR)
        // cargar claves q lyra necesita (tiene acceso a su clave privada y a la clave publica del gm)
        RSA::PublicKey gmPublicKey;
        LoadPublicKey(gm_publica_file, gmPublicKey);
        RSA::PrivateKey lyraPrivateKey;
        LoadPrivateKey(lyra_privada_file, lyraPrivateKey);

        // cifrar el mensaje con la clave publica del gm
        string mensaje_cifrado;
        AutoSeededRandomPool rng;
        // motor encriptador
        RSAES_OAEP_SHA_Encryptor rsa_encryptor(gmPublicKey);
        // pipeline donde el filtro encripta el mensaje
        StringSource(mensaje, true, 
            new PK_EncryptorFilter(rng, rsa_encryptor, 
                new StringSink(mensaje_cifrado)
            )
        );

        // proceso de firmar el mensaje original pasado por HASH con la clave privada de lyra
        string firma;
        // motor para firmar el HASH del mensaje original
        RSASSA_PKCS1v15_SHA256_Signer signer(lyraPrivateKey);
        // pipeline donde el filtro firma
        StringSource(mensaje, true, 
            new SignerFilter(rng, signer, 
                new StringSink(firma)
            )
        );
        
        // unir las partes y luego codificar en base64 para el envio
        string paquete_para_enviar = mensaje_cifrado + DELIMITADOR + firma;
        string paquete_final_b64;
        StringSource(paquete_para_enviar, true, 
            new Base64Encoder(
                new StringSink(paquete_final_b64), false
            )
        );
        
        cout << "\nPaquete final a enviar (Base64):\n" << paquete_final_b64 << endl;

        cout << "___________________________________________________________________" << endl;
        cout << "\nProceso de decodificar el mensaje (GM)..." << endl;
        // PROCESO DE GM (RECEPTOR)
        // cargar las claves q gm necesita (tiene acceso a su clave privada y a la clave publica de lyra)
        RSA::PrivateKey gmPrivateKey;
        LoadPrivateKey(gm_privada_file, gmPrivateKey);
        RSA::PublicKey lyraPublicKey;
        LoadPublicKey(lyra_publica_file, lyraPublicKey);
        
        // decodificar el paquete de su base64
        string paquete_recibido;
        StringSource(paquete_final_b64, true, 
            new Base64Decoder(
                new StringSink(paquete_recibido)
            )
        );

        // separar el mensaje de la firma segun el delimitador usado
        size_t pos = paquete_recibido.find(DELIMITADOR);
        if (pos == string::npos) {
            throw runtime_error("Error: Delimitador de firma no encontrado.");
        }
        string msj_cifrado_recibido = paquete_recibido.substr(0, pos);
        string firma_recuperada = paquete_recibido.substr(pos + DELIMITADOR.length());

        // descifrar el mensaje con la clave privada del gm
        string mensaje_descifrado;
        // motor para descifrar que usa la pem privada del gm
        RSAES_OAEP_SHA_Decryptor rsa_decryptor(gmPrivateKey);
        StringSource(msj_cifrado_recibido, true, 
            new PK_DecryptorFilter(rng, rsa_decryptor, 
                new StringSink(mensaje_descifrado)
            )
        );
    

        // verificar la firma para saber si fue lyra la que envio el mensaje (usando la key publica de lyra)
        RSASSA_PKCS1v15_SHA256_Verifier verifier(lyraPublicKey);
        StringSource(mensaje_descifrado + firma_recuperada, true,
            new SignatureVerificationFilter(verifier, NULL, SignatureVerificationFilter::THROW_EXCEPTION) //si la firma no es de lyra retorna error
        );
        
        cout << "\nLa firma es valida. El mensaje es autentico y proviene de Lyra." << endl;
        cout << "Mensaje recuperado: " << mensaje_descifrado << endl;

    } catch (const CryptoPP::Exception& e) {
        cerr << "Error en Crypto++: " << e.what() << endl;
        return 1;
    } catch (const std::exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    return 0;
}