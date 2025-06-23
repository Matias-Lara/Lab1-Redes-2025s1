#include <iostream> 
#include <string>   
#include <cryptopp/aes.h> //AES
#include <cryptopp/hex.h>  //decodificador hexadecimal
#include <cryptopp/modes.h> //cifrado CBC
#include <cryptopp/filters.h> // Para el pipeline (StringSource, StreamTransformationFilter, etc.)
#include <cryptopp/base64.h> // Para mostrar el resultado en formato de texto

using namespace CryptoPP;
using namespace std;

int main() {
    // mensaje a cifrar
    string mensaje_original = "La cámara descansa bajo el sauce llorón en el jardín del martillo.";
    // clave secreta acordada
    string clave = "6F708192A3B4C5D6E7F8A2";
    string rol = "2022040300";
    clave += rol;

    cout << "------------------------------------------------" << endl;
    cout << "Mensaje original: " << mensaje_original << endl;
    cout << "Clave en formato hexadecimal (texto): " << clave << endl;


    // contenedor para la clave en bytes, notar que AES::DEFAULT_KEYLENGTH es 16 (128bits)
    CryptoPP::byte clave_bytes[AES::DEFAULT_KEYLENGTH];
    // pipeline para conviertir la clave a binario
    // se usa StringSource porque la fuente es el string clave
    StringSource(clave, true,
        new HexDecoder( // filtro HexDecoder para transformar a bytes
            new ArraySink(clave_bytes, sizeof(clave_bytes)) // ArraySink recolecta los datos en un array
        )
    );

    // vector inicializacion
    CryptoPP::byte iv[AES::BLOCKSIZE];
    // lo llenamos con 0's para la reproducibilidad del experimento (tambien se podria usar una semilla aleatoria)
    memset(iv, 0x00, AES::BLOCKSIZE);

    // configurar cifrado AES
    // el motor de cifrado AES estara en modo CBC
    string mensaje_cifrado;
    CBC_Mode<AES>::Encryption cifrador;
    cifrador.SetKeyWithIV(clave_bytes, sizeof(clave_bytes), iv);

    // pipeline de cifrado para procesar el mensaje
    StringSource(mensaje_original, true,
        new StreamTransformationFilter(cifrador, // filtro que aplica el algoritmo de cifrado
            new StringSink(mensaje_cifrado) // StringSink recolecta los datos en un string
        )
    );

    // resultado cifrado en base 64
    // el resultado esta en bytes, para mostrarlo lo codificamos
    string mensaje_cifrado_b64;

    StringSource(mensaje_cifrado, true,
        new Base64Encoder( //filtro que recibe bytes y lo transforma en texto legible en formato base64
            new StringSink(mensaje_cifrado_b64), 
            false
        )
    );
    cout << "------------------------------------------------" << endl;
    cout << "[RESULTADO] Mensaje Cifrado (Base64): " << mensaje_cifrado_b64 << std::endl;


    // descifrando el mensaje para comprobar q se encripto bien
    string mensaje_recuperado;
    
    // creamos el motor de descifrado con 'Decryption'
    CBC_Mode<AES>::Decryption descifrador;
    // le pasamos la clave secreta acordada para q descifre
    descifrador.SetKeyWithIV(clave_bytes, sizeof(clave_bytes), iv);

    // Pipeline de descifrado. Le pasamos el texto cifrado
    StringSource(mensaje_cifrado, true,
        new StreamTransformationFilter(descifrador,
            new StringSink(mensaje_recuperado)
        )
    );

    cout << "------------------------------------------------" << endl;
    std::cout << "[VERIFICACION] Mensaje recuperado: " << mensaje_recuperado << std::endl;

    return 0;
}