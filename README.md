# Lab1-Redes-2025s1
## Como usar crypto++:
1. Descarguen la ultima version de cripto https://www.cryptopp.com/#download
2. Creen una carpeta en C: llamada dev (o como quieran) y metan el zip descomprimido q descargaron les deberia qquedar algo como C/dev/Criptopp890
3. Descarguen el zip de este git https://github.com/noloader/cryptopp-pem
4. Descompriman y metan todos esos archivos en C/dev/Criptopp890
5. Con MSYS navegen hasta C/dev/Criptopp890
6. Ejecuten 'make clean'
7. Ejecuten 'make'
8. Ejecuten 'make install PREFIX=/mingw64'
9. Y listo, tendran la libreria Cryptopp(crypto++) con el archivo pem.h que sirve para cargar claves pem en c++
10. Compilar los archivos con 'g++ nombre.cpp -o nombre -mconsole -lcryptopp'

## que falta de momento?
Faltaria el desarollo de la 4. (canal seguro o algo asi) creo q la solucion de esta parte se basa en crear un canal hibrido que usa AES y RSA para enviar/recibir y confirmar la autenticidad del mensaje

### Logica de asimetrico.cpp:
El mensaje es enviado de la forma paquete = mensaje_cifrado + delimitador + firma