# Lab1-Redes-2025s1
1. Descarguen la ultima version de cripto https://www.cryptopp.com/#download
2. Creen una carpeta en C: llamada dev (o como quieran) y metan el zip descomprimido q descargaron les deberia qquedar algo como C/dev/Criptopp890
3. Descarguen el zip de este git https://github.com/noloader/cryptopp-pem
4. Descompriman y metan todos esos archivos en C/dev/Criptopp890
5. Con MSYS navegen hasta C/dev/Criptopp890
6. Ejecuten 'make clean'
7. Ejecuten 'make'
8. Ejecuten 'make install PREFIX=/mingw64'
9. Y listo, tendran la libreria Cryptopp(crypto++) con el archivo pem.h que sirve para cargar claves pem en c++