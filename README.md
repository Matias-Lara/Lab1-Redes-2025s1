# Lab1-Redes-2025s1

## Cómo usar Crypto++

1. Descargar la última versión de Crypto++ desde https://www.cryptopp.com/#download  
2. Crear una carpeta en 'C:\' llamada 'dev' (o con el nombre de su preferencia) y descomprimir allí el ZIP descargado (ejemplo, `C:\dev\Criptopp890`)  
3. Descargar el ZIP del repositorio PEM: https://github.com/noloader/cryptopp-pem  
4. Descomprimirlo y copiar todos los archivos en 'C:\dev\Criptopp890'
5. Abrir MSYS y navegar a 'C:/dev/Criptopp890'
6. Ejecutar los siguientes comandos:
   	'make clean'
	'make'
	'make install PREFIX=/mingw64'
7. Tras completar estos pasos, dispondrá de la biblioteca Crypto++ junto con el archivo 'pem.h', necesario para la carga de claves PEM en aplicaciones C++ 
8. Para compilar los programas con Crypto++, ejecutar:  
   	'g++ nombre.cpp -o nombre -mconsole -lcryptopp'

	

