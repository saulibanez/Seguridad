#Implementación de HMACSHA1 con la biblioteca openssl


Implementa un programa en C  para Linux llamado hmacsha1.c que use la biblioteca openssl para crear HMACs del tipo HMACSHA1. El programa únicamente puede usar las funciones de esa biblioteca para crear hashes SHA-1. 

El programa debe crear la HMAC del contenido del fichero que se pasa como argumento, usando como clave los datos del fichero que se le pasa como segundo argumento. Si el fichero de clave tiene más de 64 bytes, sólo se deben usar los primeros 64 bytes del fichero como clave. 

La HMAC se debe escribir en la salida estándar aplanada en hexadecimal:

$> hmacsha1 myfile.txt key
3f786850e387550fdab836ed7e6dc881de23001b

El manual de openssl se encuentra aquí: https://www.openssl.org/docs/man1.0.1/crypto/SHA1.html
La RFC 2104 describe la creación de HMACs: https://tools.ietf.org/html/rfc2104

Para compilar y enlazar con openssl:

$> gcc -o hmacsha1 hmacsha1.c -Wall -lssl -lcrypto
Un ejemplo:

$> dd if=/dev/zero of=/tmp/a bs=1024 count=9
9+0 records in
9+0 records out
9216 bytes transferred in 0.000077 secs (119674011 bytes/sec)
$> echo hola que tal > key
$> ./hmacsha1  /tmp/a key
a3ddf4e9ce354d9522dc03f72c2033e08951c9fa
