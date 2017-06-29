/*
* Saul Ibañez Cerro
* Grado en Telematica
*
* H(K XOR opad, H(K XOR ipad, text))
*/

#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <errno.h>
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <fcntl.h>

static const int LENGTH_KEY = 64;

static void 
howUse(void)
{
	fprintf(stderr, "You should introduced file to encode and file with key\n");
	fprintf(stderr, "For example: \n\t$> dd if=/dev/zero of=/tmp/a bs=1024 count=9\n\t$> echo hola que tal > key\n\t$> ./hmacsha1 /tmp/a key\n");
	fprintf(stderr, "Result: a3ddf4e9ce354d9522dc03f72c2033e08951c9fa\n\n");
}

static void
initXor(unsigned char *k_xpad, unsigned char xpad){
	int i;
	for (i = 0; i < LENGTH_KEY; i++){
		k_xpad[i] ^= xpad;
	}
}

static int
openread(char *file, unsigned char *buffer, int flag_text, SHA_CTX *cntx)
{
	int fd;
	int nr;

	fd = open(file, O_RDONLY);
	if(fd < 0){
		warn("%s", file);
		return 0;
	}

	for(;;){
		nr = read(fd, buffer, 1024);
		if(nr < 0){
			warn("%s", file);
		}
		if(nr == 0){
			break;
		}

		if(flag_text){
			if(SHA1_Update(cntx, buffer, nr) == 0){
				err(1, "SHA1_Update buffer");
			}
		}
	}

	if(fd != 0)
		close(fd);
	return 0;
}

static void
hexa(unsigned char *md)
{
	int i;

	for (i = 0; i < 20; ++i){
		fprintf(stderr,"%02x", md[i]);
	}

	fprintf(stderr,"\n");
}

// H(K XOR ipad, text)
static void 
createHashSmsKey(char *file, char *file_key, SHA_CTX *cntx, unsigned char *md)
{
	unsigned char buffer[1024];
	unsigned char buffer_ipad[LENGTH_KEY];
	unsigned char ipad = 0x36;
	int flag_text = 0;

	memset(buffer_ipad, 0, LENGTH_KEY);

	openread(file_key, buffer_ipad, flag_text, cntx);
	initXor(buffer_ipad, ipad);

	if(SHA1_Init(cntx) == 0) {
		err(1, "SHA1_Init");
	}

	if(SHA1_Update(cntx, buffer_ipad, LENGTH_KEY) == 0) {
		err(1, "SHA1_Update buffer_ipad");
	}

	flag_text = 1;
	openread(file, buffer, flag_text, cntx);

	if(SHA1_Final(md, cntx) == 0){
		err(1, "SHA1_Final md");
	}
}

// K XOR opad
static void
createHashKeyOpad(char *file, char *file_key, SHA_CTX *cntx2)
{
	unsigned char buffer_opad[LENGTH_KEY];
	unsigned char opad = 0x5C;
	int flag_text = 0;

	memset(buffer_opad, 0, LENGTH_KEY);
	openread(file_key, buffer_opad, flag_text, cntx2);
	initXor(buffer_opad, opad);

	if(SHA1_Init(cntx2) == 0) {
		err(1, "SHA1_Init");
	}

	if(SHA1_Update(cntx2, buffer_opad, LENGTH_KEY) == 0) {
		err(1, "SHA1_Update with buffer_opad");
	}
}

// H(K XOR opad, H(K XOR ipad, text))
static void
createHMapSha1(char *file, char *file_key)
{
	SHA_CTX cntx;
	SHA_CTX cntx2;

	unsigned char md[SHA_DIGEST_LENGTH];
	unsigned char md2[SHA_DIGEST_LENGTH];

	createHashSmsKey(file, file_key, &cntx, md);
	createHashKeyOpad(file, file_key, &cntx2);

	if(SHA1_Update(&cntx2, md, SHA_DIGEST_LENGTH) == 0) {
		err(1, "SHA1_Update with md");
	}

	if(SHA1_Final(md2, &cntx2) == 0){
		err(1, "SHA1_Final md2");
	}

	hexa(md2);
}

int 
main(int argc, char *argv[]) 
{
	if (argc != 3) {
		howUse();
		errx(1, "failure, incorrect arguments");
	}
	createHMapSha1(argv[1], argv[2]);
	return 0;
}

