/*
* Saul Ibañez Cerro
* Grado en Telematica
*/

#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <errno.h>
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <fcntl.h>


static const unsigned char IPAD = 0x36;
static const unsigned char OPAD = 0x5C;

static const int length_key = 64;

enum BYTE_LENGTH
{
	md5 = 16,
	sha1 = 20
};

void
initXor(unsigned char *k_xpad, unsigned char xpad){
	int i;
	for (i=0; i<length_key; i++){
		k_xpad[i] ^= xpad;
	}
}

static void 
howUse(void)
{
	fprintf(stderr, "You should introduced file to encode and file with key\n");
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

static void 
createHashSmsKey(char *file, char *file_key, SHA_CTX *cntx, unsigned char *md)
{
	unsigned char buffer[1024];
	unsigned char buffer_ipad[length_key];
	unsigned char ipad = 0x36;
	int flag_text = 0;

	memset(buffer_ipad, 0, length_key);

	openread(file_key, buffer_ipad, flag_text, cntx);
	initXor(buffer_ipad, ipad);

	if(SHA1_Init(cntx) == 0) {
		err(1, "SHA1_Init");
	}

	if(SHA1_Update(cntx, buffer_ipad, length_key) == 0) {
		err(1, "SHA1_Update buffer_ipad");
	}

	flag_text = 1;
	openread(file, buffer, flag_text, cntx);

	if(SHA1_Final(md, cntx) == 0){
		err(1, "SHA1_Final md");
	}
}

static void
createHashKeyOpad(char *file, char *file_key)
{
	SHA_CTX cntx;
	SHA_CTX cntx2;

	int flag_text = 0;
	unsigned char md[SHA_DIGEST_LENGTH];
	unsigned char md2[SHA_DIGEST_LENGTH];

	unsigned char buffer_opad[length_key];
	unsigned char opad = 0x5C;
	createHashSmsKey(file, file_key, &cntx, md);


	memset(buffer_opad, 0, length_key);
	openread(file_key, buffer_opad, flag_text, &cntx2);
	initXor(buffer_opad, opad);

	if(SHA1_Init(&cntx2) == 0) {
		err(1, "SHA1_Init");
	}

	if(SHA1_Update(&cntx2, buffer_opad, length_key) == 0) {
		err(1, "SHA1_Update with buffer_opad");
	}

	if(SHA1_Update(&cntx2, md, SHA_DIGEST_LENGTH) == 0) {
		err(1, "SHA1_Update with md");
	}

	if(SHA1_Final(md2, &cntx2) == 0){
		err(1, "SHA1_Final md2");
	}

	hexa(md2);
}
/*
static check(char *path, unsigned char *key, char *res)
{
	opensslhmac(mac[SHA_DIGEST_LENGTH]);
	str = enc16(mac, SHA_DIGEST_LENGTH);
	if(strcmp()!=0){
		err(1, "clave erronea");
	}
	free(str);
}
*/
int 
main(int argc, char *argv[]) 
{
	if (argc != 3) {
		howUse();
		err(1, "failure, incorrect arguments");
	}
	createHashKeyOpad(argv[1], argv[2]);
	/*unsigned char md[SHA_DIGEST_LENGTH];
	unsigned long len = strlen(argv[1]);

	SHA_CTX cntx;
	SHA1_Init(&cntx);
	SHA1_Update(&cntx, argv[1], len);
	SHA1_Final(md, &cntx);

	int i;
	for (i = 0; i < 20; ++i)
	{
		fprintf(stderr,"%02x", md[i]);
	}
	
	printf("\n");*/
	return 0;
}

