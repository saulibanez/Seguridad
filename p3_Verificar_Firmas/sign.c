/*
* Saul Ibañez Cerro
* Grado en Telematica
*/

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>


static const unsigned char EMSASHA512ID[] = {0x30, 0x51, 0x30, 0x0d,
										0x06, 0x09, 0x60, 0x86,
										0x48, 0x01, 0x65, 0x03,
										0x04, 0x02, 0x03, 0x05,
										0x00, 0x04, 0x40};


static void 
howUse(void)
{
	fprintf(stderr, "You should introduced: sign myfile.txt privkey.pem\n");
	fprintf(stderr, "\nIf you use -v option, the program verifies the signature, you should introduced:\n" 
		"sign -v signature.pem myfile.txt pubkey.pem, where:\n signature.pem -> File with digital signature.\n"
		" myfile.txt -> File of the signed data.\n pubkey.pem -> File containing the corresponding public key.\n");
}

/*
* The padding to generate is: 0x00||0x01||PS||0x00||T
*/
static void
generatePadding(unsigned char *hash, unsigned char *sign_sms)
{
	long unsigned int len_T, len_PS;
	int size_sha515_id = sizeof(EMSASHA512ID);
	int bits = 8;
	int rsa = 4096;

	len_T = size_sha515_id + SHA512_DIGEST_LENGTH;

	len_PS = ((rsa/bits) - len_T -3);
	unsigned char PS[len_PS];

	memset(PS, 0xff, len_PS);
	
	sign_sms[0] = 0x00;
	sign_sms[1] = 0x01;
	memcpy(&sign_sms[2], PS, len_PS);
	sign_sms[len_PS + 2] = 0x00;

	// Generate T = ID || HASH
	memcpy(&sign_sms[len_PS + 3], EMSASHA512ID, size_sha515_id);
	memcpy(&sign_sms[len_PS + 3 + size_sha515_id], hash, SHA512_DIGEST_LENGTH);
}

static int
openread(char *file, unsigned char *buffer, SHA512_CTX *cntx)
{
	int fd;
	int nr;

	fd = open(file, O_RDONLY);
	if(fd < 0){
		errx(1, "failure, open file %s", file);
	}

	for(;;){
		nr = read(fd, buffer, 1024);
		if(nr < 0){
			errx(1, "failure, read file %s", file);
		}
		if(nr == 0){
			break;
		}

		if(SHA512_Update(cntx, buffer, nr) == 0){
			errx(1, "SHA512_Update buffer");
		}
	}

	if(SHA512_Update(cntx, file, strlen(file)) == 0){
		errx(1, "SHA512_Update buffer with name file");
	}
	
	if(fd != 0)
		close(fd);
	return 0;
}

static void
createHash(char *file, unsigned char *hash)
{
	SHA512_CTX cntx;
	unsigned char buffer[1024];
	
	if(SHA512_Init(&cntx) == 0) {
		errx(1, "SHA512_Init");
	}

	openread(file, buffer, &cntx);

	if(SHA512_Final(hash, &cntx) == 0){
		errx(1, "SHA512_Final md");
	}
}

static void 
encrypt(char *privkey, unsigned char *sign_sms, unsigned char *encrypted)
{
	FILE *file;
	RSA *rsa;
	int rsa_private;

	file = fopen(privkey, "r");
	if(file == NULL){
		errx(1, "failure open privkey %s", privkey);
	}

	rsa = PEM_read_RSAPrivateKey(file, NULL ,NULL, NULL);
	if(rsa == NULL){
		errx(1, "failure PEM_read_RSAPrivateKey");
	}

	rsa_private = RSA_private_encrypt(512, sign_sms, encrypted, rsa, RSA_NO_PADDING);
	if(rsa_private < 0){
		errx(1, "failure RSA_private_encrypt");
	}

	if(fclose(file) != 0){
		exit(EXIT_FAILURE);
	}
}

static void
flattenBase64(unsigned char *data)
{
	char start[] = "---BEGIN SRO SIGNATURE---";
	char end[] = "---END SRO SIGNATURE---";
	BIO *b64, *bio;

	b64 = BIO_new(BIO_f_base64());
	printf("%s\n", start);

	bio = BIO_new_fp(stdout, BIO_NOCLOSE);
	bio = BIO_push(b64, bio);

	if(BIO_write(b64, data, 512) < 0){
		errx(1, "failure, BIO_write");
	}

	if(BIO_flush(b64) < 1){
		errx(1, "BIO_flush");
	}

	printf("%s\n", end);
	BIO_free_all(b64);
}

static void
readBase64(char *signature, unsigned char *encrypted)
{
	FILE *file;
	BIO *b64, *bio;

	file = fopen(signature, "r");
	if(file == NULL){
		errx(1, "failure open signature %s", signature);
	}

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fp(file, BIO_NOCLOSE);
	bio = BIO_push(b64, bio);

	if(BIO_read(b64, encrypted, 512) < 0){
		errx(1, "BIO_read");
	}

	if(fclose(file) != 0){
		exit(EXIT_FAILURE);
	}	

	BIO_free_all(b64);
}

static void
decrypt(unsigned char *encrypted, unsigned char *decrypted, char *pubkey)
{
	FILE *file;
	RSA *rsa;
	int rsa_public;

	file = fopen(pubkey, "r");
	if(file == NULL){
		errx(1, "failure open pubkey %s", pubkey);
	}

	rsa = PEM_read_RSA_PUBKEY(file, NULL ,NULL, NULL);
	if(rsa == NULL){
		errx(1, "failure PEM_read_RSA_PUBKEY");
	}

	rsa_public = RSA_public_decrypt(512, encrypted, decrypted, rsa, RSA_NO_PADDING);
	if(rsa_public < 0){
		errx(1, "failure RSA_public_decrypt");
	}

	if(fclose(file) != 0){
		exit(EXIT_FAILURE);
	}
}

static void
improveHash(unsigned char *hash)
{
	SHA512_CTX cntx;
	
	if(SHA512_Init(&cntx) == 0) {
		errx(1, "SHA512_Init");
	}

	if(SHA512_Update(&cntx, hash, SHA512_DIGEST_LENGTH) == 0){
		errx(1, "SHA512_Update hash");
	}

	if(SHA512_Final(hash, &cntx) == 0){
		errx(1, "SHA512_Final md");
	}
}

static void
verify(char *signature, char *myfile, char *pubkey)
{
	unsigned char hash[SHA512_DIGEST_LENGTH];
	unsigned char sign_sms[512];
	unsigned char encrypted[512];
	unsigned char decrypted[512];
	readBase64(signature, encrypted);
	createHash(myfile, hash);
	generatePadding(hash, sign_sms);
	decrypt(encrypted, decrypted, pubkey);
	if(memcmp(sign_sms, decrypted, 512) != 0){
		errx(1, "failure, incorrect signature");
	}
}

static void
sign(char *file, char *privkey)
{
	unsigned char hash[SHA512_DIGEST_LENGTH];
	unsigned char sign_sms[512];
	unsigned char encrypted[512];
	createHash(file, hash);
	//improveHash(hash);
	//improveHash(hash);
	generatePadding(hash, sign_sms);
	encrypt(privkey, sign_sms, encrypted);
	flattenBase64(encrypted);
}

int 
main(int argc, char *argv[])
{
	if(argc < 3 || argc > 5 || argc == 4) {
		howUse();
		errx(1, "Failure, incorrect arguments");
	}

	if(strcmp(argv[1], "-v") == 0){
		verify(argv[2], argv[3], argv[4]);
	}else{
		sign(argv[1], argv[2]);
	}

	//printf("Argv: %s, %i\n", argv[1], strlen(argv[1]));

	exit(EXIT_SUCCESS);	
}
