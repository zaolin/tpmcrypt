#include <crypto/CryptoBackend.h>
#include <random>
#include <crypto++/pwdbased.h>
#include <crypto++/modes.h>
#include <crypto++/aes.h>
#include <crypto++/osrng.h>
#include <crypto++/sha.h>

using namespace std;
using namespace crypto;
using namespace CryptoPP;
using namespace utils;

const static unsigned DEFAULT_SALT_LEN = 32;
const static unsigned DEFAULT_ITERATIONS_LEN = 2000;

SecureMem<char>
CryptoBackend::generateRandomString(size_t count, bool allAscii)
{
	size_t counter = 0;
	std::random_device rng;
	std::uniform_int_distribution<int> dist(0, 255);
	char byteRand;
	char *random = (char*) calloc(count, sizeof(char));

	while (strlen(random) < count) {
		byteRand = (char) dist(rng) % 128;

		if (allAscii) {
			if (isgraph(byteRand)) {
				random[counter++] = byteRand;
			}
		} else {
			if (isalnum(byteRand)) {
				random[counter++] = byteRand;
			}
		}
	}
	byteRand = (char) 0;
	SecureMem<char> randomString(random, count);

	if (random != NULL) {
		free(random);
	}

	return randomString;
}

SecureMem<char>
CryptoBackend::getPassword(const char *promt)
{
	char *password = getpass(promt);
	SecureMem<char> spassword;

	spassword = SecureMem<char>(password, strlen(password));

	if (password != NULL) {
		free(password);
	}

	return spassword;
}

byte*
CryptoBackend::generateSalt()
{
	AutoSeededRandomPool rnd;
	byte *salt = (byte*) calloc(DEFAULT_SALT_LEN, sizeof(byte));

	if (salt == NULL) {
            throw CryptoBackendException("Can't allocate memory!");
	}

	rnd.GenerateBlock(salt, DEFAULT_SALT_LEN);

	return salt;
}

byte*
CryptoBackend::generateIV()
{
	AutoSeededRandomPool rnd;
	byte *iv = (byte*) calloc(AES::BLOCKSIZE, sizeof(byte));

	if (iv == NULL) {
            throw CryptoBackendException("Can't allocate memory!");
	}

	rnd.GenerateBlock(iv, AES::BLOCKSIZE);

	return iv;
}

SecureMem<unsigned char>
CryptoBackend::keyDerivation(SecureMem<unsigned char> passphrase, byte *salt)
{
	PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
	byte key[AES::DEFAULT_KEYLENGTH];
	int result = 0;

	result = pbkdf2.DeriveKey(key,
		AES::DEFAULT_KEYLENGTH,
		0,
		passphrase.getPointer(),
		passphrase.getLen(),
		salt,
		DEFAULT_SALT_LEN,
		DEFAULT_ITERATIONS_LEN,
		0);

	if (result < 0) {
            throw CryptoBackendException("Can't derive key from passphrase!");
	}

	return SecureMem<unsigned char>(key, AES::DEFAULT_KEYLENGTH);
}

vector<string>
CryptoBackend::initBlob(SecureMem<unsigned char> toEncrypt, SecureMem<unsigned char> passphrase)
{
	byte *iv = NULL, *salt = NULL, *encrypted = NULL;
	vector<string> cryptoParams;
	SecureMem<unsigned char> key;
        
        encrypted = (byte*) malloc(sizeof(byte)*toEncrypt.getLen());

	iv = generateIV();
	salt = generateSalt();

	key = keyDerivation(passphrase, salt);

	CFB_Mode<AES>::Encryption cfbEncryption(key.getPointer(), key.getLen(), iv);
	cfbEncryption.ProcessData(encrypted, toEncrypt.getPointer(), toEncrypt.getLen());

	cryptoParams.push_back(string(const_cast<const char*> (reinterpret_cast<char*> (encrypted))));
	cryptoParams.push_back(string(const_cast<const char*> (reinterpret_cast<char*> (iv))));
	cryptoParams.push_back(string(const_cast<const char*> (reinterpret_cast<char*> (salt))));
        
        free(encrypted);

	return cryptoParams;
}

SecureMem<unsigned char>
CryptoBackend::decryptBlob(string toDecrypt, SecureMem<unsigned char> passphrase, string iv, string salt)
{
	byte *decrypted = NULL;
	SecureMem<unsigned char> key;
        
        decrypted = (byte*)malloc(sizeof(byte)*toDecrypt.length());

	key = keyDerivation(passphrase, reinterpret_cast<byte*> (const_cast<char*>(salt.c_str())));

	CFB_Mode<AES>::Decryption cfbDecryption(key.getPointer(), key.getLen(), reinterpret_cast<byte*> (const_cast<char*>(iv.c_str())));
	cfbDecryption.ProcessData(decrypted, reinterpret_cast<const byte*> (toDecrypt.c_str()), toDecrypt.length());
        
        SecureMem<unsigned char> blob(decrypted, toDecrypt.length());
        
        free(decrypted);
        
	return blob;
}

string
CryptoBackend::encryptBlob(SecureMem<unsigned char> toEncrypt, SecureMem<unsigned char> passphrase, string iv, string salt)
{
	byte *encrypted = NULL;
	SecureMem<unsigned char> key;

	key = keyDerivation(passphrase, reinterpret_cast<byte*> (const_cast<char*>(salt.c_str())));
	
	CFB_Mode<AES>::Encryption cfbEncryption(key.getPointer(), key.getLen(), reinterpret_cast<const byte*> (iv.c_str()));
	cfbEncryption.ProcessData(encrypted, toEncrypt.getPointer(), toEncrypt.getLen());

	return string(const_cast<const char*> (reinterpret_cast<char*> (encrypted)));
}