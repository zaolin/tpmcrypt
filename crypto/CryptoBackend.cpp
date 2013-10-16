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

const static unsigned DEFAULT_SALT_LEN = 16;
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

/*
byte*
CryptoBackend::generateSalt()
{
	AutoSeededRandomPool rnd;
	byte *salt = (byte*) malloc(DEFAULT_SALT_LEN * sizeof(byte));

	if (salt == NULL) {

	}

	rnd.GenerateBlock(salt, DEFAULT_SALT_LEN);

	return salt;
}

byte*
CryptoBackend::generateIV()
{
	AutoSeededRandomPool rnd;
	byte *iv = (byte*) malloc(AES::BLOCKSIZE * sizeof(byte));

	if (iv == NULL) {

	}

	rnd.GenerateBlock(iv, AES::BLOCKSIZE);

	return iv;
}

SecureMem<unsigned char>
CryptoBackend::keyDerivation(SecureMem<unsigned char> passphrase, byte *salt)
{
	PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
	byte key[AES::DEFAULT_KEYLENGTH];
	unsigned result = 0;

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

	}

	return SecureMem<unsigned char>(key, AES::DEFAULT_KEYLENGTH);
}

vector<string>
CryptoBackend::initBlob(SecureMem<char> toEncrypt, SecureMem<char> passphrase)
{
	byte* iv, salt, encrypted;
	vector<string> cryptoParams;
	SecureMem<unsigned char> key;

	iv = generateIV();
	salt = generateSalt();

	key = keyDerivation(passphrase, salt);

	CFB_Mode<AES>::Encryption cfbEncryption(key.getPointer(), key.getLen(), iv);
	cfbEncryption.ProcessData(encrypted, toEncrypt.getPointer(), toEncrypt.getLen());

	cryptoParams.push_back(string(const_cast<const char*> (reinterpret_cast<char*> (encrypted))));
	cryptoParams.push_back(string(const_cast<const char*> (reinterpret_cast<char*> (iv))));
	cryptoParams.push_back(string(const_cast<const char*> (reinterpret_cast<char*> (salt))));

	return cryptoParams;
}

SecureMem<unsigned char>
CryptoBackend::decryptBlob(string toDecrypt, SecureMem<char> passphrase, string iv, string salt)
{
	byte *decrypted;
	SecureMem<unsigned char> key;

	key = keyDerivation(passphrase, salt);

	CFB_Mode<AES>::Decryption cfbDecryption(key.getPointer(), key.getLen(), iv);
	cfbDecryption.ProcessData(decrypted, static_cast<byte*> (toDecrypt.c_str()), toDecrypt.length());

	return SecureMem<unsigned char>(decrypted, toDecrypt.length());
}

string
CryptoBackend::encryptBlob(SecureMem<unsigned char> toEncrypt, SecureMem<char> passphrase, string iv, string salt)
{
	byte *encrypted;
	SecureMem<unsigned char> key;

	key = keyDerivation(passphrase, salt);
	
	CFB_Mode<AES>::Encryption cfbEncryption(key.getPointer(), key.getLen(), iv);
	cfbEncryption.ProcessData(encrypted, toEncrypt.getPointer(), toEncrypt.getLen());

	return string(const_cast<const char*> (reinterpret_cast<char*> (encrypted)));
}
 */
/*
std::string encrypt(SecureMem<char> password, 
		    SecureMem<char> salt, 
		    SecureMem<char> iv, 
		    unsigned iterations, 
		    SecureMem<char> toEncrypt)
{
	PBKDF* pbkdf = NULL;
	OctetString aesKey;
	InitializationVector initialisation_vector(iv);
	
	pbkdf = get_pbkdf(KEY_DERIVATION);
	aesKey = pbkdf->derive_key(32, password.getString(), &salt[0], salt.size(), iterations);
	SymmetricKey key(aesKey.as_string());
        
	Pipe pipe(get_cipher(ALGORITHM, key, iv, ENCRYPTION));
	pipe.process_msg(toEncrypt);
	return pipe.read_all_as_string();
}

SecureMem<char> decrypt()
{
	PBKDF* pbkdf = get_pbkdf(KEY_DERIVATION);
	AutoSeeded_RNG rng;
	AutoSeeded_RNG rng2;
	secure_vector<byte> salt = rng.random_vec(16);
	OctetString aes256_key = pbkdf->derive_key(32, "password", &salt[0], salt.size(), 10000);
	SymmetricKey key(aes256_key.as_string()); // a random 128-bit key         
	InitializationVector iv(rng2, 16); // a random 128-bit IV          
	Pipe pipe(get_cipher(ALGORITHM, key, iv, DECRYPTION));
	pipe.process_msg("secrets");
	return pipe.read_all_as_string();
}
 */
