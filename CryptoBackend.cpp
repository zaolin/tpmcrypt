#include "CryptoBackend.h"
#include <random>
#include <botan/botan.h>
#include <botan/secmem.h>

using namespace std;
using namespace crypto;
using namespace Botan;

const static string KEY_DERIVATION = "PBKDF2(SHA-256)";
const static string ALGORITHM = "AES-256/CBC";

string
CryptoBackend::generateRandomString(size_t count, bool allAscii)
{
	std::random_device rng;
	std::uniform_int_distribution<int> dist(0, 255);
	std::string stringRandom;
	std::stringstream byteRandom;

	while (stringRandom.length() < count) {
		if (byteRandom.eof()) {
			byteRandom.clear();
			byteRandom << (char) dist(rng);
		}

		uint8_t num = byteRandom.get() % 128;

		if (allAscii) {
			if (isgraph(num)) {
				stringRandom += (char) num;
			}
		} else {
			if (isalnum(num)) {
				stringRandom += (char) num;
			}
		}
	}

	return stringRandom;
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