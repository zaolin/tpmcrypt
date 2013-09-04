/* 
 *    This file is part of tpmcrypt.
 * 
 *    tpmcrypt is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    tpmcrypt is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with tpmcrypt.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <iostream>
#include <string>
#include <stdio.h>
#include <cstdlib>
#include <fstream>
#include <unistd.h>
#include "CryptoBackend.h"
#include "TpmBackend.h"
#include "CryptSetup.h"
#include "Base64.h"
#include "KeyFile.h"

using namespace std;
using namespace crypto;
using namespace tpm;
using namespace tools;

/*
 * 
 */
int
main(int argc, char** argv)
{
	CryptSetup tool;
	TpmBackend tpm;
	KeyFile key("./foo");
	
	string device(argv[1]);
	string password(argv[2]);
	string rand(generateRandomString(64, false));
	
	vector<unsigned int> pcrs;
	for (int i = 0; i < 24; ++i) {
		pcrs.push_back(i);
	}
	
	string encrypted = tpm.seal(rand.c_str(), rand.length(), 0, pcrs, password.c_str(), password.length());
	tool.createVolume(device, rand, true, AES, XTS, SHA256, S512, URANDOM);
	key.del("usb");
	key.add("usb", device, encrypted, CryptSetup::TAG);
	
	VolumeKey vkey = key.get("usb");
	string decrypted = tpm.unseal(vkey.getKey(), password.c_str(), password.length());
	cout << decrypted << endl;
	tool.openVolume(device, decrypted);
	//tool.changeVolume(string(argv[1]), string(argv[2]), string(argv[3]));
	//tool.openVolume(string(argv[1]), string(argv[2]));
	//tool.closeVolume(string(argv[1]));
	/*
	int i = 0;
	tpm::TpmBackend tpm;
	CryptSetup tool;
	fstream stream;
	string foo;
	char call[255];
	string pw(generateRandomString(64, false));
	cout << pw << endl;
	vector<unsigned int> pcrs;
	for (int i = 0; i < 24; ++i) {
		pcrs.push_back(i);
	}

	string encrypted = tpm.seal(pw.c_str(), pw.length(), 0, pcrs, argv[2], strlen(argv[2]));
	sprintf(call, "cryptsetup -q luksFormat %s", argv[1]);
	FILE *fp = popen(call, "w");
	fwrite(pw.c_str(), sizeof(char), pw.length(), fp);
	pclose(fp);
		
	string decrypted = tpm.unseal(encrypted, argv[2], strlen(argv[2]));
	tool.openVolume(string(argv[1]), decrypted);
	*/
	
	
	//tpm.changeSrkPassword(argv[1], strlen(argv[1]), argv[2], strlen(argv[2]));
	//tpm.preCalculatePcr();

	//tpm.own(argv[1], strlen(argv[1]), argv[2], strlen(argv[2]));
	//pcrs = tpm.readPcrs();


	//for(map<unsigned, pair<string, string> >::iterator it = pcrs.begin(); it != pcrs.end(); ++it) {
	//	cout << it->first << ": 0x" << it->second.first << endl;
	//}
	/*
	vector<unsigned int> pcrs;
	for (int i = 0; i < 24; ++i) {
		pcrs.push_back(i);
	}

	string encrypted = tpm.seal(pw.c_str(), pw.length(), 0, pcrs, argv[1], strlen(argv[1]));
	sprintf(call, "cryptsetup -q luksFormat %s", argv[2]);
	FILE *fp = popen(call, "w");
	fwrite(argv[1], sizeof(char), strlen(argv[1]), fp);
	pclose(fp);
	
	fstream stream;
	string foo;
	
	stream.open("credential", std::ios::in);
	stream >> foo;
	
	string decrypted = tpm.unseal(foo, argv[1], strlen(argv[1]));
	sprintf(call2, "cryptsetup luksOpen %s test", argv[2]);
	FILE *fp = popen(call2, "w");
	fwrite(argv[1], sizeof(char), strlen(argv[1]), fp);
	pclose(fp);
	*/
	//tpm::TpmBackend().own(argv[1], strlen(argv[1]), argv[2], strlen(argv[2]));
	//tpm::TpmBackend().getState();
	//tpm::TpmBackend().clear(argv[1], strlen(argv[1]));
	//vector<unsigned int> pcrs;
	//string test(generateRandomString(127, false));

	//cout << test << endl;
	/*
		for (int i = 0; i < 24; ++i) {
			pcrs.push_back(i);
		}

		string encrypted = tpm::TpmBackend().seal(test.c_str(), test.length() + 1, 0, pcrs, argv[1], strlen(argv[1]));
		char *decrypted = tpm::TpmBackend().unseal(encrypted, argv[1], strlen(argv[1]));

		if (!strcasecmp(decrypted, test.c_str())) {
			cout << decrypted << endl;
		}

		clearMem(decrypted, strlen(decrypted));

		free(decrypted);*/
	return 0;
}

