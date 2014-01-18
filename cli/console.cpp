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
#include <protocol/AuthenticationProtocol.h>
#include <utils/KeyFile.h>
#include <tools/CryptSetup.h>
#include <tpm/TpmBackend.h>
#include <tpm/TpmStateMachine.h>
#include <crypto/CryptoBackend.h>
#include <utils/CommandLine.h>
#include <management/VolumeManagement.h>

using namespace management;
using namespace std;
using namespace crypto;
using namespace tools;
using namespace tpm;
using namespace utils;
using namespace protocol;

void foo()
{
	cout << "blah" << endl;
}

int
main(int argc, char** argv)
{
	TpmBackend tpm;
	std::map<unsigned, std::pair<std::string, std::string> > foo;
	foo = tpm.readPcrs();

	for(std::map<unsigned, std::pair<std::string, std::string> >::iterator it = foo.begin(); it != foo.end(); ++it) {
		cout << it->first << "\t" << it->second.first << "\t" << it->second.second << endl;
	}

	//KeyFile keyFile("keyfile.vol");
	//Volume volume("foo", "/dev/loop0", "blah", CryptSetup::TAG, "foo");
        //keyFile.add(volume);
	
	/*unsigned char tmp[] = "foo";
	TpmStateMachine tpmState;
        
        SecureMem<unsigned char> password(tmp, 4);
        SecureMem<unsigned char> toEncrypt(tmp, 4);
        
        vector<string> data = CryptoBackend().initBlob(toEncrypt, password);
        SecureMem<unsigned char> foo = CryptoBackend().decryptBlob(data.at(0), password, data.at(1), data.at(2));
        
        cout << "encrypted" << data.at(0) << endl;
        cout << "iv" << data.at(1) << endl;
        cout << "salt" << data.at(2) << endl;
        cout << "unecrypted" << foo.getAsUnsecureString() << endl;
	*/
	//CommandLine cmdParser;
	//TpmStateMachine tpmState;

	//cmdParser.registerOptionClass<VolumeManagement > ("foooooooooooooooooooooo", "help", CommandLine::NONE);
	//cmdParser.registerOptionClass<VolumeManagement > ("xxxxxxxxxxxxxxxxw sadsadsa", "blah", CommandLine::NONE);
	//cmdParser.registerOptionFunction(foo, "ajdssfaf", "foo");

	//cmdParser.run(argc, argv);
	/*
	    CryptSetup tool;
	    KeyFile file("keyfile.vol");
	    vector<unsigned> pcrs;
	    string pw = CryptoBackend().generateRandomString(64, false);
	    string monce = CryptoBackend().generateRandomString(64, false);
	    SecureMem<char> secpw(const_cast < char* > (pw.c_str()), pw.length());
	    SecureMem<char> secmonce(const_cast < char* > (monce.c_str()), monce.length());
	    SecureMem<char> dummy;

	    for ( int i = 0; i < 24; i++ ) {
		pcrs.push_back(i);
	    }

	    SecureMem<char> password = CryptoBackend().getPassword("Enter password: ");

	    string encrypted1 = TpmBackend().seal(secpw, 0, pcrs, dummy);
	    string encrypted2 = TpmBackend().seal(secmonce, 0, pcrs, dummy);

	    Volume vol("foo", "/dev/loop0", encrypted1, CryptSetup::TAG, encrypted2);

	    file.add(vol);

	    tool.createVolume("/dev/loop0", secpw, true, AES, CBC, SHA1, S256, RANDOM);
	    AuthenticationProtocol foo(vol);
	 */
	//SecureMem<char> foo = CryptoBackend().generateRandomString(64, false); 
	//cout << foo.getAsUnsecureString() << endl;
	//TpmStateMachine();
	return 0;
}

