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

#include <protocol/LoginProtocol.h>
#include <utils/KeyFile.h>
#include <utils/Volume.h>
#include <tools/CryptSetup.h>
#include <crypto/CryptoBackend.h>
#include <tpm/TpmBackend.h>

using namespace std;
using namespace crypto;
using namespace tools;
using namespace tpm;
using namespace utils;
using namespace protocol;

/*
 * 1. Unseal monce
 * 2. Show monce
 * 3. Get password
 * 4. Open Blob 1
 * 5. Unseal Blob 2
 * 6. Open Volume
 * 7. Recalculate monce
 * 8. Show monce
 * 9. Seal monce
 * 10. Save volume
 *
 */

LoginProtocol::LoginProtocol ( Volume volume ) {
    /*
    SecureMem<char> dummy;
    CryptSetup tool;
    vector<unsigned> pcrs;

    for ( int i = 0; i < 24; i++ ) {
        pcrs.push_back(i);
    }

    /// Unseal Monce
    SecureMem<char> decrypted = TpmBackend().unseal(volume.encryptedMonce, dummy);

    /// Get Password
    SecureMem<char> password = CryptoBackend().getPassword("Enter password: ");

    /// Open Blob 1
    SecureMem<char> blob1 = CryptoBackend().decryptBlob()

    /// Unseal Blob2
    SecureMem<char> blob2 = TpmBackend().unseal(blob1, dummy);

    /// Open Volume
    tool.openVolume(volume.getDev(), blob2);

    /// Recalculate monce
    string random; // = CryptoBackend().generateRandomString(4, false);
    SecureMem<char> newMonce(const_cast < char* > (random.c_str()), random.length());

    /// Show Monce
    cout << newMonce.getPointer() << endl;

    /// Seal Monce
    std::string encrypted = TpmBackend().seal(newMonce, 0, pcrs, dummy);

    /// Save Volume
    KeyFile file("keyfile.vol");

    file.del(volume.getName());
    file.add(Volume(volume.getName(), volume.getDev(), volume.getKey(), volume.getTool(), encrypted));
    */
}

LoginProtocol::~LoginProtocol ( ) {

}

