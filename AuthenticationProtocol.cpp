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

#include "AuthenticationProtocol.h"
#include "KeyFile.h"
#include "Volume.h"
#include "CryptSetup.h"
#include "CryptoBackend.h"
#include "TpmBackend.h"

using namespace std;
using namespace crypto;
using namespace tools;
using namespace tpm;

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

AuthenticationProtocol::AuthenticationProtocol ( Volume volume ) {
    SecureString<char> dummy;
    CryptSetup tool;
    vector<unsigned> pcrs;

    for ( int i = 0; i < 24; i++ ) {
        pcrs.push_back(i);
    }

    /// Unseal Monce
    SecureString<char> decrypted = TpmBackend().unseal(volume.getMonce(), dummy);

    /// Show Monce
    cout << decrypted.getValue() << endl;

    /// Get Password
    SecureString<char> password = CryptoBackend().getPassword("Enter password: ");

    /// Open Blob 1
    SecureString<char> blob1 = TpmBackend().unseal(volume.getKey(), dummy);
    string unsecure(const_cast < const char* > (blob1.getValue()), blob1.getLen());
    string decoded(const_cast < const char* > (base64_decode(unsecure.c_str())));

    /// Unseal Blob2
    SecureString<char> blob2 = TpmBackend().unseal(decoded, dummy);

    /// Open Volume
    tool.openVolume(volume.getDev(), blob2);

    /// Recalculate monce
    string random = CryptoBackend().generateRandomString(4, false);
    SecureString<char> newMonce(const_cast < char* > (random.c_str()), random.length());

    /// Show Monce
    cout << newMonce.getValue() << endl;

    /// Seal Monce
    std::string encrypted = TpmBackend().seal(newMonce, 0, pcrs, dummy);

    /// Save Volume
    KeyFile file("keyfile.vol");

    file.del(volume.getName());
    file.add(Volume(volume.getName(), volume.getDev(), volume.getKey(), volume.getTool(), encrypted));
}

AuthenticationProtocol::~AuthenticationProtocol ( ) {

}

