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


}

AuthenticationProtocol::~AuthenticationProtocol ( ) {

}

