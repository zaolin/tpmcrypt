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

#include <tpm/TpmStateMachine.h>
#include <crypto/CryptoBackend.h>
#include <utils/Logging.h>

#include <unistd.h>
#include <linux/reboot.h>
#include <sys/reboot.h>

using namespace tpm;
using namespace utils;
using namespace crypto;
using namespace std;

TpmStateMachine::TpmStateMachine() :
currentTpmState() {
	switch(currentTpmState = TpmBackend().getState()) {
		case S1: Logging(LOG_INFO, "Tpm State is fine !");
		break;

		case S2:
		break;

		case S3:
		break;

		case S4:
		break;

		case S5: Logging(LOG_INFO, "Tpm is unowned but ready !");
			 needOwnership();
		break;

		case S6: Logging(LOG_INFO, "Tpm is cleared need to reboot !");
			 needReboot();
		break;

		case S7:
		break;

		case S8: Logging(LOG_INFO, "Tpm is disabled, please activate tpm in bios configuration !");
			 
		break;

		default:
		break;
	}
}

TpmStateMachine::~TpmStateMachine() {

}

void TpmStateMachine::needOwnership() {
	TpmBackend tpmConnection;
	SecureMem<char> ownerPassphrase, srkPassphrase;
	
	cout << "Tpm needs to be owned, ownership not set. Will guide you wisely !" << endl;	
	ownerPassphrase = CryptoBackend().getPassword("Please enter a owner passphrase: ");
	tpmConnection.own(ownerPassphrase, srkPassphrase);
	Logging(LOG_INFO, "Owning of tpm successfully !");
}

void TpmStateMachine::needReboot() {
	Logging(LOG_INFO, "Restarting the system !");

	sync();
	reboot(LINUX_REBOOT_CMD_RESTART);
}
