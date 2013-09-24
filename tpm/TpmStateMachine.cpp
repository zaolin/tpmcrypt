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
#include <utils/Logging.h>

using namespace tpm;
using namespace utils;

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

		case S6:
		break;

		case S7:
		break;

		case S8:
		break;

		default:
		break;
	}
}

TpmStateMachine::~TpmStateMachine() {

}

void TpmStateMachine::needOwnership() {

}
