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

#ifndef CRYPTOBACKEND_H
#define	CRYPTOBACKEND_H

#include <iostream>
#include <string.h>
#include <stdexcept>
#include "TpmBackend.h"


namespace crypto {

    template<typename T>
    void clearMem(T* t, size_t len) {
        memset(t, 0, sizeof (T) * len);
    }

    std::string
    generateRandomString(size_t count, bool allAscii) {
        std::string stringRandom;
        std::stringstream byteRandom;

        while (stringRandom.length() < count) {
            if (byteRandom.eof()) {
                byteRandom.clear();
                byteRandom << tpm::TpmBackend().getRandom(count);
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
}
#endif