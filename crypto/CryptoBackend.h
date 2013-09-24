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
#include <unistd.h>
#include <sstream>

#include <utils/SecureMem.h>

namespace crypto {

    class CryptoBackend {
    public:
        utils::SecureMem<char>
        getPassword(const char *promt);

        std::string
        generateRandomString(size_t count, bool allAscii);
    };
}
#endif
