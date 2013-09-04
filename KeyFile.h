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

#ifndef KEYFILE_H
#define	KEYFILE_H

#include <iostream>
#include <fstream>
#include "VolumeKey.h"

namespace tools {

    class KeyFile {
    public:
        KeyFile(std::string file);
        ~KeyFile();

        void add(std::string name, std::string dev, std::string key, std::string tool);
        void del(std::string name);
        VolumeKey get(std::string name);

    private:
        void parseFile();
        void flushFile();
        std::vector<VolumeKey>::iterator searchFile(std::string name);

        std::string keyFilePath;
        std::fstream keyFile;
        std::vector<VolumeKey> volumeKeys;
    };
}

#endif	/* KEYFILE_H */

