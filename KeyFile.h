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
#include <list>
#include "Volume.h"

namespace tools {

    class KeyFile {
    public:
        KeyFile(std::string file);
        ~KeyFile();

        void add(Volume vol);
        void del(std::string id);
        Volume get(std::string id);
        std::list<Volume> getAll();

    private:
        void parseFile();
        void flushFile();
        std::list<Volume>::iterator searchFile(std::string name);

        std::string keyFilePath;
        std::fstream keyFile;
        std::list<Volume> volumes;
    };
}

#endif	/* KEYFILE_H */

