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

#ifndef VOLUME_H
#define	VOLUME_H

#include <iostream>
#include "Base64.h"

namespace tools {

    class Volume {
    public:

        Volume(std::string name, std::string dev, std::string key, std::string tool, std::string monce) :
        volumeName(name),
        volumeDev(dev),
        volumeKey(key),
        volumeTool(tool),
        volumeMonce(monce){

        }

        std::string getName() {
            return volumeName;
        }

        std::string getDev() {
            return volumeDev;
        }

        std::string getKey() {
            return volumeKey;
        }
        
        std::string getKeyBase64() {
            return std::string(const_cast<const char*>(base64_encode(volumeKey.c_str(), volumeKey.length())));
        }
        
        std::string getTool() {
            return volumeTool;
        }
        
        std::string getMonce() {
            return volumeMonce;
        }
    private:
        std::string volumeName;
        std::string volumeDev;
        std::string volumeKey;
        std::string volumeTool;
        std::string volumeMonce;
    };
}

#endif	/* VOLUME_H */

