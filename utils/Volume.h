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
#include <externals/Base64.h>

namespace utils {

    class Volume {
    public:

        Volume() :
        volumeName(),
        volumeDev(),
        volumeKey(),
        volumeTool(),
        volumeMonce(){

        }

        std::string getVolumeName() {
            return volumeName;
        }

        std::string getDevice() {
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
        std::string isDevice(std::string input) {
            
        }
        
        std::string isAlphaNumeric(std::string input) {
            
        }
        
        std::string volumeName;
        std::string volumeDev;
        std::string volumeKey;
        std::string volumeTool;
        std::string volumeMonce;
    };
}

#endif	/* VOLUME_H */

