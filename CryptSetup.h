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

#ifndef CRYPTSETUP_H
#define	CRYPTSETUP_H

#include <iostream>
#include "ToolBackend.h"

namespace tools {
    
    class CryptSetup : public ToolBackend {
    public:
        const static std::string TAG;
        
        ~CryptSetup();
        
        std::string openVolume(std::string dev, std::string password);
        void closeVolume(std::string dev);
        void createVolume(std::string dev, std::string password, 
                    bool force, Cipher c, Mode m,
                    Hash h, KeySize k, Entropy e);
        void changeVolume(std::string dev, std::string password, std::string newPassword);
        
    private:
        std::string getCipher(Cipher c);
        std::string getHash(Hash h);
        std::string getMode(Mode m);
        std::string getKeySize(KeySize k);
        std::string getEntropy(Entropy e);
        bool isTool(std::string dev);
        bool isAvailable();
    };
}


#endif	/* CRYPTSETUP_H */

