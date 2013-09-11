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

#ifndef TOOLBACKEND_H
#define	TOOLBACKEND_H

#include <iostream>
#include <list>

namespace tools {
    
    enum Cipher {
        AES,
        SERPENT,
        TWOFISH,
        CAST,
        MARS
    };
    
    enum Mode {
        CBC,
        XTS,
        XTS64
    };
    
    enum Hash {
        SHA1,
        SHA256,
        SHA512,
        WHIRLPOOL,
        RIPEMD160
    };
    
    enum KeySize {
        S128,
        S256,
        S384,
        S512
    };
    
    enum Entropy {
        RANDOM,
        URANDOM
    };

    class ToolBackend {
    public:
        ToolBackend();
        virtual ~ToolBackend();
        
        virtual std::string openVolume(std::string dev, std::string password) = 0;
        virtual void closeVolume(std::string dev) = 0;
        virtual void createVolume(std::string dev, 
                            std::string password, bool force, Cipher c, Mode m,
                            Hash h, KeySize k, Entropy e) = 0;
        virtual void changeVolume(std::string dev, std::string password, std::string newPassword) = 0;
        
    protected:
        void call(std::string executable, std::list<std::string> commands, std::list<std::string> toWrite, std::string &toRead, int *ret);
        std::string genUniqueName(std::string dev);
        
    private:
        virtual bool isTool(std::string dev) = 0;
        virtual bool isAvailable() = 0;
        virtual std::string getCipher(Cipher c) = 0;
        virtual std::string getHash(Hash h) = 0;
        virtual std::string getMode(Mode m) = 0;
        virtual std::string getKeySize(KeySize k) = 0;
        virtual std::string getEntropy(Entropy e) = 0;    
    };

}
#endif	/* TOOLBACKEND_H */

