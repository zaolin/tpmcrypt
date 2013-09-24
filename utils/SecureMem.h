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

#ifndef SECUREMEM_H
#define	SECUREMEM_H

#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <botan/botan.h>
#include <stdexcept>

namespace utils {
    
    class SecureMemException : public std::runtime_error {
    public:

        SecureMemException(const std::string& _message) : std::runtime_error(_message) {
        }
    };

    template<typename T>
    void clearMem(T* t, size_t len) {
        memset(t, 0, sizeof (T) * len);
    }

    template<typename T>
    class SecureMem {
    public:

        SecureMem() :
        pointer(NULL),
        pointerLen(0) {
        }

        SecureMem(T *t, size_t len) :
        pointer(),
        pointerLen() {
            if (t == NULL || len == 0) {
                throw SecureMemException("");
            }

            pointerLen = len;
            pointer = new T[pointerLen];
            
            if(mlock(pointer, pointerLen) < 0) {
                throw SecureMemException("");
            }

            memcpy(pointer, t, pointerLen);

            if(mlock(t, len) < 0) {
                throw SecureMemException("");
            }
            
            clearMem(t, len);
            munlock(t, len);
        }

        SecureMem(const SecureMem& rhs) :
        pointer(),
        pointerLen() {
            pointer = new T[rhs.pointerLen];
            pointerLen = rhs.pointerLen;
            
            if(mlock(pointer, pointerLen) < 0) {
                throw SecureMemException("");
            }

            memcpy(pointer, rhs.pointer, rhs.pointerLen);
        }

        SecureMem &operator=(const SecureMem& rhs) {
            if (pointer != NULL) {
                clearMem(pointer, pointerLen);
                munlock(pointer, pointerLen);
                delete[] pointer;
            }

            pointer = new T[rhs.pointerLen];
            pointerLen = rhs.pointerLen;
            
            if(mlock(pointer, pointerLen) < 0) {
                throw SecureMemException("");
            }

            memcpy(pointer, rhs.pointer, rhs.pointerLen);

            return *this;
        }

        ~SecureMem() {
            if (pointer != NULL) {
                clearMem(pointer, pointerLen);
                munlock(pointer, pointerLen);
                delete[] pointer;
            }
        }

        T* getPointer() {
            pointer[pointerLen] = 0;

            return pointer;
        }

        size_t getLen() {
            return pointerLen;
        }
        
        std::string getAsUnsecureString() {
            return std::string(const_cast<const char*>(reinterpret_cast<char*>(pointer)), pointerLen);
        }

        bool isEmpty() {
            return (pointer != NULL) && pointerLen > 0 ? false : true;
        }

    private:
        T *pointer;
        size_t pointerLen;
    };
}

#endif	/* SECUREMEM_H */

