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

#ifndef SECURESTRING_H
#define	SECURESTRING_H

#include <iostream>
#include <string.h>
#include <stdlib.h>

namespace crypto {

    template<typename T>
    void clearMem(T* t, size_t len) {
        memset(t, 0, sizeof (T) * len);
    }

    template<typename T>
    class SecureString {
    public:

        SecureString() :
        pointer(NULL),
        pointerLen(0) {
        }

        SecureString(T *t, size_t len) :
        pointer(),
        pointerLen() {
            if (t == NULL || strlen(t) != len) {
                throw 1;
            }

            pointerLen = len;
            pointer = new T[pointerLen];

            memcpy(pointer, t, pointerLen);

            clearMem(t, len);
        }

        SecureString(const SecureString& rhs) :
        pointer(),
        pointerLen() {
            pointer = new T[rhs.pointerLen];
            pointerLen = rhs.pointerLen;

            memcpy(pointer, rhs.pointer, rhs.pointerLen);
        }

        SecureString &operator=(const SecureString& rhs) {
            if (pointer != NULL) {
                clearMem(pointer, pointerLen);
                delete[] pointer;
            }

            pointer = new T[rhs.pointerLen];
            pointerLen = rhs.pointerLen;

            memcpy(pointer, rhs.pointer, rhs.pointerLen);

            return *this;
        }

        ~SecureString() {
            if (pointer != NULL) {
                clearMem(pointer, pointerLen);
                free(pointer);
            }
        }

        T* getValue() {
            pointer[pointerLen] = 0;

            return pointer;
        }

        size_t getLen() {
            return pointerLen;
        }

        bool isEmpty() {
            return (pointer != NULL) && pointerLen > 0 ? false : true;
        }

    private:
        T *pointer;
        size_t pointerLen;

    };
}

#endif	/* SECURESTRING_H */

