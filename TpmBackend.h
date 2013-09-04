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

#ifndef TPMBACKEND_H
#define	TPMBACKEND_H

#include <iostream>
#include <stdexcept>
#include <string>
#include <sstream>
#include <list>
#include <vector>
#include <map>

#include <trousers/tss.h>
#include <trousers/trousers.h>
#include <string.h>

#define TSS_ERROR_CODE(x)       (x & 0xFFF)
#define TSS_ERROR_LAYER(x)      (x & 0x3000)

#define NULL_HOBJECT    0
#define NULL_HKEY       NULL_HOBJECT
#define NULL_HPCRS      NULL_HOBJECT
#define NULL_HHASH      NULL_HOBJECT
#define NULL_HENCDATA   NULL_HOBJECT
#define NULL_HTPM       NULL_HOBJECT
#define NULL_HCONTEXT   NULL_HOBJECT
#define NULL_HDELFAMILY NULL_HOBJECT
#define NULL_HPOLICY    NULL_HOBJECT

namespace tpm {

    class TpmBackendException : public std::runtime_error {
    public:

        TpmBackendException(const std::string& _message) : std::runtime_error(_message) {
        }
    };

    enum TpmGlobalState {
        S1 = 0x6F, /// TPM is ready state.
        S2 = 0x0B,
        S3 = 0x65,
        S4 = 0x01,
        S5 = 0x6E, /// TPM is unowned but ready.
        S6 = 0x0A, /// TPM is cleared. Need reboot
        S7 = 0x64, /// TPM is resetted after clear command.
        S8 = 0x00, /// TPM is completly off.
    };
    
    enum TpmManufactur {
        ATMEL,
        STM,
        INFINEON,
        UNKNOWN,
    };
    
    enum TpmVersion {
        T12,
        T11,
        T10
    };

    class TpmBackend {
    public:

        TpmBackend();
        ~TpmBackend();

        void changeSrkPassword(const char * srkPassword, size_t srkPasswordLen, const char* newPassword, size_t newPasswordLen);
        void changeOwnerPassword(const char * tpmPassword, size_t tpmPasswordLen, const char* newPassword, size_t newPasswordLen);
        void preCalculatePcr();
        std::string sealBackup(const char* toSeal, size_t len, const char *password, size_t passwordLen);
        std::map<unsigned, std::pair<std::string, std::string> > readPcrs();
        unsigned getPcrSize();
        TpmGlobalState getState();
        TpmManufactur getTpmManufactur();
        void clear(const char * tpmPassword, size_t tpmPasswordLen);
        void own(const char * password, size_t passwordLen, const char * srkPassword, size_t srkPasswordLen);
        std::string seal(const char* toSeal, size_t len, int loc, std::vector<unsigned int> pcrs, const char *password, size_t passwordLen);
        char* unseal(const std::string &toUnseal, const char *password, size_t len);
        std::string getRandom(size_t count);

    private:

        enum TpmState {
            Enabled = 0x64,
            Active = 0x0A,
            Owned = 0x01,
            Disabled = 0x00,
            Inactive = 0x00,
            Unowned = 0x00,
        };

        void getEventLog();
        std::string readPcr(size_t num);

        TpmState isEnabled();
        TpmState isActivated();
        TpmState isOwned();

        std::string getException(TSS_RESULT err);

        TSS_HCONTEXT hContext;
        TSS_HTPM hTPM;
        TpmGlobalState tpmState;
        TpmManufactur tpmManufactur;
        unsigned tpmPcrSize;
    };
}


#endif	/* TPMBACKEND_H */

