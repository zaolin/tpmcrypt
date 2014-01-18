h/*
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

#include <utils/SecureMem.h>

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

/*
 * TPM Implementation supports ATMEL, INFINEON and STM chips version <= 1.2
 * which are built-in thinkpad and hellwet packard notebooks.
 */

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
        S8 = 0x00 /// TPM is completly off.
    };

    enum TpmManufactur {
        ATMEL,
        STM,
        INFINEON,
        UNKNOWN
    };

    enum TpmVersion {
        T12,
        T11,
        T10
    };
    
    static struct {
        unsigned pcr;
        std::string description;
    } PlatformConfigurationRegisters[] = {
        { 0, "S-CRTM and POST data" },
        { 1, "POST BIOS, NVRAM, CMOS, SMBIOS and Platform Config flags data" },
        { 2, "Option ROM data" },
        { 3, "Option ROM configuration data" },
        { 4, "IPL, Boot Device Used, Calling INT and MBR data" },
        { 5, "IPL Configuration data" },
        { 6, "State Transitions and Wake events data" },
        { 7, "Host Platform Manufactur data" },
        { 8, "Trusted Grub Legacy Stage 1.5 data" },
        { 9, "Trusted Grub Legacy Stage 2 data" },
        { 10, "Integrity Measurement Architecture data" },
        { 11, "Reserved" },
        { 12, "Trusted Grub Legacy menu.lst data" },
        { 13, "Trusted Grub Legacy checkfile data" },
        { 14, "Trusted Grub Linux Kernel and Initramfs data" },
        { 15, "Reserved" },
        { 16, "Debug" },
        { 17, "Intel TXT (DRTM: LCP Policy, BIOS ACM, STM, MLE, S-CRTM state data)" },
        { 18, "Intel TXT (DRTM: ACM pubkey and LCP Hash data)" },
        { 19, "Intel TXT (TBOOT: LCP and grub modules data)" },
        { 20, "Intel TXT Reserved" },
        { 21, "Intel TXT Reserved" },
        { 22, "Intel TXT Reserved" },
        { 23, "Debug" },
    };

    class TpmBackend {
    public:

        TpmBackend();
        ~TpmBackend();

        void changeSrkPassword(utils::SecureMem<char> srkPasswordOld, utils::SecureMem<char> srkPasswordNew);
        void changeOwnerPassword(utils::SecureMem<char> ownerPasswordOld, utils::SecureMem<char> ownerPasswordNew);
        void preCalculatePcr();
        std::string sealBackup(utils::SecureMem<char> toSeal, utils::SecureMem<char> password);
        std::map<unsigned, std::pair<std::string, std::string> > readPcrs();
        unsigned getPcrSize();
        TpmGlobalState getState();
        TpmManufactur getTpmManufactur();
        void clear(utils::SecureMem<char> ownerPassword);
        void own(utils::SecureMem<char> ownerPassword, utils::SecureMem<char> srkPassword);
        std::string seal(utils::SecureMem<char> toSeal, int loc, std::vector<unsigned int> pcrs, utils::SecureMem<char> password);
        utils::SecureMem<char> unseal(const std::string &toUnseal, utils::SecureMem<char> password);
        utils::SecureMem<char> getRandom(size_t count);

    private:

        enum TpmState {
            Enabled = 0x64,
            Active = 0x0A,
            Owned = 0x01,
            Disabled = 0x00,
            Inactive = 0x00,
            Unowned = 0x00
        };

        void getEventLog();
        std::string readPcr(size_t num);

        TpmState isEnabled();
        TpmState isActivated();
        TpmState isOwned();

        std::string getException(TSS_RESULT err);

        TSS_HCONTEXT    hContext;
        TSS_HTPM        hTPM;
        TpmGlobalState  tpmState;
        TpmManufactur   tpmManufactur;
        TpmVersion      tpmVersion
        unsigned        tpmPcrSize;
    };
}


#endif	/* TPMBACKEND_H */

