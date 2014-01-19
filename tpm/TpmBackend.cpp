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

#include <tpm/TpmBackend.h>
#include <iomanip>

using namespace std;
using namespace tpm;
using namespace utils;

TpmBackend::TpmBackend ( ) :
hContext ( ),
hTPM ( ),
tpmState ( ),
tpmManufactur ( ),
tpmPcrSize ( ) {
    TSS_RESULT err;

    try {
        err = Tspi_Context_Create(&hContext);
        if ( err != TSS_SUCCESS )
            throw TpmBackendException("TPM Error: " + getException(err));

        err = Tspi_Context_Connect(hContext, NULL);
        if ( err != TSS_SUCCESS )
            throw TpmBackendException("TPM Error: " + getException(err));

        err = Tspi_Context_GetTpmObject(hContext, &hTPM);
        if ( err != TSS_SUCCESS )
            throw TpmBackendException("TPM Error: " + getException(err));

        tpmState        = this->getState();
        tpmManufactur   = this->getTpmManufactur();
        tpmPcrSize      = this->getPcrSize();
        tpmVersion      = this->getVersion();
    } catch ( TpmBackendException &e ) {
        if ( hContext )
            Tspi_Context_FreeMemory(hContext, NULL);

        Tspi_Context_Close(hContext);
    }

}

TpmBackend::~TpmBackend ( ) {
    if ( hContext )
        Tspi_Context_FreeMemory(hContext, NULL);

    Tspi_Context_Close(hContext);
}

/*
vector<string> TpmBackend::quoteNow( SecureMem<char> srkPassword, string aik ) {

    TSS_RESULT err;
    TSS_HPCRS hPCR;
    TSS_HKEY hKey;
    TSS_HPOLICY hSrkPolicy;
    TSS_HPOLICY hPolicy;
    TSS_VALIDATION hValid;
    UINT32 pcrvaluelength;
    BYTE *pcrvalue;
    UINT32 *versionInfoLen;
    BYTE *versionInfo;
    UINT32 aikLen;
    BYTE* aikBlob;
    vector<string> quote;
    TPM_QUOTE_INFO *quoteInfo;
    TPM_QUOTE_INFO2 *quote2Info;
    
    aikLen = aik.length();
    aikBlob = reinterpret_cast < BYTE* > (aik.c_str());

    hValid.ulExternalDataLength = srkPassword.isEmpty() ? TPM_SHA1_160_HASH_LEN : srkPassword.getLen()
    hValid.rgbExternalData = srkPassword.isEmpty() ? well_known_secret : reinterpret_cast < BYTE* > (srkPassword.getPointer());

    err = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
    if ( err != TSS_SUCCESS ) {
        throw TpmBackendException("TPM Error: " + getException(err));
    }

    err = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSrkPolicy);
    if ( err != TSS_SUCCESS ) {
        throw TpmBackendException("TPM Error: " + getException(err));
    }

    err = Tspi_Policy_SetSecret(hSrkPolicy, srkPassword.isEmpty() ? TSS_SECRET_MODE_SHA1 : TSS_SECRET_MODE_PLAIN, srkPassword.isEmpty() ? TPM_SHA1_160_HASH_LEN : srkPassword.getLen(), srkPassword.isEmpty() ? well_known_secret : reinterpret_cast < BYTE* > (srkPassword.getPointer()));
    if ( err != TSS_SUCCESS ) {
        throw TpmBackendException("TPM Error: " + getException(err));
    }

    err = Tspi_Context_LoadKeyByBlob(hContext, hSRK, aikLen, aikBlob, &hKey);
    if ( err != TSS_SUCCESS ) {
        throw TpmBackendException("TPM Error: " + getException(err));
    }

    err = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_PCRS, TSS_PCRS_STRUCT_INFO_SHORT, &hPCR);
    if ( err != TSS_SUCCESS ) {
        throw TpmBackendException("TPM Error: " + getException(err));
    }

    err = Tspi_PcrComposite_SetPcrLocality(hPCR, TPM_LOC_ZERO);
    if ( err != TSS_SUCCESS ) {
        Tspi_Context_CloseObject(hContext, hEncData);
        throw TpmBackendException("TPM Error: " + getException(err));
    }

    for ( int i = 0; i < 24; ++i ) {
        err = Tspi_TPM_PcrRead(hTPM, i, &pcrvaluelength, &pcrvalue);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_PcrComposite_SetPcrValue(hPCR, i, pcrvaluelength, pcrvalue);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        pcrvaluelength = 0;
        pcrvalue = NULL;
    }

    err = Tspo_TPM_Quote2(hTPM, hKey, FALSE, &hPCR, &hValid, 0, NULL);
    if ( err != TSS_SUCCESS ) {
        throw TpmBackendException("TPM Error: " + getException(err));
    }

    if(  ) {
        quote2Info = (TPM_QUOTE_INFO2*) hValid.rgbData;
    } else if( atoi(tpmVersion->version.bMajor) == 1 && atoi(tpmVersion->version.bMinor) < 2 ) {
        quoteInfo = (TPM_QUOTE_INFO*) hValid.rgbData;
    }

    try {
        err = Tspi_Policy_FlushSecret(hPolicy);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_Policy_FlushSecret(hSrkPolicy);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }
    } catch ( exception &e ) {

    }
    
}
*/

void TpmBackend::preCalculatePcr ( ) {

}

string TpmBackend::sealBackup ( SecureMem<char> toSeal, SecureMem<char> password ) {
    string emptyPcr = "0000000000000000000000000000000000000000";
    try {
        for ( int i = 23; i > 20; i-- ) {
            if ( this->readPcr(i) == emptyPcr ) {
                return this->seal(toSeal, 0, vector<unsigned int>(i), password);
            }
        }
    } catch ( exception &e ) {

    }

    return string();
}

string TpmBackend::readPcr ( size_t num ) {
    TSS_RESULT err;
    UINT32 pcrValLen;
    BYTE* pcrVal;
    stringstream ss;

    try {
        err = Tspi_TPM_PcrRead(hTPM, num, &pcrValLen, &pcrVal);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        for ( unsigned int j = 0; j < pcrValLen; j++ ) {
            ss << hex << setw(2) << setfill('0') << static_cast < const unsigned int > (pcrVal[j]);
        }
    } catch ( exception &e ) {

    }

    return ss.str();
}

map<unsigned, pair<string, string> > TpmBackend::readPcrs ( ) {
    map<unsigned, pair<string, string> > pcrs;

    for ( unsigned i = 0; i < tpmPcrSize; i++ ) {
        pcrs.insert(make_pair(i, make_pair(this->readPcr(i), PlatformConfigurationRegisters[i].description)));
    }

    return pcrs;
}

TpmBackend::TpmState TpmBackend::isOwned ( ) {
    TSS_RESULT err;
    BYTE *owner;
    UINT32 len;
    UINT32 subCap = TSS_TPMCAP_PROP_OWNER;

    err = Tspi_TPM_GetCapability(hTPM, TSS_TPMCAP_PROPERTY, sizeof (UINT32), (BYTE*) & subCap, &len, &owner);
    if ( err != TSS_SUCCESS )
        throw TpmBackendException("TPM Error: " + getException(err));

    if ( *owner == true )
        return Owned;

    return Unowned;
}

TpmBackend::TpmState TpmBackend::isActivated ( ) {
    TSS_RESULT err;
    UINT32 pcrValLen;
    BYTE* pcrVal;
    ;

    err = Tspi_TPM_PcrRead(hTPM, 0, &pcrValLen, &pcrVal);
    if ( err != TSS_SUCCESS ) {
        if ( TSS_ERROR_CODE(err) == TPM_E_DEACTIVATED ) {
            return Inactive;
        }
    }

    return Active;
}

TpmBackend::TpmState TpmBackend::isEnabled ( ) {
    TSS_RESULT err;
    UINT32 pcrValLen;
    BYTE* pcrVal;

    err = Tspi_TPM_PcrRead(hTPM, 0, &pcrValLen, &pcrVal);
    if ( err != TSS_SUCCESS ) {
        if ( TSS_ERROR_CODE(err) == TPM_E_DISABLED ) {
            return Disabled;
        }
    }

    return Enabled;
}

TpmGlobalState TpmBackend::getState ( ) {
    return static_cast < TpmGlobalState > (
            static_cast < int > (isEnabled()) |
            static_cast < int > (isActivated()) |
            static_cast < int > (isOwned()));
}

unsigned TpmBackend::getPcrSize ( ) {
    TSS_RESULT err;
    UINT32 capLen;
    BYTE *capData;
    UINT32 subCap = TSS_TPMCAP_PROP_PCR;

    err = Tspi_TPM_GetCapability(hTPM, TSS_TPMCAP_PROPERTY, sizeof (UINT32), (BYTE*) & subCap, &capLen, &capData);
    if ( err != TSS_SUCCESS ) {
        throw TpmBackendException("TPM Error: " + getException(err));
    }

    return *( int* ) capData;
}

TpmVersion TpmBackend::getVersion() {
    

    
    return 
}

TpmManufactur TpmBackend::getTpmManufactur ( ) {
    TSS_RESULT err;
    UINT32 capLen;
    BYTE *capData;
    UINT32 subCap = TSS_TPMCAP_PROP_MANUFACTURER;

    err = Tspi_TPM_GetCapability(hTPM, TSS_TPMCAP_PROPERTY, sizeof (UINT32), (BYTE*) & subCap, &capLen, &capData);
    if ( err != TSS_SUCCESS ) {
        throw TpmBackendException("TPM Error: " + getException(err));
    }

    string tmp(( const char* ) capData, capLen - 1);

    if ( tmp == "ATML" ) {
        return ATMEL;
    } else if ( tmp == "STM" ) {
        return STM;
    } else if ( tmp == "IFX" ) {
        return INFINEON;
    } else {
        return UNKNOWN;
    }
}

void TpmBackend::changeOwnerPassword ( SecureMem<char> ownerPasswordOld, SecureMem<char> ownerPasswordNew ) {
    TSS_RESULT err;
    TSS_HPOLICY hTpmPolicy;
    TSS_HPOLICY hNewPolicy;

    if ( !this->isOwned() ) {
        throw TpmBackendException("TPM is not owned!");
    }

    try {
        err = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hTpmPolicy);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hNewPolicy);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_Policy_SetSecret(hTpmPolicy, TSS_SECRET_MODE_PLAIN, ownerPasswordOld.getLen(), reinterpret_cast < BYTE* > (ownerPasswordOld.getPointer()));
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_Policy_SetSecret(hNewPolicy, TSS_SECRET_MODE_PLAIN, ownerPasswordNew.getLen(), reinterpret_cast < BYTE* > (ownerPasswordNew.getPointer()));
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_ChangeAuth(hTPM, NULL_HOBJECT, hNewPolicy);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }
    } catch ( exception &e ) {

    }

    try {
        err = Tspi_Policy_FlushSecret(hTpmPolicy);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_Policy_FlushSecret(hNewPolicy);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }
    } catch ( exception &e ) {

    }
}

void TpmBackend::changeSrkPassword ( SecureMem<char> srkPasswordOld, SecureMem<char> srkPasswordNew ) {
    TSS_RESULT err;
    TSS_HKEY hSRK;
    TSS_HPOLICY hTpmPolicy;
    TSS_HPOLICY hNewPolicy;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    BYTE well_known_secret[TPM_SHA1_160_HASH_LEN] = TSS_WELL_KNOWN_SECRET;

    if ( !this->isOwned() ) {
        throw TpmBackendException("TPM is not owned!");
    }
    try {
        err = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hTpmPolicy);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hNewPolicy);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_Policy_SetSecret(hTpmPolicy, srkPasswordOld.isEmpty() ? TSS_SECRET_MODE_SHA1 : TSS_SECRET_MODE_PLAIN, srkPasswordOld.isEmpty() ? TPM_SHA1_160_HASH_LEN : srkPasswordOld.getLen(), srkPasswordOld.isEmpty() ? well_known_secret : reinterpret_cast < BYTE* > (srkPasswordOld.getPointer()));
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_Policy_SetSecret(hNewPolicy, srkPasswordNew.isEmpty() ? TSS_SECRET_MODE_SHA1 : TSS_SECRET_MODE_PLAIN, srkPasswordNew.isEmpty() ? TPM_SHA1_160_HASH_LEN : srkPasswordNew.getLen(), srkPasswordNew.isEmpty() ? well_known_secret : reinterpret_cast < BYTE* > (srkPasswordNew.getPointer()));
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_ChangeAuth(hSRK, hTPM, hNewPolicy);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }
    } catch ( exception &e ) {

    }

    try {
        err = Tspi_Policy_FlushSecret(hTpmPolicy);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_Policy_FlushSecret(hNewPolicy);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }
    } catch ( exception &e ) {

    }
}

void TpmBackend::clear ( SecureMem<char> ownerPassword ) {
    TSS_RESULT err;
    TSS_RESULT err2;
    TSS_HPOLICY hTpmPolicy;

    if ( !this->isOwned() ) {
        throw TpmBackendException("TPM is not owned!");
    }

    try {
        err = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hTpmPolicy);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_Policy_SetSecret(hTpmPolicy, TSS_SECRET_MODE_PLAIN, ownerPassword.getLen(), reinterpret_cast < BYTE* > (ownerPassword.getPointer()));
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_TPM_ClearOwner(hTPM, FALSE);
        if ( err != TSS_SUCCESS ) {
            err = Tspi_TPM_ClearOwner(hTPM, TRUE);
            if ( err != TSS_SUCCESS ) {
                if ( tpmManufactur == ATMEL && (TSS_ERROR_CODE(err) == TPM_E_DISABLED ||
                        TSS_ERROR_CODE(err) == TPM_E_DEACTIVATED) ) {
                    err2 = Tspi_Policy_FlushSecret(hTpmPolicy);
                    if ( err2 != TSS_SUCCESS ) {
                        throw TpmBackendException("TPM Error: " + getException(err2));
                    }

                    return;
                } else {
                    err2 = Tspi_Policy_FlushSecret(hTpmPolicy);
                    if ( err2 != TSS_SUCCESS ) {
                        throw TpmBackendException("TPM Error: " + getException(err2));
                    }

                    throw TpmBackendException("TPM Error: " + getException(err));
                }
            }
        }

        err2 = Tspi_Policy_FlushSecret(hTpmPolicy);
        if ( err2 != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err2));
        }
    } catch ( exception &e ) {

    }
}

void TpmBackend::own ( SecureMem<char> ownerPassword, SecureMem<char> srkPassword ) {
    TSS_RESULT err;
    TSS_HKEY hSRK;
    TSS_HPOLICY hSrkPolicy;
    TSS_HPOLICY hTpmPolicy;
    BYTE well_known_secret[TPM_SHA1_160_HASH_LEN] = TSS_WELL_KNOWN_SECRET;

    if ( this->isOwned() ) {
        throw TpmBackendException("TPM already owned!");
    }

    try {
        err = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
                                        TSS_KEY_TSP_SRK | TSS_KEY_AUTHORIZATION,
                                        &hSRK);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSrkPolicy);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hTpmPolicy);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_Policy_SetSecret(hSrkPolicy, srkPassword.isEmpty() ? TSS_SECRET_MODE_SHA1 : TSS_SECRET_MODE_PLAIN, srkPassword.isEmpty() ? TPM_SHA1_160_HASH_LEN : srkPassword.getLen(), srkPassword.isEmpty() ? well_known_secret : reinterpret_cast < BYTE* > (srkPassword.getPointer()));
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_Policy_SetSecret(hTpmPolicy, TSS_SECRET_MODE_PLAIN, ownerPassword.getLen(), reinterpret_cast < BYTE* > (ownerPassword.getPointer()));
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_TPM_TakeOwnership(hTPM, hSRK, NULL_HKEY);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }
    } catch ( exception &e ) {

    }

    try {
        err = Tspi_Policy_FlushSecret(hTpmPolicy);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_Policy_FlushSecret(hSrkPolicy);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }
    } catch ( exception &e ) {

    }
}

string TpmBackend::seal ( SecureMem<char> toSeal, int loc, std::vector<unsigned int> pcrs, SecureMem<char> password ) {
    TSS_HKEY hSRK;
    TSS_HENCDATA hEncData;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    TSS_HPCRS hPCR;
    TSS_HPOLICY hPolicy;
    UINT32 encLen;
    UINT32 pcrvaluelength;
    UINT32 locality;
    BYTE *pcrvalue;
    BYTE *encData;
    TSS_RESULT err;
    BYTE well_known_secret[TPM_SHA1_160_HASH_LEN] = TSS_WELL_KNOWN_SECRET;
    string encryptedData;

    if ( !this->isOwned() ) {
        throw TpmBackendException("TPM is not owned!");
    }
    try {
        err = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_ENCDATA, TSS_ENCDATA_SEAL, &hEncData);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
        if ( err != TSS_SUCCESS ) {
            Tspi_Context_CloseObject(hContext, hEncData);
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hPolicy);
        if ( err != TSS_SUCCESS ) {
            Tspi_Context_CloseObject(hContext, hEncData);
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_Policy_SetSecret(hPolicy, password.isEmpty() ? TSS_SECRET_MODE_SHA1 : TSS_SECRET_MODE_PLAIN, password.isEmpty() ? TPM_SHA1_160_HASH_LEN : password.getLen(), password.isEmpty() ? well_known_secret : reinterpret_cast < BYTE* > (password.getPointer()));
        if ( err != TSS_SUCCESS ) {
            Tspi_Context_CloseObject(hContext, hEncData);
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_PCRS, TSS_PCRS_STRUCT_INFO_LONG, &hPCR);
        if ( err != TSS_SUCCESS ) {
            Tspi_Context_CloseObject(hContext, hEncData);
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        switch ( loc ) {
            default:
                locality = TPM_LOC_ZERO;
                break;
            case 1:
                locality = TPM_LOC_ONE;
                break;
            case 2:
                locality = TPM_LOC_TWO;
                break;
            case 3:
                locality = TPM_LOC_THREE;
                break;
            case 4:
                locality = TPM_LOC_FOUR;
                break;
        }

        err = Tspi_PcrComposite_SetPcrLocality(hPCR, locality);
        if ( err != TSS_SUCCESS ) {
            Tspi_Context_CloseObject(hContext, hEncData);
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        for ( vector<unsigned int>::const_iterator it = pcrs.begin(); it != pcrs.end(); ++it ) {
            err = Tspi_TPM_PcrRead(hTPM, *it, &pcrvaluelength, &pcrvalue);
            if ( err != TSS_SUCCESS ) {
                Tspi_Context_CloseObject(hContext, hEncData);
                throw TpmBackendException("TPM Error: " + getException(err));
            }

            err = Tspi_PcrComposite_SetPcrValue(hPCR, *it, pcrvaluelength, pcrvalue);
            if ( err != TSS_SUCCESS ) {
                Tspi_Context_CloseObject(hContext, hEncData);
                throw TpmBackendException("TPM Error: " + getException(err));
            }

            pcrvaluelength = 0;
            pcrvalue = NULL;
        }

        err = Tspi_Data_Seal(hEncData, hSRK, toSeal.getLen(), reinterpret_cast < BYTE* > (toSeal.getPointer()), hPCR);
        if ( err != TSS_SUCCESS ) {
            Tspi_Context_CloseObject(hContext, hEncData);
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_GetAttribData(hEncData, TSS_TSPATTRIB_ENCDATA_BLOB, TSS_TSPATTRIB_ENCDATABLOB_BLOB, &encLen, &encData);
        if ( err != TSS_SUCCESS ) {
            Tspi_Context_CloseObject(hContext, hEncData);
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        encryptedData = string(const_cast < const char* > (reinterpret_cast < char* > (encData)), encLen);
        Tspi_Context_CloseObject(hContext, hEncData);
    } catch ( exception &e ) {

    }

    try {
        err = Tspi_Policy_FlushSecret(hPolicy);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }
    } catch ( exception &e ) {

    }

    return encryptedData;
}

SecureMem<char> TpmBackend::unseal ( const std::string &toUnseal, SecureMem<char> password ) {
    TSS_HKEY hSRK;
    TSS_HENCDATA hEncData;
    TSS_HPOLICY hPolicy;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    BYTE *plainData;
    UINT32 plainLen;
    TSS_RESULT err;
    BYTE well_known_secret[TPM_SHA1_160_HASH_LEN] = TSS_WELL_KNOWN_SECRET;

    if ( !this->isOwned() ) {
        throw TpmBackendException("TPM is not owned!");
    }
    try {
        err = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_ENCDATA, TSS_ENCDATA_SEAL, &hEncData);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_SetAttribData(hEncData, TSS_TSPATTRIB_ENCDATA_BLOB, TSS_TSPATTRIB_ENCDATABLOB_BLOB, toUnseal.length(), ( BYTE* ) toUnseal.c_str());
        if ( err != TSS_SUCCESS ) {
            Tspi_Context_CloseObject(hContext, hEncData);
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
        if ( err != TSS_SUCCESS ) {
            Tspi_Context_CloseObject(hContext, hEncData);
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hPolicy);
        if ( err != TSS_SUCCESS ) {
            Tspi_Context_CloseObject(hContext, hEncData);
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_Policy_SetSecret(hPolicy, password.isEmpty() ? TSS_SECRET_MODE_SHA1 : TSS_SECRET_MODE_PLAIN, password.isEmpty() ? TPM_SHA1_160_HASH_LEN : password.getLen(), password.isEmpty() ? well_known_secret : reinterpret_cast < BYTE* > (password.getPointer()));
        if ( err != TSS_SUCCESS ) {
            Tspi_Context_CloseObject(hContext, hEncData);
            throw TpmBackendException("TPM Error: " + getException(err));
        }

        err = Tspi_Data_Unseal(hEncData, hSRK, &plainLen, &plainData);
        if ( err != TSS_SUCCESS ) {
            Tspi_Context_CloseObject(hContext, hEncData);
            throw TpmBackendException("TPM Error: " + getException(err));
        }
    } catch ( exception &e ) {
        cout << e.what() << endl;
    }

    try {
        err = Tspi_Policy_FlushSecret(hPolicy);
        if ( err != TSS_SUCCESS ) {
            throw TpmBackendException("TPM Error: " + getException(err));
        }
    } catch ( exception &e ) {
        cout << e.what() << endl;
    }

    return SecureMem<char>(reinterpret_cast < char* > (plainData), plainLen);
}

SecureMem<char> TpmBackend::getRandom ( size_t count ) {
    BYTE * random;
    TSS_RESULT err;

    if ( !this->isOwned() ) {
        throw TpmBackendException("TPM is not owned!");
    }

    if ( !count )
        throw TpmBackendException("Invalid length of bytes submited!");

    err = Tspi_TPM_GetRandom(hTPM, count, &random);
    if ( err != TSS_SUCCESS ) {
        throw TpmBackendException("TPM Error: " + getException(err));
    }

    return SecureMem<char>(reinterpret_cast < char* > (random), count);
}

string
TpmBackend::getException ( TSS_RESULT err ) {

    if ( TSS_ERROR_LAYER(err) == TSS_LAYER_TPM ) {
        switch ( TSS_ERROR_CODE(err) ) {
            case TPM_E_AUTHFAIL: return "TPM_E_AUTHFAIL";
            case TPM_E_BAD_PARAMETER: return "TPM: Bad function parameter.";
            case TPM_E_BADINDEX: return "TPM: Index out of range.";
            case TPM_E_AUDITFAILURE: return "TPM_E_AUDITFAILURE";
            case TPM_E_CLEAR_DISABLED: return "TPM: TPM clear disabled.";
            case TPM_E_DEACTIVATED: return "TPM: TPM is deactivated";
            case TPM_E_DISABLED: return "TPM: TPM is disabled.";
            case TPM_E_FAIL: return "TPM: TPM communication error or epic fail.";
            case TPM_E_BAD_ORDINAL: return "TPM: Wrong locality.";
            case TPM_E_INSTALL_DISABLED: return "TPM_E_INSTALL_DISABLED";
            case TPM_E_INVALID_KEYHANDLE: return "TPM_E_INVALID_KEYHANDLE";
            case TPM_E_KEYNOTFOUND: return "TPM_E_KEYNOTFOUND";
            case TPM_E_INAPPROPRIATE_ENC: return "TPM_E_INAPPROPRIATE_ENC";
            case TPM_E_MIGRATEFAIL: return "TPM_E_MIGRATEFAIL";
            case TPM_E_INVALID_PCR_INFO: return "TPM_E_INVALID_PCR_INFO";
            case TPM_E_NOSPACE: return "TPM_E_NOSPACE";
            case TPM_E_NOSRK: return "TPM_E_NOSRK";
            case TPM_E_NOTSEALED_BLOB: return "TPM_E_NOTSEALED_BLOB";
            case TPM_E_OWNER_SET: return "TPM_E_OWNER_SET";
            case TPM_E_RESOURCES: return "TPM_E_RESOURCES";
            case TPM_E_SHORTRANDOM: return "TPM_E_SHORTRANDOM";
            case TPM_E_SIZE: return "TPM_E_SIZE";
            case TPM_E_WRONGPCRVAL: return "TPM_E_WRONGPCRVAL";
            case TPM_E_BAD_PARAM_SIZE: return "TPM_E_BAD_PARAM_SIZE";
            case TPM_E_SHA_THREAD: return "TPM_E_SHA_THREAD";
            case TPM_E_SHA_ERROR: return "TPM_E_SHA_ERROR";
            case TPM_E_FAILEDSELFTEST: return "TPM_E_FAILEDSELFTEST";
            case TPM_E_AUTH2FAIL: return "TPM_E_AUTH2FAIL";
            case TPM_E_BADTAG: return "TPM_E_BADTAG";
            case TPM_E_IOERROR: return "TPM_E_IOERROR";
            case TPM_E_ENCRYPT_ERROR: return "TPM_E_ENCRYPT_ERROR";
            case TPM_E_DECRYPT_ERROR: return "TPM_E_DECRYPT_ERROR";
            case TPM_E_INVALID_AUTHHANDLE: return "TPM_E_INVALID_AUTHHANDLE";
            case TPM_E_NO_ENDORSEMENT: return "TPM_E_NO_ENDORSEMENT";
            case TPM_E_INVALID_KEYUSAGE: return "TPM_E_INVALID_KEYUSAGE";
            case TPM_E_WRONG_ENTITYTYPE: return "TPM_E_WRONG_ENTITYTYPE";
            case TPM_E_INVALID_POSTINIT: return "TPM_E_INVALID_POSTINIT";
            case TPM_E_INAPPROPRIATE_SIG: return "TPM_E_INAPPROPRIATE_SIG";
            case TPM_E_BAD_KEY_PROPERTY: return "TPM_E_BAD_KEY_PROPERTY";
            case TPM_E_BAD_MIGRATION: return "TPM_E_BAD_MIGRATION";
            case TPM_E_BAD_SCHEME: return "TPM_E_BAD_SCHEME";
            case TPM_E_BAD_DATASIZE: return "TPM_E_BAD_DATASIZE";
            case TPM_E_BAD_MODE: return "TPM_E_BAD_MODE";
            case TPM_E_BAD_PRESENCE: return "TPM_E_BAD_PRESENCE";
            case TPM_E_BAD_VERSION: return "TPM_E_BAD_VERSION";
            case TPM_E_NO_WRAP_TRANSPORT: return "TPM_E_NO_WRAP_TRANSPORT";
            case TPM_E_AUDITFAIL_UNSUCCESSFUL: return "TPM_E_AUDITFAIL_UNSUCCESSFUL";
            case TPM_E_AUDITFAIL_SUCCESSFUL: return "TPM_E_AUDITFAIL_SUCCESSFUL";
            case TPM_E_NOTRESETABLE: return "TPM_E_NOTRESETABLE";
            case TPM_E_NOTLOCAL: return "TPM_E_NOTLOCAL";
            case TPM_E_BAD_TYPE: return "TPM_E_BAD_TYPE";
            case TPM_E_INVALID_RESOURCE: return "TPM_E_INVALID_RESOURCE";
            case TPM_E_NOTFIPS: return "TPM_E_NOTFIPS";
            case TPM_E_INVALID_FAMILY: return "TPM_E_INVALID_FAMILY";
            case TPM_E_NO_NV_PERMISSION: return "TPM_E_NO_NV_PERMISSION";
            case TPM_E_REQUIRES_SIGN: return "TPM_E_REQUIRES_SIGN";
            case TPM_E_KEY_NOTSUPPORTED: return "TPM_E_KEY_NOTSUPPORTED";
            case TPM_E_AUTH_CONFLICT: return "TPM_E_AUTH_CONFLICT";
            case TPM_E_AREA_LOCKED: return "TPM_E_AREA_LOCKED";
            case TPM_E_BAD_LOCALITY: return "TPM_E_BAD_LOCALITY";
            case TPM_E_READ_ONLY: return "TPM_E_READ_ONLY";
            case TPM_E_PER_NOWRITE: return "TPM_E_PER_NOWRITE";
            case TPM_E_FAMILYCOUNT: return "TPM_E_FAMILYCOUNT";
            case TPM_E_WRITE_LOCKED: return "TPM_E_WRITE_LOCKED";
            case TPM_E_BAD_ATTRIBUTES: return "TPM_E_BAD_ATTRIBUTES";
            case TPM_E_INVALID_STRUCTURE: return "TPM_E_INVALID_STRUCTURE";
            case TPM_E_KEY_OWNER_CONTROL: return "TPM_E_KEY_OWNER_CONTROL";
            case TPM_E_BAD_COUNTER: return "TPM_E_BAD_COUNTER";
            case TPM_E_NOT_FULLWRITE: return "TPM_E_NOT_FULLWRITE";
            case TPM_E_CONTEXT_GAP: return "TPM_E_CONTEXT_GAP";
            case TPM_E_MAXNVWRITES: return "TPM_E_MAXNVWRITES";
            case TPM_E_NOOPERATOR: return "TPM_E_NOOPERATOR";
            case TPM_E_RESOURCEMISSING: return "TPM_E_RESOURCEMISSING";
            case TPM_E_DELEGATE_LOCK: return "TPM_E_DELEGATE_LOCK";
            case TPM_E_DELEGATE_FAMILY: return "TPM_E_DELEGATE_FAMILY";
            case TPM_E_DELEGATE_ADMIN: return "TPM_E_DELEGATE_ADMIN";
            case TPM_E_TRANSPORT_NOTEXCLUSIVE: return "TPM_E_TRANSPORT_NOTEXCLUSIVE";
            case TPM_E_OWNER_CONTROL: return "TPM_E_OWNER_CONTROL";
            case TPM_E_DAA_RESOURCES: return "TPM_E_DAA_RESOURCES";
            case TPM_E_DAA_INPUT_DATA0: return "TPM_E_DAA_INPUT_DATA0";
            case TPM_E_DAA_INPUT_DATA1: return "TPM_E_DAA_INPUT_DATA1";
            case TPM_E_DAA_ISSUER_SETTINGS: return "TPM_E_DAA_ISSUER_SETTINGS";
            case TPM_E_DAA_TPM_SETTINGS: return "TPM_E_DAA_TPM_SETTINGS";
            case TPM_E_DAA_STAGE: return "TPM_E_DAA_STAGE";
            case TPM_E_DAA_ISSUER_VALIDITY: return "TPM_E_DAA_ISSUER_VALIDITY";
            case TPM_E_DAA_WRONG_W: return "TPM_E_DAA_WRONG_W";
            case TPM_E_BAD_HANDLE: return "TPM_E_BAD_HANDLE";
            case TPM_E_BAD_DELEGATE: return "TPM_E_BAD_DELEGATE";
            case TPM_E_BADCONTEXT: return "TPM_E_BADCONTEXT";
            case TPM_E_TOOMANYCONTEXTS: return "TPM_E_TOOMANYCONTEXTS";
            case TPM_E_MA_TICKET_SIGNATURE: return "TPM_E_MA_TICKET_SIGNATURE";
            case TPM_E_MA_DESTINATION: return "TPM_E_MA_DESTINATION";
            case TPM_E_MA_SOURCE: return "TPM_E_MA_SOURCE";
            case TPM_E_MA_AUTHORITY: return "TPM_E_MA_AUTHORITY";
            case TPM_E_PERMANENTEK: return "TPM_E_PERMANENTEK";
            case TPM_E_BAD_SIGNATURE: return "TPM_E_BAD_SIGNATURE";
            case TPM_E_NOCONTEXTSPACE: return "TPM_E_NOCONTEXTSPACE";
            case TPM_E_RETRY: return "TPM_E_RETRY";
            case TPM_E_NEEDS_SELFTEST: return "TPM_E_NEEDS_SELFTEST";
            case TPM_E_DOING_SELFTEST: return "TPM_E_DOING_SELFTEST";
            case TPM_E_DEFEND_LOCK_RUNNING: return "TPM_E_DEFEND_LOCK_RUNNING";
            case TPM_E_DISABLED_CMD: return "TPM_E_DISABLED_CMD";
            default: return "UNKNOWN TPM ERROR";

        }
    } else if ( TSS_ERROR_LAYER(err) == TSS_LAYER_TDDL ) {
        switch ( TSS_ERROR_CODE(err) ) {
            case TSS_E_FAIL: return "TSS_E_FAIL";
            case TSS_E_BAD_PARAMETER: return "TSS_E_BAD_PARAMETER";
            case TSS_E_INTERNAL_ERROR: return "TSS_E_INTERNAL_ERROR";
            case TSS_E_NOTIMPL: return "TSS_E_NOTIMPL";
            case TSS_E_PS_KEY_NOTFOUND: return "TSS_E_PS_KEY_NOTFOUND";
            case TSS_E_KEY_ALREADY_REGISTERED: return "TSS_E_KEY_ALREADY_REGISTERED";
            case TSS_E_CANCELED: return "TSS_E_CANCELED";
            case TSS_E_TIMEOUT: return "TSS_E_TIMEOUT";
            case TSS_E_OUTOFMEMORY: return "TSS_E_OUTOFMEMORY";
            case TSS_E_TPM_UNEXPECTED: return "TSS_E_TPM_UNEXPECTED";
            case TSS_E_COMM_FAILURE: return "TSS_E_COMM_FAILURE";
            case TSS_E_TPM_UNSUPPORTED_FEATURE: return "TSS_E_TPM_UNSUPPORTED_FEATURE";
            case TDDL_E_COMPONENT_NOT_FOUND: return "TDDL_E_COMPONENT_NOT_FOUND";
            case TDDL_E_ALREADY_OPENED: return "TDDL_E_ALREADY_OPENED";
            case TDDL_E_BADTAG: return "TDDL_E_BADTAG";
            case TDDL_E_INSUFFICIENT_BUFFER: return "TDDL_E_INSUFFICIENT_BUFFER";
            case TDDL_E_COMMAND_COMPLETED: return "TDDL_E_COMMAND_COMPLETED";
            case TDDL_E_COMMAND_ABORTED: return "TDDL_E_COMMAND_ABORTED";
            case TDDL_E_ALREADY_CLOSED: return "TDDL_E_ALREADY_CLOSED";
            case TDDL_E_IOERROR: return "TDDL_E_IOERROR";
            default: return "UNKNOWN TDDL ERROR";
        }
    } else if ( TSS_ERROR_LAYER(err) == TSS_LAYER_TCS ) {
        switch ( TSS_ERROR_CODE(err) ) {
            case TSS_E_FAIL: return "TSS_E_FAIL";
            case TSS_E_BAD_PARAMETER: return "TCS_E_BAD_PARAMETER";
            case TSS_E_INTERNAL_ERROR: return "TCS_E_INTERNAL_ERROR";
            case TSS_E_NOTIMPL: return "TCS_E_NOTIMPL";
            case TSS_E_PS_KEY_NOTFOUND: return "TSS_E_PS_KEY_NOTFOUND";
            case TSS_E_KEY_ALREADY_REGISTERED: return "TCS_E_KEY_ALREADY_REGISTERED";
            case TSS_E_CANCELED: return "TSS_E_CANCELED";
            case TSS_E_TIMEOUT: return "TSS_E_TIMEOUT";
            case TSS_E_OUTOFMEMORY: return "TCS_E_OUTOFMEMORY";
            case TSS_E_TPM_UNEXPECTED: return "TSS_E_TPM_UNEXPECTED";
            case TSS_E_COMM_FAILURE: return "TSS_E_COMM_FAILURE";
            case TSS_E_TPM_UNSUPPORTED_FEATURE: return "TSS_E_TPM_UNSUPPORTED_FEATURE";
            case TCS_E_KEY_MISMATCH: return "TCS_E_KEY_MISMATCH";
            case TCS_E_KM_LOADFAILED: return "TCS_E_KM_LOADFAILED";
            case TCS_E_KEY_CONTEXT_RELOAD: return "TCS_E_KEY_CONTEXT_RELOAD";
            case TCS_E_BAD_INDEX: return "TCS_E_BAD_INDEX";
            case TCS_E_INVALID_CONTEXTHANDLE: return "TCS_E_INVALID_CONTEXTHANDLE";
            case TCS_E_INVALID_KEYHANDLE: return "TCS_E_INVALID_KEYHANDLE";
            case TCS_E_INVALID_AUTHHANDLE: return "TCS_E_INVALID_AUTHHANDLE";
            case TCS_E_INVALID_AUTHSESSION: return "TCS_E_INVALID_AUTHSESSION";
            case TCS_E_INVALID_KEY: return "TCS_E_INVALID_KEY";
            default: return "UNKNOWN TCS ERROR";
        }
    } else {
        switch ( TSS_ERROR_CODE(err) ) {
            case TSS_E_FAIL: return "TSS_E_FAIL";
            case TSS_E_BAD_PARAMETER: return "TSS_E_BAD_PARAMETER";
            case TSS_E_INTERNAL_ERROR: return "TSS_E_INTERNAL_ERROR";
            case TSS_E_NOTIMPL: return "TSS_E_NOTIMPL";
            case TSS_E_PS_KEY_NOTFOUND: return "TSS_E_PS_KEY_NOTFOUND";
            case TSS_E_KEY_ALREADY_REGISTERED: return "TSS_E_KEY_ALREADY_REGISTERED";
            case TSS_E_CANCELED: return "TSS_E_CANCELED";
            case TSS_E_TIMEOUT: return "TSS_E_TIMEOUT";
            case TSS_E_OUTOFMEMORY: return "TSS_E_OUTOFMEMORY";
            case TSS_E_TPM_UNEXPECTED: return "TSS_E_TPM_UNEXPECTED";
            case TSS_E_COMM_FAILURE: return "TSS_E_COMM_FAILURE";
            case TSS_E_TPM_UNSUPPORTED_FEATURE: return "TSS_E_TPM_UNSUPPORTED_FEATURE";
            case TSS_E_INVALID_OBJECT_TYPE: return "TSS_E_INVALID_OBJECT_TYPE";
            case TSS_E_INVALID_OBJECT_INITFLAG: return "TSS_E_INVALID_OBJECT_INITFLAG";
            case TSS_E_INVALID_HANDLE: return "TSS_E_INVALID_HANDLE";
            case TSS_E_NO_CONNECTION: return "TSS_E_NO_CONNECTION";
            case TSS_E_CONNECTION_FAILED: return "TSS_E_CONNECTION_FAILED";
            case TSS_E_CONNECTION_BROKEN: return "TSS_E_CONNECTION_BROKEN";
            case TSS_E_HASH_INVALID_ALG: return "TSS_E_HASH_INVALID_ALG";
            case TSS_E_HASH_INVALID_LENGTH: return "TSS_E_HASH_INVALID_LENGTH";
            case TSS_E_HASH_NO_DATA: return "TSS_E_HASH_NO_DATA";
            case TSS_E_SILENT_CONTEXT: return "TSS_E_SILENT_CONTEXT";
            case TSS_E_INVALID_ATTRIB_FLAG: return "TSS_E_INVALID_ATTRIB_FLAG";
            case TSS_E_INVALID_ATTRIB_SUBFLAG: return "TSS_E_INVALID_ATTRIB_SUBFLAG";
            case TSS_E_INVALID_ATTRIB_DATA: return "TSS_E_INVALID_ATTRIB_DATA";
            case TSS_E_NO_PCRS_SET: return "TSS_E_NO_PCRS_SET";
            case TSS_E_KEY_NOT_LOADED: return "TSS_E_KEY_NOT_LOADED";
            case TSS_E_KEY_NOT_SET: return "TSS_E_KEY_NOT_SET";
            case TSS_E_VALIDATION_FAILED: return "TSS_E_VALIDATION_FAILED";
            case TSS_E_TSP_AUTHREQUIRED: return "TSS_E_TSP_AUTHREQUIRED";
            case TSS_E_TSP_AUTH2REQUIRED: return "TSS_E_TSP_AUTH2REQUIRED";
            case TSS_E_TSP_AUTHFAIL: return "TSS_E_TSP_AUTHFAIL";
            case TSS_E_TSP_AUTH2FAIL: return "TSS_E_TSP_AUTH2FAIL";
            case TSS_E_KEY_NO_MIGRATION_POLICY: return "TSS_E_KEY_NO_MIGRATION_POLICY";
            case TSS_E_POLICY_NO_SECRET: return "TSS_E_POLICY_NO_SECRET";
            case TSS_E_INVALID_OBJ_ACCESS: return "TSS_E_INVALID_OBJ_ACCESS";
            case TSS_E_INVALID_ENCSCHEME: return "TSS_E_INVALID_ENCSCHEME";
            case TSS_E_INVALID_SIGSCHEME: return "TSS_E_INVALID_SIGSCHEME";
            case TSS_E_ENC_INVALID_LENGTH: return "TSS_E_ENC_INVALID_LENGTH";
            case TSS_E_ENC_NO_DATA: return "TSS_E_ENC_NO_DATA";
            case TSS_E_ENC_INVALID_TYPE: return "TSS_E_ENC_INVALID_TYPE";
            case TSS_E_INVALID_KEYUSAGE: return "TSS_E_INVALID_KEYUSAGE";
            case TSS_E_VERIFICATION_FAILED: return "TSS_E_VERIFICATION_FAILED";
            case TSS_E_HASH_NO_IDENTIFIER: return "TSS_E_HASH_NO_IDENTIFIER";
            case TSS_E_PS_KEY_EXISTS: return "TSS_E_PS_KEY_EXISTS";
            case TSS_E_PS_BAD_KEY_STATE: return "TSS_E_PS_BAD_KEY_STATE";
            case TSS_E_EK_CHECKSUM: return "TSS_E_EK_CHECKSUM";
            case TSS_E_DELEGATION_NOTSET: return "TSS_E_DELEGATION_NOTSET";
            case TSS_E_DELFAMILY_NOTFOUND: return "TSS_E_DELFAMILY_NOTFOUND";
            case TSS_E_DELFAMILY_ROWEXISTS: return "TSS_E_DELFAMILY_ROWEXISTS";
            case TSS_E_VERSION_MISMATCH: return "TSS_E_VERSION_MISMATCH";
            case TSS_E_DAA_AR_DECRYPTION_ERROR: return "TSS_E_DAA_AR_DECRYPTION_ERROR";
            case TSS_E_DAA_AUTHENTICATION_ERROR: return "TSS_E_DAA_AUTHENTICATION_ERROR";
            case TSS_E_DAA_CHALLENGE_RESPONSE_ERROR:return "TSS_E_DAA_CHALLENGE_RESPONSE_ERROR";
            case TSS_E_DAA_CREDENTIAL_PROOF_ERROR: return "TSS_E_DAA_CREDENTIAL_PROOF_ERROR";
            case TSS_E_DAA_CREDENTIAL_REQUEST_PROOF_ERROR:return "TSS_E_DAA_CREDENTIAL_REQUEST_PROOF_ERROR";
            case TSS_E_DAA_ISSUER_KEY_ERROR: return "TSS_E_DAA_ISSUER_KEY_ERROR";
            case TSS_E_DAA_PSEUDONYM_ERROR: return "TSS_E_DAA_PSEUDONYM_ERROR";
            case TSS_E_INVALID_RESOURCE: return "TSS_E_INVALID_RESOURCE";
            case TSS_E_NV_AREA_EXIST: return "TSS_E_NV_AREA_EXIST";
            case TSS_E_NV_AREA_NOT_EXIST: return "TSS_E_NV_AREA_NOT_EXIST";
            case TSS_E_TSP_TRANS_AUTHFAIL: return "TSS_E_TSP_TRANS_AUTHFAIL";
            case TSS_E_TSP_TRANS_AUTHREQUIRED: return "TSS_E_TSP_TRANS_AUTHREQUIRED";
            case TSS_E_TSP_TRANS_NOTEXCLUSIVE: return "TSS_E_TSP_TRANS_NOTEXCLUSIVE";
            case TSS_E_NO_ACTIVE_COUNTER: return "TSS_E_NO_ACTIVE_COUNTER";
            case TSS_E_TSP_TRANS_NO_PUBKEY: return "TSS_E_TSP_TRANS_NO_PUBKEY";
            case TSS_E_TSP_TRANS_FAIL: return "TSS_E_TSP_TRANS_FAIL";
            default: return "UNKNOWN TSS ERROR";
        }
    }
}
