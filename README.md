# ![alt text](https://raw.github.com/zaolin/tpmcrypt/devel/logo.png) TpmCrypt

A disk encryption tool based on Trusted Computing for Linux.
This tool can utilize the tpm to bind the volume encryption key to the platform state.

| Branches      | Continus Integration | Code Coverage |
| ------------- | -------------------  |:-------------:|
| master        | [![Build Status](https://travis-ci.org/zaolin/tpmcrypt.png?branch=master)](https://travis-ci.org/zaolin/tpmcrypt) | [![Coverage Status](https://coveralls.io/repos/zaolin/tpmcrypt/badge.png)](https://coveralls.io/r/zaolin/tpmcrypt) |
| devel         | [![Build Status](https://travis-ci.org/zaolin/tpmcrypt.png?branch=devel)](https://travis-ci.org/zaolin/tpmcrypt) | [![Coverage Status](https://coveralls.io/repos/zaolin/tpmcrypt/badge.png)](https://coveralls.io/r/zaolin/tpmcrypt) |

Features
-----------

* TPM management: take ownership, clear, change SRK, change Owner...
* Trusted Boot with different PCR's.
* KeyFile Management.
* Cryptsetup support.
