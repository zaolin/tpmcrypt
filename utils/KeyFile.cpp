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

#include <vector>
#include <sstream>
#include <cstring>
#include <string>
#include <utils/KeyFile.h>
#include <unistd.h>

using namespace utils;
using namespace std;

const static string BEGIN_VOLUME = "-----BEGIN VOLUME-----";
const static string END_VOLUME = "-----END VOLUME-----";
const static string BEGIN_MONCE = "-----BEGIN MONCE-----";
const static string END_MONCE = "-----END MONCE-----";
const static string BEGIN_KEYBLOB = "-----BEGIN KEYBLOB-----";
const static string END_KEYBLOB = "-----END KEYBLOB-----";
const static string VOLUME_NAME = "Volume Name: ";
const static string DEVICE_NAME = "Device: ";
const static string TOOL_NAME = "Encryption Tool: ";

KeyFile::KeyFile(string file) :
keyFilePath(file),
keyFile(),
volumes() {
    this->parseFile();
}

KeyFile::~KeyFile() {

}

void KeyFile::parseFile() {
    string line, volumeName, deviceName, toolName;
    size_t found = 0;
    stringstream key, monce;

    keyFile.open(keyFilePath.c_str(), ios::in);

    if (!keyFile.is_open()) {

    }

    while (keyFile.good()) {
        getline(keyFile, line);
        while (line.find(END_VOLUME) == std::string::npos) {
            found = line.find(BEGIN_VOLUME);
            if (found != std::string::npos) {
                found = line.find(VOLUME_NAME);
                if (found == 0) {
                    volumeName = line.substr(VOLUME_NAME.length());
                }
                
                found = line.find(DEVICE_NAME);
                if (found == 0) {
                    deviceName = line.substr(DEVICE_NAME.length());
                }

                found = line.find(TOOL_NAME);
                if (found == 0) {
                    toolName = line.substr(TOOL_NAME.length());
                }

                found = line.find(BEGIN_MONCE);
                if (found != std::string::npos) {
                    while (!line.find(END_MONCE)) {
                        monce << line;
                        getline(keyFile, line);
                    }
                }

                found = line.find(BEGIN_KEYBLOB);
                if (found != std::string::npos) {
                    while (!line.find(END_KEYBLOB)) {
                        key << line;
                        getline(keyFile, line);
                    }
                }

            } else {
                continue;
            }
            getline(keyFile, line);
        }
        if( !volumeName.empty() && !deviceName.empty() && !toolName.empty() && key.good() && monce.good() ) {
                volumes.push_back(Volume(volumeName, deviceName, key.str(), toolName, monce.str()));
        }
    }

    keyFile.close();
}

void KeyFile::flushFile() {
    keyFile.open(keyFilePath.c_str(), ios::out | ios::trunc);

    if (!keyFile.is_open()) {

    }

    for (list<Volume>::iterator it = volumes.begin(); it != volumes.end(); ++it) {
        stringstream key, monce;
        
        keyFile << BEGIN_VOLUME << endl;

        keyFile << VOLUME_NAME << it->getName() << endl;
        keyFile << DEVICE_NAME << it->getDev() << endl;
        keyFile << TOOL_NAME << it->getTool() << endl;
        
        monce << it->getMonce() << endl;
        key << it->getKeyBase64() << endl;
        
        keyFile << BEGIN_MONCE << endl;
        
        while(!monce.eof()) {
            if ((monce.tellp() % 64) == 0) {
                keyFile << endl;
            }

            keyFile << (char) monce.get();
        }
        
        keyFile << END_MONCE << endl;
        keyFile << BEGIN_KEYBLOB << endl;
        
        while(!key.eof()) {
            if ((key.tellp() % 64) == 0) {
                keyFile << endl;
            }

            keyFile << (char) key.get();
        }
        
        keyFile << END_KEYBLOB << endl;
        keyFile << END_VOLUME << endl;
    }

    keyFile.close();
    sync();
}

void KeyFile::add(Volume vol) {
    if (searchFile(vol.getName()) != volumes.end()) {
        throw 1;
    }

    volumes.push_back(vol);
    flushFile();
}

void KeyFile::del(string id) {
    list<Volume>::iterator it;

    it = searchFile(id);

    if (it == volumes.end()) {
        throw 1;
    }

    volumes.erase(it);
    flushFile();
}

Volume KeyFile::get(string id) {
    list<Volume>::iterator it;

    it = searchFile(id);

    if (it == volumes.end()) {
        throw 1;
    }

    return (*it);
}

list<Volume> KeyFile::getAll() {
    return volumes;
}

list<Volume>::iterator KeyFile::searchFile(string name) {
    for (list<Volume>::iterator it = volumes.begin(); it != volumes.end(); ++it) {
        if (it->getName() == name) {
            return it;
        }
    }

    return volumes.end();
}
