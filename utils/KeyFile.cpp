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

const static string BEGIN = "-----BEGIN VOLUME-----";
const static string END = "-----END VOLUME-----";
const static string NAME = "Volume Name: ";
const static string DEV = "Device: ";
const static string TOOL = "Encryption Tool: ";
const static string MONCE = "Monce: ";

KeyFile::KeyFile(string file) :
keyFilePath(file),
keyFile(),
volumes()
{
	this->parseFile();
}

KeyFile::~KeyFile()
{

}

void KeyFile::parseFile()
{
	string line, name, dev, tool, monce;
	size_t found = 0;
	stringstream ss;

	keyFile.open(keyFilePath.c_str(), ios::in);

	if (!keyFile.is_open()) {

	}
	
	while(keyFile.good()) {
		getline(keyFile, line);
		found = line.find(BEGIN);
		if (found != std::string::npos) {
			getline(keyFile, line);
			found = line.find(NAME);
			
			if(found == 0) {
				name = line.substr(NAME.length());
			} else {
				continue;
			}
			
			getline(keyFile, line);
			found = line.find(DEV);
			
			if(found == 0) {
				dev = line.substr(DEV.length());
			} else {
				continue;
			}
			
			getline(keyFile, line);
			found = line.find(TOOL);
			
			if(found == 0) {
				tool = line.substr(TOOL.length());
			} else {
				continue;
			}
			
			getline(keyFile, line);
			found = line.find(MONCE);
			
			if(found == 0) {
				monce = line.substr(MONCE.length());
			} else {
				continue;
			}
			
			getline(keyFile, line);
			if(!line.empty()) {
				continue;
			}
			
			getline(keyFile, line);
			while(!line.empty()) {
				getline(keyFile, line);
				ss << line;
			}
			
			getline(keyFile, line);
			found = line.find(END);
			if (found != std::string::npos) {
				volumes.push_back(Volume(name, dev, ss.str(), tool, monce));
			}
		} else {
			continue;
		}
	}

	keyFile.close();
}

void KeyFile::flushFile()
{
	stringstream ss;

	keyFile.open(keyFilePath.c_str(), ios::out | ios::trunc);

	if (!keyFile.is_open()) {

	}

	for (list<Volume>::iterator it = volumes.begin(); it != volumes.end(); ++it) {
		keyFile << BEGIN << endl;

		keyFile << NAME << it->getName() << endl;
		keyFile << DEV << it->getDev() << endl;
		keyFile << TOOL << it->getTool() << endl;
		keyFile << MONCE << it->getMonce() << endl;

		ss << it->getKeyBase64() << endl;

		ss.seekg(0, ss.end);
		int len = ss.tellg();
		ss.seekg(0, ss.beg);

		for(int i = 0; i < len; ++i) {
			if ((i % 64) == 0 ) {
				keyFile << endl;
			}

			keyFile << (char) ss.get();
		}

		keyFile << endl;

		ss.str("");
		ss.clear();

		keyFile << END << endl;
	}

	keyFile.close();
	sync();
}

void KeyFile::add(Volume vol)
{
	if (searchFile(vol.getName()) != volumes.end()) {
		throw 1;
	}

	volumes.push_back(vol);
	flushFile();
}

void KeyFile::del(string id)
{
	list<Volume>::iterator it;

	it = searchFile(id);

	if (it == volumes.end()) {
		throw 1;
	}

	volumes.erase(it);
	flushFile();
}

Volume KeyFile::get(string id)
{
	list<Volume>::iterator it;

	it = searchFile(id);

	if (it == volumes.end()) {
		throw 1;
	}

	return(*it);
}

list<Volume> KeyFile::getAll() {
	return volumes;
}

list<Volume>::iterator KeyFile::searchFile(string name)
{
	for (list<Volume>::iterator it = volumes.begin(); it != volumes.end(); ++it) {
		if (it->getName() == name) {
			return it;
		}
	}

	return volumes.end();
}
