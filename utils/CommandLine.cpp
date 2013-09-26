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

#include <utils/CommandLine.h>
#include <string.h>

using namespace std;
using namespace utils;

void CommandLine::run(int argc, char **argv) {
	int counter = 0;
	int option_index;
	struct option long_options[optionMap.size()];
	
	for(map<string, map<struct option *, std::function<void(void)> > >::iterator optionPair = optionMap.begin(); optionPair != optionMap.end(); ++optionPair) {	
		for(map<struct option *, std::function<void(void)> >::iterator it = optionPair->second.begin(); it != optionPair->second.end(); ++it) {
			long_options[counter++] = *it->first;
		}
	}
	
	while(1) {
		int c = getopt_long(argc, argv, "h", long_options, &option_index);

		if(c == -1)
			break;
		
	}
}

void CommandLine::prepareOption(std::string name, char value, Argument arg, std::function<void(void)> function) {
	struct option *newOption;
        std::map<struct option *, std::function<void(void)> > table;
                        
        newOption = (struct option*)malloc(sizeof(struct option));
        char *newName = new char[name.length()];

	strncpy(newName, name.c_str(), name.length());
	
	newOption->name = newName;
        newOption->has_arg = static_cast<int>(arg);
        newOption->flag = NULL;

       	newOption->val = (int)value;

	table.insert(std::pair<struct option *, std::function<void(void)> >(newOption , function));
        optionMap.insert(std::pair<std::string, std::map<struct option *, std::function<void(void)> > >(name, table));
}
