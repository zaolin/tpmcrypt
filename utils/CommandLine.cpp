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
#include <sstream>

using namespace std;
using namespace utils;

void CommandLine::run(int argc, char **argv)
{
	int counter = 0;
	int option_index;
	struct option long_options[optionMap.size() + 1];
	stringstream shortOptions;
	
	if(argc < 2) {
		for (multimap<string, Option>::iterator it = optionMap.begin(); it != optionMap.end(); ++it) {
				cout << "	" << "--" << it->second.commandLineOption->name << "	" << it->first << endl;
		}
		
		return;
	}

	for (multimap<string, Option>::iterator it = optionMap.begin(); it != optionMap.end(); ++it) {
		long_options[counter++] = *it->second.commandLineOption;
		shortOptions << (char)it->second.commandLineOption->val;
	}
	
	long_options[counter] = {0, 0, 0, 0};

	while (1) {
		multimap<string, CommandLine::Option>::iterator it;

		int c = getopt_long(argc, argv, shortOptions.str().c_str(), long_options, &option_index);

		if (c == -1)
			break;
	
		switch (c) {
		case '?': 
			break;

		default:
			it = findOption(long_options[option_index].name);
			if(it != optionMap.end())
				it->second.memberFunction();
			
			break;
		}
	}
}

void CommandLine::prepareOption(std::string desc, std::string name, char value, Argument arg, std::function<void(void) > function, std::function<void(void) > destructor)
{
	struct option *newOption;

	newOption = (struct option*) malloc(sizeof(struct option));
	char *newName = new char[name.length()];

	strncpy(newName, name.c_str(), name.length());

	newOption->name = newName;
	newOption->has_arg = static_cast<int> (arg);
	newOption->flag = NULL;
	newOption->val = (int) value;

	optionMap.insert(std::make_pair(desc, Option(newOption, function, destructor)));
}

multimap<string, CommandLine::Option>::iterator CommandLine::findOption(const char *longName)
{
	for (multimap<string, Option>::iterator it = optionMap.begin(); it != optionMap.end(); ++it) {
		if (strncasecmp(longName, it->second.commandLineOption->name, strlen(it->second.commandLineOption->name)) == 0)
			return it;
	}

	return optionMap.end();
}