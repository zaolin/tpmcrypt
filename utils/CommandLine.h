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

#ifndef COMMANDLINE_H
#define COMMANDLINE_H

#include <iostream>
#include <map>
#include <getopt.h>
#include <string.h>
#include <management/Management.h>
#include <functional>

namespace utils {

class CommandLine {	
	public:
		
		template<class T>
		void registerOption(std::string longName, char shortName, int argument) {
			struct option newOption;
			
			newOption.name = new char[longName.length()];
			//strncpy(newOption.name, longName.c_str(), longName.length());
			
			newOption.has_arg = argument;
			newOption.flag = NULL;
			newOption.val = (int)shortName;
			
			matrix.insert(std::pair<struct option, std::function<void(management::Management&)> >(newOption , &T::start));
		}
		
		void run(int argc, char **argv);
		
	private:
		
		std::map<struct option, std::function<void(management::Management&)> > matrix;
};

}
#endif
