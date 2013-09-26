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
#include <functional>

namespace utils {

class CommandLine {	
	public:
		enum Argument {
			NONE,
			REQUIRED,
			OPTIONAL
		};
	
		CommandLine() :
		optionMap() {

		}

		~CommandLine() { }
		
		template<typename T>
		void registerOptionClass(std::string name, char value = '\0', Argument arg = NONE) {
			T *t = new T();

			prepareOption(name, value, arg, std::bind(&T::start, t));
		}
		
		void registerOptionFunction(std::function<void(void)> function, std::string name, char value = '\0', Argument arg = NONE) {
			prepareOption(name, value, arg, function);
		}
		
		void run(int argc, char **argv);
		
	private:
		void prepareOption(std::string name, char value, Argument arg, std::function<void(void)> function);
		
		std::multimap<std::string, std::map<struct option *, std::function<void(void)> > > optionMap;
};

}
#endif
