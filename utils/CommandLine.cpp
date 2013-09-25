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

using namespace std;
using namespace utils;

void CommandLine::run(int argc, char **argv) {
	struct option long_options[matrix.size()];

	for(map<struct option, std::function<void(management::Management&)> >::iterator it = matrix.begin(); it != matrix.end(); ++it) {
	}	

	//getopt_long(argc, argv, "abc:d:012", long_options, &option_index);	
}
