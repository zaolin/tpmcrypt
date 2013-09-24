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

#include <tools/ToolBackend.h>
#include <stdio.h>
#include <sstream>
#include <err.h>
#include <spawn.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <cassert>
#include <blkid/blkid.h>

using namespace utils;
using namespace tools;
using namespace std;

ToolBackend::ToolBackend ( ) {

}

ToolBackend::~ToolBackend ( ) {

}

void ToolBackend::call ( string executable, list<string> commands, list<SecureMem<char> > toWrite, string &toRead, int *ret ) {
    char buf[255];
    char* args[255];
    char* envp[2];
    stringstream ss;
    int out[2];
    int in[2];
    posix_spawn_file_actions_t action;
    pid_t pid;
    int status, i = 1;

    if ( commands.size() > 255 ) {
        throw 1;
    }

    args[0] = strdup(executable.c_str());

    for ( list<string>::iterator it = commands.begin(); it != commands.end(); it++ ) {
        args[i++] = strdup(it->c_str());
    }

    args[i] = 0;

    envp[0] = strdup(("PATH=" + string(getenv("PATH"))).c_str());
    envp[1] = 0;

    if(pipe(out) < 0 || pipe(in) < 0 ) {
    
    }

    posix_spawn_file_actions_init(&action);
    posix_spawn_file_actions_adddup2(&action, out[0], 0);
    posix_spawn_file_actions_addclose(&action, out[1]);

    posix_spawn_file_actions_adddup2(&action, in[1], 1);
    posix_spawn_file_actions_addclose(&action, in[0]);

    posix_spawnp(&pid, executable.c_str(), &action, NULL, args, envp);

    close(out[0]);
    close(in[1]);

    for ( list<SecureMem<char> >::iterator it = toWrite.begin(); it != toWrite.end(); it++ ) {
        if(write(out[1], it->getPointer(), it->getLen() != it->getLen()))  {
	
	}
        
	if(write(out[1], "\n", 1) != 1) {

	}
    }

    close(out[1]);

    while ( read(in[0], buf, 255) ) {
        ss << buf;
    }

    toRead = ss.str();
    close(in[0]);


    waitpid(pid, &status, 0);
    *ret = WEXITSTATUS(status);

    posix_spawn_file_actions_destroy(&action);

    return;
}

string ToolBackend::genUniqueName ( std::string dev ) {
    blkid_probe pr;
    const char *uuid;
    stringstream ss;

    pr = blkid_new_probe_from_filename(dev.c_str());

    blkid_do_probe(pr);
    blkid_probe_lookup_value(pr, "UUID", &uuid, NULL);

    ss << uuid << "-crypt";

    blkid_free_probe(pr);

    return ss.str();
}
