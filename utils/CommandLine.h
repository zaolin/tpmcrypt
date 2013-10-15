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
#include <memory>

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

        ~CommandLine() {
        }

        template<typename T>
        void registerOptionClass(std::string desc, std::string name, Argument arg = NONE) {
            T *t = new T();
            char shortName = name.at(0);

            prepareOption(desc, name, shortName, arg, std::bind(&T::start, t), std::bind(std::default_delete<T > (), t));

        }

        void registerOptionFunction(std::function<void(void) > function, std::string desc, std::string name, Argument arg = NONE) {
            char shortName = name.at(0);
            
            prepareOption(desc, name, shortName, arg, function, NULL);
        }

        void run(int argc, char **argv);

    private:

        class Option {
        public:

            Option(struct option *option, std::function<void(void) > function, std::function<void(void) > destructor) :
            commandLineOption(option),
            memberFunction(function),
            instanceDestructor(destructor) {

            }

            void cleanUp() {
                try {
                    this->instanceDestructor();
                } catch (std::exception &e) {

                }
            }

            struct option *commandLineOption;
            std::function<void(void) > memberFunction;
            std::function<void(void) > instanceDestructor;
        };

        std::multimap<std::string, Option>::iterator findOption(const char *longName);
        void prepareOption(std::string desc, std::string name, char value, Argument arg, std::function<void(void) > function, std::function<void(void) > destructor);

        std::multimap<std::string, Option> optionMap;
    };

}
#endif
