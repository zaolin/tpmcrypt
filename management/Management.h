#ifndef MANAGEMENT_H
#define MANAGEMENT_H

#include <iostream>

namespace management {

class Management {
	public:
		virtual ~Management() { }
		virtual void start() = 0;	
};

}
#endif
