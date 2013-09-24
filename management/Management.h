#include <iostream>

namespace management {

class Management {
	public:
		virtual ~Management();
		virtual void start() = 0;	
	protected:
		Management();
};

}
