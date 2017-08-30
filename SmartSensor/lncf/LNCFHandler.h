#ifndef _LNCF_HANDLER_H_
#define _LNCF_HANDLER_H_

#define __STDC_WANT_LIB_EXT1__ 1

#include <string>

namespace lncf {
	class LNCFHandler {
	public:
		virtual void Handle(std::string topic, std::string message) = 0;
	};
}

#endif
