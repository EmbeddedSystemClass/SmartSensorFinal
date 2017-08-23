#include <cstdlib>
#include <ctime>
#include <iostream>

#include <boost/thread.hpp>

#include "lncf/LNCF.h"
#include "lncf/CryptoEngine.h"

#include "MyHandler.h"

bool stop = false;
void senderTest(lncf::LNCF* lncf);

void cpy_rand_str(char *dest, int size) {
	int i;
	int rand_num;

	srand(time(NULL));

	for (i = 0; i < size; i++) {
		rand_num = rand() % 36;
		if (rand_num >= 10) {
			rand_num += ('A' - 10);
		}
		else {
			rand_num += '0';
		}
		dest[i] = (char)rand_num;
	}
	dest[size] = '\0';
}

int main() {
	boost::asio::io_service service;

	MyHandler handler;
	lncf::LNCF lncf(&service);
	lncf.Init(boost::asio::ip::address::from_string("0.0.0.0"), boost::asio::ip::address::from_string("224.0.0.1"), 6666);
	lncf.Handle("TOTO", &handler);
	lncf.ListenAndServe();

	boost::thread bt(boost::bind(&boost::asio::io_service::run, &service));

	senderTest(&lncf);

	std::cout << "Press enter to terminate whenever you want!" << std::endl;
	std::string request;
	std::getline(std::cin, request);

	std::cout << handler.numberReceived << std::endl;

	std::cout << "Begin shutdown procedure" << std::endl;
	lncf.Stop();
	std::cout << "LNCF stopped" << std::endl;
	service.stop();
	std::cout << "ASIO stopped" << std::endl;

	std::cin.ignore();
	return EXIT_SUCCESS;
}

void senderTest(lncf::LNCF* lncf) {
	std::string topic("TOTO");
	char* data = new char[30720];
	cpy_rand_str(data, 30719);
	std::string message(data, 30720);

	unsigned long numberOfSend = 0;
	boost::posix_time::ptime t1(boost::posix_time::microsec_clock::local_time());

	for(int i = 0; i < 10000; i++) {
		lncf->SendClearMessage(topic, message);
		numberOfSend++;
	}
	boost::posix_time::ptime t2(boost::posix_time::microsec_clock::local_time());
	boost::posix_time::time_duration dt = t2 - t1;
	
	std::cout << "Time : " << dt.total_milliseconds() << std::endl;
}