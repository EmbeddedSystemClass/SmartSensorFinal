#include <cstdlib>
#include <vector>
#include <ctime>
#include <iostream>
#include <fstream>

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

int main(int argc, char **argv) {

	if (argc != 3) {
		std::cerr << "Usage : smartsensor GROUP_IP LISTEN_IP" << std::endl;
		return EXIT_FAILURE;
	}

	boost::asio::io_service service;

	MyHandler handler;
	lncf::LNCF lncf(&service);
	lncf.Init(boost::asio::ip::address::from_string(argv[2]), boost::asio::ip::address::from_string(argv[1]), 6666);
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

void generateDataTest(std::vector<std::string>* datas) {
	if (datas == nullptr) {
		return;
	}

	int size = 16;
	while (size < 65536) {
		char* data = new char[size];
		cpy_rand_str(data, size-1);
		std::string message(data, size);
		datas->push_back(message);
		size *= 2;
	}	
}

void senderTest(lncf::LNCF* lncf) {
	std::vector<std::string> dataTest;
	generateDataTest(&dataTest);
	std::string topic("TOTO");
	std::map<long, boost::posix_time::time_duration> clearResults;
	std::map<long, boost::posix_time::time_duration> cryptedResults;

	unsigned long numberOfSend = 0;
	
	for (std::vector<std::string>::iterator it = dataTest.begin(); it != dataTest.end(); it++) {
		try
		{
			std::string message = *it;
			boost::posix_time::ptime t1(boost::posix_time::microsec_clock::local_time());
			for (int i = 0; i < 10000; i++) {
				lncf->SendClearMessage(topic, message);
				numberOfSend++;
			}
			boost::posix_time::ptime t2(boost::posix_time::microsec_clock::local_time());
			boost::posix_time::time_duration dt = t2 - t1;
			clearResults[message.length()] = dt;
			std::cout << "Time for " << message.length() << " bytes unencrypted : " << dt.total_milliseconds() << " ms" << std::endl;
		}
		catch (const std::exception& e)
		{
			std::cout << e.what() << std::endl;
		}
	}

	std::string fingerprint = lncf->GenerateEncryptionKey();

	for (std::vector<std::string>::iterator it = dataTest.begin(); it != dataTest.end(); it++) {
		try
		{
			std::string message = *it;
			boost::posix_time::ptime t1(boost::posix_time::microsec_clock::local_time());
			for (int i = 0; i < 10000; i++) {
				lncf->SendEncryptedMessage(topic, message,fingerprint);
				numberOfSend++;
			}
			boost::posix_time::ptime t2(boost::posix_time::microsec_clock::local_time());
			boost::posix_time::time_duration dt = t2 - t1;
			cryptedResults[message.length()] = dt;
			std::cout << "Time for " << message.length() << " bytes encrypted : " << dt.total_milliseconds() << " ms" << std::endl;
		}
		catch (const std::exception& e)
		{
			std::cout << e.what() << std::endl;
		}
	}

	std::ofstream outputFile("encrypted.csv");
	if (outputFile)
	{
		outputFile << "Size" << ',' << "Time" << std::endl;
		for (auto data : cryptedResults) {
			outputFile << data.first << ',' << data.second.total_milliseconds() << std::endl;
		}
		outputFile.flush();
		outputFile.close();
	}
	else
	{
		std::cerr << "Failure opening " << "encrypted.csv" << '\n';
	}

	std::ofstream outputClearFile("clear.csv");
	if (outputClearFile)
	{
		outputClearFile << "Size" << ',' << "Time" << std::endl;
		for (auto data : clearResults) {
			outputClearFile << data.first << ',' << data.second.total_milliseconds() << std::endl;
		}
		outputClearFile.flush();
		outputClearFile.close();
	}
	else
	{
		std::cerr << "Failure opening " << "clear.csv" << '\n';
	}
}