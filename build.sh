#!/bin/sh

g++ -I. -g -o2 -J4 -std=c++11 -o smartsensor ./SmartSensor/*.cpp ./SmartSensor/lncf/*.cpp -lcryptopp -pthread -lboost_thread_pthread -lboost_system
