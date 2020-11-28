#ifndef Gateway_h
#define Gateway_h
#include <iostream>
#include <string>
#include <vector>
#include <stdlib.h>
#include <thread>
#include <stdlib.h>
#include <sstream>
#include <fstream>
#include <stdio.h>
#include <thread>
#include <stdlib.h>
#include <typeinfo>
#include <time.h>
#include <ibe.h>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

#include <boost/serialization/vector.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/string.hpp>
#include "../CommLib/NetComm/include/EtherReceiver.hpp"
#include "../CommLib/NetComm/include/EtherSender.hpp"
#include "../CommLib/NetComm/include/UDPSender.hpp"
#include "../CommLib/NetComm/include/UDPReceiver.hpp"
#include "../CommLib/NetComm/include/packet.hpp"
#include "./MQ.h"
#define STATE___init 0
#define STATE___final 1
#define STATE__reqMsgRecved 2
#define STATE__reqMsgSent 3
#define STATE__authQueRecved 4
#define STATE__authQueSent 5
#define STATE__queRespRecved 6
#define STATE__queRespSent 7
#define STATE__authRespRecved 8
#define MAX_CLIENT_NUM 6
std::string SELF_IP_STR = "127.0.0.1";
std::string SERVER_IP_STR = "127.0.0.1";
static pcap_t* devGateway;
std::map<int, int> clientIp2QIDMap;
int CLIENT_NUM;
u_char gateway_mac[6];
ConcurrentQueue cqs[MAX_CLIENT_NUM];
class Gateway {


	public: 
		int debugId;
		int hostId;
		int gateway;
		int server;		
		GwAnce gwAnce;
		AcAuthReq_C2G acAuthReq_c2g;
		AcAuthReq_G2S acAuthReq_g2s;
		AuthQuAck authQuAck;
		AuthQu authQu;
		AcAuthAns acAuthAns;

		int clientId_int;
		int gatewayId_int;
		int __currentState;
		ushort SELF_PORT;
		ushort SERVER_PORT;


        unsigned char master_privkey[IBE_MASTER_PRIVKEY_LEN];
        unsigned char master_pubkey[IBE_MASTER_PUBKEY_LEN];
        unsigned char usr_privkey[IBE_USR_PRIVKEY_LEN];

		Gateway();
		~Gateway();
		void Sign(unsigned char* msg, unsigned char* sig, size_t msglen);
		bool Verify(unsigned char* msg, unsigned char* sig, size_t msglen, int verify_id);
		int sendToHost(u_char* data_, int length_, u_char dmac[6]);
		int sendToServer();
		void SMLMainGateway();
		void recvFromServer();
		void initConfig(std::string client_ip_str, ushort self_port, ushort server_port);
};


int recvFromHost();
void receive_udp(Gateway* gw);
void recv_udp_thd(Gateway* gw);
void recv_ether_thd();
void receive_udp(Gateway* gw);
void handle_thd(Gateway* gw);
void gwAnce_thd(Gateway* gw);

void initOverallConfig(int client_num, std::string gate_ip_str, std::string server_ip_str, u_char mac[6]){
	SELF_IP_STR = gate_ip_str;
	SERVER_IP_STR = server_ip_str;
	CLIENT_NUM = client_num;
	gateway_mac[0] = mac[0];
	gateway_mac[1] = mac[1];
	gateway_mac[2] = mac[2];
	gateway_mac[3] = mac[3];
	gateway_mac[4] = mac[4];
	gateway_mac[5] = mac[5];
}



int main(int argc, char** argv) {

	std::string client_ips[2];
	ushort self_prefix = 8000;
	ushort server_prefix = 6000;

	std::cout << "CONFIG: " << argv[1] << std::endl;
	std::ifstream inConf(argv[1]);
	std::string s = "";
	u_char mac[6];
	while(getline(inConf,s)){
		int split_pos = s.find(",");
		std::string first = s.substr(0, split_pos);
		std::string second = s.substr(split_pos + 1, sizeof(s));
		std::cout << "first: " << first << std::endl;
		std::cout << "second: " << second << std::endl;
		if(!first.compare("GATE_IP_STR")){
			SELF_IP_STR = second;
			std::cout << "read SELF_IP_STR " << SELF_IP_STR << std::endl;
		} else if(!first.compare("SERVER_IP_STR")){
			SERVER_IP_STR = second;
			std::cout << "SERVER_IP: " << SERVER_IP_STR << std::endl; 
		} else if(!first.compare("CLIENT_NUM")){
			CLIENT_NUM = atoi(second.c_str());
			std::cout << "CLIENT_NUM: " << CLIENT_NUM << std::endl;
		} else if(!first.compare("RECV_PORT_PRE")){
			self_prefix = atoi(second.c_str());
			std::cout << "self_prefix: " << self_prefix << std::endl;
		} else if(!first.compare("SND_PORT_PRE")){
			server_prefix = atoi(second.c_str());
			std::cout << "server_prefix: " << server_prefix << std::endl;
		} else if(!first.compare("IP2ID")){
			int second_split_pos = second.find(",");
			std::string sec = second.substr(0, second_split_pos);
			std::string third = second.substr(second_split_pos + 1, sizeof(second));
			std::cout << "sec: " << sec << std::endl;
			std::cout << "third: " << third << std::endl;
			int id = atoi(third.c_str());
			clientIp2QIDMap[inet_addr(sec.c_str())] = id;
			client_ips[id] = sec;
			std::cout << "ip: " << sec << "id: "<< third << std::endl;
		} else if(!first.compare("GATE_MAC")){
			for(int i = 0; i < 6; i++){
				for(int j = 0; j < 3; j ++){
				switch(second.c_str()[j + 3*i])  
   				{  
					case ':': break;
   					case '0': mac[i] += (j == 0)? 16*0 :  1*0 ; break;
   					case '1': mac[i] += (j == 0)? 16*1 :  1*1 ; break;
   					case '2': mac[i] += (j == 0)? 16*2 :  1*2 ; break;
   					case '3': mac[i] += (j == 0)? 16*3 :  1*3 ; break;
   					case '4': mac[i] += (j == 0)? 16*4 :  1*4 ; break;
   					case '5': mac[i] += (j == 0)? 16*5 :  1*5 ; break;
   					case '6': mac[i] += (j == 0)? 16*6 :  1*6 ; break;
   					case '7': mac[i] += (j == 0)? 16*7 :  1*7 ; break;
   					case '8': mac[i] += (j == 0)? 16*8 :  1*8 ; break;
   					case '9': mac[i] += (j == 0)? 16*9 :  1*9 ; break;
   					case 'a': mac[i] += (j == 0)? 16*10 : 1*10; break;
   					case 'A': mac[i] += (j == 0)? 16*10 : 1*10;  break;
   					case 'b': mac[i] += (j == 0)? 16*11 : 1*11; break;
   					case 'B': mac[i] += (j == 0)? 16*11 : 1*11;  break;
   					case 'c': mac[i] += (j == 0)? 16*12 : 1*12; break;
   					case 'C': mac[i] += (j == 0)? 16*12 : 1*12;  break;
   					case 'd': mac[i] += (j == 0)? 16*13 : 1*13; break;
   					case 'D': mac[i] += (j == 0)? 16*13 : 1*13;  break;
   					case 'e': mac[i] += (j == 0)? 16*14 : 1*14; break;
   					case 'E': mac[i] += (j == 0)? 16*14 : 1*14;  break;
   					case 'f': mac[i] += (j == 0)? 16*15 : 1*15; break;
   					case 'F': mac[i] += (j == 0)? 16*15 : 1*15;  break;  
					default: std::cout << "ERROR: parsing mac" << std::endl;  
   				}  
				j++;
				}
			}
		} else {
			std::cout << "ERROR: should not be here" << std::endl;
		}

	}
	initOverallConfig(CLIENT_NUM, SELF_IP_STR, SERVER_IP_STR, mac);
	// this is for sending hellp packet, no need for initialized
	Gateway* gwAnceSender = new Gateway();
	gwAnceSender->debugId = 0;
	gwAnceSender->initConfig("0.0.0.0", 10000, 10000);

	Gateway* gates[CLIENT_NUM];
	std::cout << "start hello thread" << std::endl;
	std::thread sendHello_t(&gwAnce_thd, gwAnceSender);
	sendHello_t.detach();
	std::cout << "start hello thread end" << std::endl;
	
	// client_ips[0] = "127.0.0.10";
	// client_ips[1] = "127.0.0.11";
	std::thread recvEther_t(&recv_ether_thd);
	for(ushort i = 0; i < CLIENT_NUM; i++){
		// configure the port num here
		gates[i] = new Gateway();
		gates[i]->debugId = i + 1;
		gates[i]->initConfig(client_ips[i], self_prefix + i, server_prefix + i);
	}
	std::thread recvUdp_ts[CLIENT_NUM];
	std::thread handle_ts[CLIENT_NUM];
	
	for(int i = 0; i < CLIENT_NUM; i++){
		recvUdp_ts[i] = std::thread(&recv_udp_thd, gates[i]);
		handle_ts[i] = std::thread(&handle_thd, gates[i]);
	}

	for(int i = 0; i < CLIENT_NUM; i++){
		recvUdp_ts[i].join();
		handle_ts[i].join();
	}
	recvEther_t.join();
}
#endif

