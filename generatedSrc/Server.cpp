#include "../generatedHeader/Server.h"


Server::Server(){
	this->__currentState = STATE___init;
}

Server::~Server(){
	
}

int Server::receive(){
	/*Add IP Str and portNUm here*/
	std::string IPStr_ = SELF_IP_STR;
	u_short portNum_ = SELF_PORT;
	this->breakListen = true;
	UDPReceiver  er;
	/*allocation for dst_ here*/
	while(this->breakListen){

		char* item = (char*)malloc(1000*sizeof(char));
		
		std::cout << "recving info: IP: " << IPStr_ << " port: " << portNum_ << std::endl;
		int result = er.receivePacket((u_char*)item, IPStr_, portNum_);

		std::cout << "recv item: " << static_cast<const void *>(item) << std::endl;
		if(result == 0 || result == -1 || result == -2){
			std::cout << "receivePacket Error: " << std::dec <<result << std::endl;
			this->breakListen = false;
		}
		auth_header* auth_hdr = (auth_header*)item;
		std::cout << "UDP PACKET RECV" << std::endl;
		if(auth_hdr->type == 0x10){
			std::cout << "server: acAuthReq_g2s recv" << std::endl;
			AcAuthReq_G2S* itemitem = (AcAuthReq_G2S*)item;
			// JUDGEMENT OF IP
			itemitem->client_id;
			memcpy(&acAuthReq_g2s, item, sizeof(AcAuthReq_G2S));
			std::cout << "recv: " << item << std::endl;
			this->cq.Push(item);
		} else if(auth_hdr->type = 0x21){
			std::cout << "authQuAck recv" << std::endl;
			memcpy(&authQuAck, item, sizeof(AuthQuAck));
			std::cout << "recv: " << item << std::endl;
			this->cq.Push(item);
		} else {
			std::cout << "IGNORED" << std::endl;
			free(item);
		}
	}
	return 0;
}

// int Server::receive_plus(){
// 	std::string ipStr =  SELF_IP_STR;
// 	u_short portNum = this->SELF_PORT;

//     std::cout << "receive Packet" << std::endl;
//     int this_fd, ret;
//     struct sockaddr_in target_addr;
//     this_fd = socket(AF_INET, SOCK_DGRAM, 0);
//     std::cout << "this_fd: " << this_fd << std::endl;
//     if(this_fd < 0)
//     {
//         close(this_fd);
//         std::cout << "create socket failed: " << errno << std::endl;
// 		return 0;
//     }
//     memset(&target_addr, 0, sizeof(target_addr));
//     target_addr.sin_family = AF_INET;
//     in_addr_t addr_dst;
//     inet_aton(ipStr.c_str(), (in_addr*)&addr_dst);
//     target_addr.sin_addr.s_addr = (uint32_t)addr_dst;
//     target_addr.sin_port = htons(portNum);
//     ret = bind(this_fd, (struct sockaddr*)&target_addr, sizeof(target_addr));
//     if(ret < 0)
//     {
//         std::cout << "bind failure:" <<errno<< std::endl;
//         close(this_fd);
// 		return -1;
//     }
// 	this->breakListen = true;
// 	while(this->breakListen){
// 		char* dst = (char*)malloc(1000*sizeof(char));
//     	char recvBuf[1000];
//     	socklen_t len = 1000;
//     	struct sockaddr_in recv_target_addr;
//     	memset(recvBuf, 0, 1000);
//     	int count;
//     	std::cout << "receive from" << std::endl;
//     	count = recvfrom(this_fd, recvBuf, 1000, 0, (struct sockaddr*) &recv_target_addr, &len);
//     	std::cout << "receive from ends" << std::endl;
//     	if (count == -1) {
// 			std::cout << "recv data failed: " << errno << std::endl;
//     	    close(this_fd);
// 			return -2;
// 		}
//     	std::cout << "RECV BUF:" << recvBuf << std::endl;
//     	memcpy(dst, recvBuf, 1000);
// 		auth_header* auth_hdr = (auth_header*)dst;
// 		std::cout << "UDP PACKET RECV" << std::endl;
// 		if(auth_hdr->type == 0x10){
// 			std::cout << "server: acAuthReq_g2s recv" << std::endl;
// 			AcAuthReq_G2S* itemitem = (AcAuthReq_G2S*)dst;
// 			// JUDGEMENT OF IP
// 			itemitem->client_id;
// 			memcpy(&acAuthReq_g2s, dst, sizeof(AcAuthReq_G2S));
// 			std::cout << "recv: " << dst << std::endl;
// 			this->cq.Push(dst);
// 		} else if(auth_hdr->type = 0x21){
// 			std::cout << "authQuAck recv" << std::endl;
// 			memcpy(&authQuAck, dst, sizeof(AuthQuAck));
// 			std::cout << "recv: " << dst << std::endl;
// 			this->cq.Push(dst);
// 		} else {
// 			std::cout << "IGNORED" << std::endl;
// 			free(dst);
// 		}
// 	}
// 	close(this_fd);
//     return 1;

// }


int Server::send(u_char* data_, int length_){
	/*Add Ip Str and portNum here*/
	std::string IPStr_ = GATEWAY_IP_STR;
	u_short portNum_ = GATEWAY_PORT;
	UDPSender snd;
	/*Add length and data content to send here*/
	int result = snd.sendPacket(data_, length_, IPStr_, portNum_);
	std::cout << "udp send: " << data_ << std::endl;
	return result;
}


void Server::Sign(unsigned char* msg, unsigned char* sig, size_t msglen){
	if (digital_sign(msg, msglen, usr_privkey, sig) == -1) {
        printf("digital_sign failed\n");
    }
	std::cout << "sign over" << std::endl;
}

bool Server::Verify(unsigned char* msg, unsigned char* sig, size_t msglen, int verify_id){
	if(digital_verify(sig, msg, msglen, verify_id, master_pubkey) == -1){
		std::cout << "VERIFY FAILED !!!" << std::endl;
		return false;
	} else {
		std::cout << "VERIFY CORRECT..." << std::endl;
		return true;
	}
}

void Server::initConfig(std::string client_ip, ushort self_port, ushort gate_port){
	// init the ibe library
	ibe_init();
	// set server ip which is set by overall init
	this->serverId_int = inet_addr(SELF_IP_STR.c_str());
	// set client ip, gateway port and self port: respected to the object
	this->CLIENT_IP_STR = client_ip;
	this->SELF_PORT = self_port;
	this->GATEWAY_PORT = gate_port;
	this->clientId_int = inet_addr(CLIENT_IP_STR.c_str());
	// init the master private key and master public key
	unsigned char mprik[IBE_MASTER_PRIVKEY_LEN] = {0x40, 0x8c, 0xe9, 0x67};
	unsigned char mpubk[IBE_MASTER_PUBKEY_LEN] = {0x31, 0x57, 0xcd, 0x29, 0xaf, 0x13, 0x83, 0xb7, 0x5e, 0xa0};
	memcpy(this->master_privkey, mprik, IBE_MASTER_PRIVKEY_LEN);
	memcpy(this->master_pubkey, mpubk, IBE_MASTER_PUBKEY_LEN);
	// if (masterkey_gen(master_privkey, master_pubkey) == -1) {
    //         printf("masterkey_gen failed\n");
    // }
	// generate usr private key according to its serverId listening to
	std::cout << "start user key gen" << std::endl;
    userkey_gen(this->serverId_int, this->master_privkey, this->usr_privkey);
	std::cout << "start user key over" << std::endl;
	
}




void Server::SMLMainServer(){
	std::cout << "Server started" << std::endl;
	srand(NULL);
	//initConfig();
	while(__currentState != -100) {
		switch(__currentState){
			case STATE___init:{

				std::cout << "--------------------STATE___init" << std::endl;
				AcAuthReq_G2S* acAuthReq_g2s_result;
				while(true){
					char* item;
					std::cout << "pop" << std::endl;
					this->cq.Pop(item);
					std::cout << "pop over. item: " << static_cast<const void *>(item) << std::endl;
					auth_header* auth_hdr = (auth_header*) item;
					if(auth_hdr->type == 0x10){
						AcAuthReq_G2S tempItem;
						memcpy(&tempItem, item, sizeof(AcAuthReq_G2S));
						free(item);
						//std::cout << "tempItem: " << static_cast<const void *>(tempItem) << std::endl;
						int recvClientId = 0;
						memcpy(&recvClientId, &tempItem.client_id, sizeof(int));
						std::cout << std::hex << ntohl(recvClientId) << std::endl;
						std::cout << std::hex << this->clientId_int << std::endl;
						if(ntohl(recvClientId) == this->clientId_int){
							std::cout << "recvClient Id = clientId_int" << std::endl;
							acAuthReq_g2s_result= &tempItem;
							break;
						} else {
						}
					} else {
						free(item);
					}
				}
				std::cout << "out of the loop" << std::endl;
				memcpy(&this->acAuthReq_g2s, acAuthReq_g2s_result, sizeof(AcAuthReq_G2S));
				std::cout << "udp packet received" << std::endl;
				// free(acAuthReq_g2s_result);
				__currentState = STATE__reqRecved;
				break;
			}
			case STATE___final:
			{
				__currentState = -100;
				std::cout << "--------------------STATE___final" << std::endl;
				this->breakListen = false;
				break;
			}
			case STATE__reqRecved:
			{
				std::cout << "--------------------STATE__reqRecved" << std::endl;
				if(!Verify((unsigned char*)&acAuthReq_g2s, (unsigned char*)acAuthReq_g2s.gateway_signature, sizeof(AcAuthReq_G2S) - 16, Id2Int(acAuthReq_g2s.gateway_id))){
					__currentState = STATE__verifyReqFailed;
				}
				else {
					//clientId_int = Id2Int(acAuthReq_g2s.client_id);
					authQu.auth_hdr.length = htonl(sizeof(AuthQu) - sizeof(auth_header) - 16);
					authQu.auth_hdr.serial_num = htonl(ntohl(acAuthReq_g2s.auth_hdr.serial_num));
					authQu.auth_hdr.timestamp = htonl(ntohl(acAuthReq_g2s.auth_hdr.timestamp));
					authQu.auth_hdr.type = 0x20;
					authQu.auth_hdr.version = 1;
					int tempClientId = htonl(clientId_int);
					memcpy(&authQu.client_id, &tempClientId, sizeof(int));
					authQu.random_num_rs = htonl(rand()); 
					int tempServerId = htonl(serverId_int);
					memcpy(&authQu.server_id, &tempServerId, sizeof(int));
					Sign((unsigned char*)&authQu, authQu.server_signature, sizeof(AuthQu) - 16);
				__currentState = STATE__queCreated;
				}
				break;
			}
				
			case STATE__queCreated:
			{
				
					std::cout << "--------------------STATE__queCreated" << std::endl;
					char* sendData;
					sendData = (char*)malloc(sizeof(AuthQu));
					memcpy(sendData, &authQu, sizeof(AuthQu));
					send((u_char*)sendData, sizeof(AuthQu));
					free(sendData);
					__currentState = STATE__queSent;

				
				break;
			}
			case STATE__verifyReqFailed:{
				std::cout << "--------------------STATE__verifyReqFailed" << std::endl;
				
				__currentState = STATE___final;
				
				break;}
			case STATE__queSent:{
				std::cout << "--------------------STATE__queSent" << std::endl;
				
				AuthQuAck* authQuAck_result;
				AcAuthReq_G2S* acAuthReq_g2s_result;
				while(true){
					char* item;
					this->cq.Pop(item);
					auth_header* auth_hdr = (auth_header*) item;
					if(auth_hdr->type == 0x21){
						AcAuthReq_G2S* tempItem = (AcAuthReq_G2S*) item;
						int recvClientId = 0;
						memcpy(&recvClientId, &tempItem->client_id, sizeof(int));
						std::cout << std::hex << ntohl(recvClientId) << std::endl;
						std::cout << std::hex << this->clientId_int << std::endl;
						if(ntohl(recvClientId) == this->clientId_int){
							authQuAck_result = (AuthQuAck*) tempItem;
							break;
						} else {
							free(item);
						}
					} else if(auth_hdr->type = 0x10){
						AcAuthReq_G2S* tempItem = (AcAuthReq_G2S*) item;
						int recvClientId = 0;
						memcpy(&recvClientId, &tempItem->client_id, sizeof(int));
						if(ntohl(recvClientId) == this->clientId_int){
							acAuthReq_g2s_result= tempItem;
							memcpy(&acAuthReq_g2s, acAuthReq_g2s_result, sizeof(AcAuthReq_G2S));
							__currentState = STATE__reqRecved;
							break;
						}
					} else {
						free(item);
					}
				}
				memcpy(&authQuAck, authQuAck_result, sizeof(AuthQuAck));
				std::cout << "udp packet received" << std::endl;
				free(authQuAck_result);
				__currentState = STATE__queRespRecved;
				
				break;}
			case STATE__queRespRecved:{
				std::cout << "--------------------STATE__queRespRecved" << std::endl;

				if(!Verify((unsigned char*)&authQuAck, (unsigned char*)authQuAck.client_signature, sizeof(AuthQuAck) - 16, Id2Int(authQuAck.client_id))){
					__currentState = STATE__verifyQueRespFailed;
				}
				else {
					bool result = true;
					std::cout << "Serial number test" << std::endl;
					if(ntohl(authQuAck.auth_hdr.serial_num) == ntohl(authQu.auth_hdr.serial_num)){
						std::cout << "PASSED" << std::endl;
					} else {
						result = false;
						std::cout << "FAILED" << std::endl;
					}
					std::cout << "Timestamp test" << std::endl;
					if(ntohl(authQuAck.auth_hdr.timestamp) == ntohl(authQu.auth_hdr.timestamp)){
						std::cout << "PASSED" << std::endl;
					} else {
						result = false;
						std::cout << "FAILED" << std::endl;
					}
					std::cout << "Random number test"  << std::endl;
					if(ntohl(authQuAck.random_number_rs) == ntohl(authQu.random_num_rs)){
						std::cout << "PASSED" << std::endl;
					} else {
						result = false;
						std::cout << "FAILED" << std::endl;
					}
					if(!result){
						std::cout << "Error: entries matching problem of authQuAck" << std::endl;
					}
					acAuthAns.auth_hdr.length = htonl(sizeof(AcAuthAns) - sizeof(auth_header) - 16);
					acAuthAns.auth_hdr.serial_num = htonl(ntohl(authQuAck.auth_hdr.serial_num));
					acAuthAns.auth_hdr.timestamp = htonl(ntohl(authQuAck.auth_hdr.timestamp));
					acAuthAns.auth_hdr.type =  0x11;
					acAuthAns.auth_hdr.version = 1;
					int resultInt = result;
					int tempClientId = 0;
					memcpy(&tempClientId, &authQuAck.client_id, sizeof(int));
					int temptempClient = htonl(ntohl(tempClientId));
					memcpy(&acAuthAns.client_id, &temptempClient, sizeof(int));
					acAuthAns.auth_result = htonl(resultInt);
					acAuthAns.authorization = htonl(0);
					memcpy(&acAuthAns.client_ip_and_mask[0], &temptempClient, sizeof(int));
					int mask= 0xffffff00;
					int tempMask = htonl(mask);
					memcpy(&acAuthAns.client_ip_and_mask[1], &tempMask, sizeof(int));
					int tempGateId = 0;
					memcpy(&tempGateId, & acAuthReq_g2s.gateway_id, sizeof(int));
					int temptempGateId = htonl(ntohl(tempGateId));
					memcpy(&acAuthAns.gateway_ip, &temptempGateId, sizeof(int));
					// TODO: set prikey here.
					memcpy(&acAuthAns.client_ip_prikey, &usr_privkey, 14);
					acAuthAns.random_num_rs = htonl(ntohl(authQuAck.random_number_rs));
					int tempServerId = htonl(serverId_int);
					memcpy(&acAuthAns.server_id, &tempServerId, sizeof(int));
					Sign((unsigned char*)&acAuthAns, (unsigned char*)&acAuthAns.server_signature, sizeof(AcAuthAns) - 16);
				__currentState = STATE__authRespCreated;
				}
				break;}
			case STATE__authRespCreated:{
				std::cout << "--------------------STATE__authRespCreated" << std::endl;
				char* sendData = (char*)malloc(sizeof(AcAuthAns));
				memcpy(sendData, &acAuthAns, sizeof(AcAuthAns));
				send((u_char*)sendData, sizeof(AcAuthAns));
				__currentState = STATE___final;
				
				break;}
			case STATE__verifyQueRespFailed:{
				std::cout << "--------------------STATE__verifyQueRespFailed" << std::endl;
				
				__currentState = STATE___final;
				this->breakListen = false;
				break;}
			default: break;
		}
	}
}

