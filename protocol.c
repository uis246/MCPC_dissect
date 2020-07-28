#include "protocol.h"
#include "protocol_constants.h"


int parse_server_handshake(const void *data, guint length, mcpc_protocol_context *ctx){
	guint readed;
	uint32_t varint;
	int8_t varlen;
	readed=varlen=VarIntToUint(data, &varint, length);//PacketID
	if(varlen>0){
//		readed=varlen;
		switch(varint){
			case 0x00:
				varlen=VarIntToUint(data+readed, &varint, length-readed);//Protocol version
				readed+=varlen;
				varlen=VarIntToUint(data+readed, &varint, length);//String length
				readed+=varlen+varint+2;
				varlen=VarIntToUint(data+readed, &varint, length);//Next state
				if(varint==1)
					ctx->state=STATE_SLP;
				else if(varint==2)
					ctx->state=STATE_LOGIN;
				else
					return -1;
				break;
			default:
				return -1;
		}
		return 0;
	}
	return -1;
}


int parse_server_login(const void *data, guint length, mcpc_protocol_context *ctx _U_){
//	guint readed;
	uint32_t varint;
	int8_t varlen;
	varlen=VarIntToUint(data, &varint, length);//PacketID
	if(varlen>0){
//		readed=varlen;
		return 0;
	}
	return -1;
}
int parse_client_login(const void *data, guint length, mcpc_protocol_context *ctx){
//	guint readed;
	uint32_t varint;
	int8_t varlen;
	varlen=VarIntToUint(data, &varint, length);//PacketID
	if(varlen>0){
//		readed=varlen;
		switch(varint){
			case PID_CB_LOGIN_SET_COMPRESSION:
				varlen=VarIntToUint(data+varlen, &varint, length);//PacketID
				if(varlen>0)
					ctx->compressTrxld=(int32_t)varint;
				else
					return -1;
				break;
			case PID_CB_LOGIN_SUCCESS:
				ctx->state=STATE_PLAY;
				break;
			case PID_CB_LOGIN_CRYPT_RQ:
			case PID_CB_LOGIN_DISCONNECT:
				break;
			default:
				return -1;
		}
		return 0;
	}
	return -1;
}
