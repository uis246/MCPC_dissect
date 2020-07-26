#include "protocol.h"

extern int
	hf_protocol_packetid_sb,
	hf_protocol_packetid_cb,
	hf_protocol_packetid_sb_hs,
	hf_protocol_packetid_sb_login,
	hf_protocol_packetid_cb_login,
	hf_protocol_packetid_sb_slp,
	hf_protocol_packetid_cb_slp;


void tree_server_login(proto_tree *packet_tree, tvbuff_t *tvb, const void *data, guint length){
//	guint readed;
	uint32_t varint;
	int8_t varlen;
	varlen=VarIntToUint(data, &varint, length);//PacketID
	if(varlen>0){
//		readed=varlen;
		proto_tree_add_uint(packet_tree, hf_protocol_packetid_sb_login, tvb, 0, varlen, varint);
	}
}
void tree_client_login(proto_tree *packet_tree, tvbuff_t *tvb, const void *data, guint length){
//	guint readed;
	uint32_t varint;
	int8_t varlen;
	varlen=VarIntToUint(data, &varint, length);//PacketID
	if(varlen>0){
//		readed=varlen;
		proto_tree_add_uint(packet_tree, hf_protocol_packetid_cb_login, tvb, 0, varlen, varint);
	}
}

void tree_server_handshake(proto_tree *packet_tree, tvbuff_t *tvb, const void *data, guint length){
//	guint readed;
	uint32_t varint;
	int8_t varlen;
	varlen=VarIntToUint(data, &varint, length);//PacketID
	if(varlen>0){
//		readed=varlen;
		proto_tree_add_uint(packet_tree, hf_protocol_packetid_sb_hs, tvb, 0, varlen, varint);
		switch(varint){
			case 0x00:
/*				varlen=VarIntToUint(data+readed, &varint, length-readed);//Protocol version
				readed+=varlen;
				varlen=VarIntToUint(data+readed, &varint, length-readed);//String length
				readed+=varlen;
				readed+=varint;//Skip string
				readed+=2;//Skip short
				varlen=VarIntToUint(data+readed, &varint, length-pinfo->pooreaded);//Next State*/
				break;
		}
	}
	return;
}


int parse_server_handshake(const void *data, guint length, mcpc_protocol_context *ctx){
	guint readed;
	uint32_t varint;
	int8_t varlen;
	varlen=VarIntToUint(data, &varint, length);//PacketID
	if(varlen>0){
		readed=varlen;
		switch(varint){
			case 0x00:
				varlen=VarIntToUint(data+readed, &varint, length-readed);//Protocol version
				readed+=varlen;
				varlen=VarIntToUint(data+readed, &varint, length-readed);//String length
				readed+=varlen;
				readed+=varint;//Skip string
				readed+=2;//Skip short
				varlen=VarIntToUint(data+readed, &varint, length-readed);//Next State
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
		switch(varint){
		}
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
			case 0x03:
				varlen=VarIntToUint(data+varlen, &varint, length);//PacketID
				if(varlen>0)
					ctx->compressTrxld=(int32_t)varint;
				else
					return -1;
			case 0x02:
			case 0x01:
				break;
			default:
				return -1;
		}
		return 0;
	}
	return -1;
}
