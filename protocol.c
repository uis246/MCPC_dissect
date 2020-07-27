#include "protocol.h"
#include "protocol_constants.h"

extern int
	hf_protocol_packetid_sb,
	hf_protocol_packetid_cb,
	hf_protocol_packetid_sb_hs,
	hf_protocol_packetid_sb_login,
	hf_protocol_packetid_cb_login,
	hf_protocol_packetid_sb_slp,
	hf_protocol_packetid_cb_slp;
extern int
	hf_string_length,
	hf_player_name,
	hf_uuid,
	hf_compression_trxld,
	hf_protocol_version,
	hf_hs_next_state,
	hf_server_address,
	hf_entity_id,
	hf_difficulty;
extern int proto_mcpc, ett_strlen;

#define CUSTOM_STR_TO_TREE(format)		{varlen=VarIntToUint(data+readed, &varint, length);\
										gchar *name=wmem_alloc(pinfo->pool, varint+1);\
										memcpy(name, data+readed+varlen, varint);\
										name[varint]=0x00;\
										proto_item *ti=proto_tree_add_item(packet_tree, proto_mcpc, tvb, readed+varlen, varint, FALSE);\
										proto_item_set_text(ti, format, name);\
										proto_tree_add_uint(\
											proto_item_add_subtree(ti, ett_strlen),\
											hf_string_length, tvb, readed, varlen, varint);\
										\
										wmem_free(pinfo->pool, name);\
										readed+=varlen+varint;}


#define STR_TO_TREE(to_hf) 				{varlen=VarIntToUint(data+readed, &varint, length);\
										gchar *name=wmem_alloc(pinfo->pool, varint+1);\
										memcpy(name, data+readed+varlen, varint);\
										name[varint]=0x00;\
										proto_tree_add_uint(\
											proto_item_add_subtree(\
												proto_tree_add_string(packet_tree, to_hf, tvb, readed, varint+varlen, name),\
												ett_strlen),\
											hf_string_length, tvb, readed, varlen, varint);\
										\
										wmem_free(pinfo->pool, name);\
										readed+=varlen+varint;}

void tree_server_slp(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const void *data, guint length){
	uint32_t varint;
	int8_t varlen;
	varlen=VarIntToUint(data, &varint, length);//PacketID
	if(varlen>0){
		proto_tree_add_uint(packet_tree, hf_protocol_packetid_sb_slp, tvb, 0, varlen, varint);
	}
}
void tree_client_slp(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const void *data, guint length){
	uint32_t varint;
	int8_t varlen;
	varlen=VarIntToUint(data, &varint, length);//PacketID
	if(varlen>0){
		proto_tree_add_uint(packet_tree, hf_protocol_packetid_cb_slp, tvb, 0, varlen, varint);
	}
}

void tree_server_play(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const void *data, guint length){
	//	guint readed;
		uint32_t varint;
		int8_t varlen;
		varlen=VarIntToUint(data, &varint, length);//PacketID
		if(varlen>0){
	//		readed=varlen;
			proto_tree_add_uint(packet_tree, hf_protocol_packetid_sb, tvb, 0, varlen, varint);
		}
}
void tree_client_play(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const void *data, guint length){
		guint readed;
		uint32_t varint;
		int8_t varlen;
		readed=varlen=VarIntToUint(data, &varint, length);//PacketID
		if(varlen>0){
			proto_tree_add_uint(packet_tree, hf_protocol_packetid_cb, tvb, 0, varlen, varint);
			switch(varint){
				case PID_CB_PLAY_JOIN_GAME:
					proto_tree_add_int(packet_tree, hf_entity_id, tvb, readed, 4, *(int32_t*)data+readed);
					readed+=4;
					proto_item_set_text(
						proto_tree_add_item(packet_tree, proto_mcpc, tvb, readed, 1, FALSE),
						"Gamemode: %hhu", *(uint8_t*)(data+readed));
					readed+=1;
					proto_item_set_text(
						proto_tree_add_item(packet_tree, proto_mcpc, tvb, readed, 4, FALSE),
						"Dimension: %d", *(int32_t*)(data+readed));
					readed+=4;
					proto_tree_add_uint(packet_tree, hf_difficulty, tvb, readed, 1, *(uint8_t*)(data+readed));
					readed+=1;
					proto_item_set_text(
						proto_tree_add_item(packet_tree, proto_mcpc, tvb, readed, 1, FALSE),
						"Max Players: %hhu", *(uint8_t*)(data+readed));
					readed+=1;
					CUSTOM_STR_TO_TREE("Level Type: %s");
					proto_item_set_text(
						proto_tree_add_item(packet_tree, proto_mcpc, tvb, readed, 1, FALSE),
						"Reduced Debug Info: %s", *(uint8_t*)(data+readed) ? "true" : "false");
					break;
			}
		}
}

void tree_server_login(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo, const void *data, guint length){
	guint readed;
	uint32_t varint;
	int8_t varlen;
	readed=varlen=VarIntToUint(data, &varint, length);//PacketID
	if(varlen>0){
		proto_tree_add_uint(packet_tree, hf_protocol_packetid_sb_login, tvb, 0, varlen, varint);
		switch(varint){
			case PID_SB_LOGIN_START:
				STR_TO_TREE(hf_player_name);
				break;
		}
	}
}
void tree_client_login(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo, const void *data, guint length){
	guint readed;
	uint32_t varint;
	int8_t varlen;
	readed=varlen=VarIntToUint(data, &varint, length);//PacketID
	if(varlen>0){
		proto_tree_add_uint(packet_tree, hf_protocol_packetid_cb_login, tvb, 0, varlen, varint);
		switch(varint){
			case PID_CB_LOGIN_SUCCESS:
				varlen=VarIntToUint(data+readed, &varint, length);//String length

				STR_TO_TREE(hf_uuid);

				STR_TO_TREE(hf_player_name);
				break;
			case PID_CB_LOGIN_SET_COMPRESSION:
				varlen=VarIntToUint(data+readed, &varint, length);//Threshold
				proto_tree_add_int(packet_tree, hf_compression_trxld, tvb, readed, varlen, (int32_t)varint);
				break;
		}
	}
}

void tree_server_handshake(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const void *data, guint length){
	guint readed;
	uint32_t varint;
	int8_t varlen;
	readed=varlen=VarIntToUint(data, &varint, length);//PacketID
	if(varlen>0){
		proto_tree_add_uint(packet_tree, hf_protocol_packetid_sb_hs, tvb, 0, varlen, varint);
		switch(varint){
			case 0x00:
				varlen=VarIntToUint(data+readed, &varint, length-readed);//Protocol version
				proto_tree_add_uint(packet_tree, hf_protocol_version, tvb, readed, varlen, varint);
				readed+=varlen;

				varlen=VarIntToUint(data+readed, &varint, length-readed);//String length
				proto_tree_add_uint(packet_tree, hf_string_length, tvb, readed, varlen, varint);
				readed+=varlen;

				gchar *addr=wmem_alloc(pinfo->pool, varint+1);
				memcpy(addr, data+readed, varint);
				addr[varint]=0x00;
				readed+=varint;

				proto_item_set_text(
					proto_tree_add_item(packet_tree, hf_server_address, tvb, readed-varint, varint+2, FALSE),
					"Address: %s:%hu", addr, g_ntohs(*(uint16_t*)(data+readed)));
				readed+=2;//Skip short

				varlen=VarIntToUint(data+readed, &varint, length-readed);//Next State
				proto_tree_add_uint(packet_tree, hf_hs_next_state, tvb, readed, varlen, varint);
				break;
		}
	}
	return;
}


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
