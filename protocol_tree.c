#include "protocol_constants.h"
#include "protocol_tree.h"
#include "protocol_tree_internal.h"
#include "protocol.h"


void tree_server_slp(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const void *data, guint length){
	uint32_t varint;
	int8_t varlen;
	varlen=VarIntToUint(data, &varint, length);//PacketID
	if(varlen>0){
		proto_item_append_text(proto_tree_get_parent(proto_tree_get_parent_tree(packet_tree)), ", PID: 0x%X", varint);
		proto_tree_add_uint(packet_tree, hf_protocol_packetid_sb_slp, tvb, 0, varlen, varint);
	}
}
void tree_client_slp(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const void *data, guint length){
	guint readed;
	uint32_t varint;
	int8_t varlen;
	readed=varlen=VarIntToUint(data, &varint, length);//PacketID
	if(varlen>0){
		proto_item_append_text(proto_tree_get_parent(proto_tree_get_parent_tree(packet_tree)), ", PID: 0x%X", varint);
		proto_tree_add_uint(packet_tree, hf_protocol_packetid_cb_slp, tvb, 0, varlen, varint);
		switch(varint){
			case 0x00:
				varlen=VarIntToUint(data+readed, &varint, length-readed);//String length
				proto_tree_add_uint(packet_tree, hf_string_length, tvb, readed, varlen, varint);
				readed+=varlen;

				gchar *addr=wmem_alloc(pinfo->pool, varint+1);
				memcpy(addr, data+readed, varint);
				addr[varint]=0x00;
				readed+=varint;

				proto_item_set_text(
					proto_tree_add_item(packet_tree, hf_server_address, tvb, readed-varint, varint+2, FALSE),
					"Response: %s:%hu", addr, g_ntohs(*(uint16_t*)(data+readed)));
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
		proto_item_append_text(proto_tree_get_parent(proto_tree_get_parent_tree(packet_tree)), ", PID: 0x%X", varint);
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
		proto_item_append_text(proto_tree_get_parent(proto_tree_get_parent_tree(packet_tree)), ", PID: 0x%X", varint);
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
		proto_item_append_text(proto_tree_get_parent(proto_tree_get_parent_tree(packet_tree)), ", PID: 0x%X", varint);
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
					"Address: %s:%hu", addr, be16toh(*(uint16_t*)(data+readed)));
				readed+=2;//Skip short

				varlen=VarIntToUint(data+readed, &varint, length-readed);//Next State
				proto_tree_add_uint(packet_tree, hf_hs_next_state, tvb, readed, varlen, varint);
				break;
		}
	}
	return;
}
