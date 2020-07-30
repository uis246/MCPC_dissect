#include "protocol.h"
#include "protocol_constants.h"
#include "protocol_tree.h"
#include "protocol_tree_internal.h"

void tree_server_play(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const void *data, guint length){
	guint readed;
	uint32_t varint;
	int8_t varlen;
	readed=varlen=VarIntToUint(data, &varint, length);//PacketID
	if(varlen>0){
		proto_item_append_text(proto_tree_get_parent(proto_tree_get_parent_tree(packet_tree)), ", PID: %u", varint);
		proto_tree_add_uint(packet_tree, hf_protocol_packetid_sb, tvb, 0, varlen, varint);
		switch(varint){
			case PID_SB_PLAY_RESOURCE_PACK_STAT:
				varlen=VarIntToUint(data, &varint, length);
				proto_tree_add_int(packet_tree, hf_resourcepack_state, tvb, readed, 1, varint);
				break;
			case PID_SB_PLAY_PLUGIN_MESSAGE:
				STR_TO_TREE(hf_channel_name);
				break;
		}
	}
}
void tree_client_play(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const void *data, guint length){
	guint readed;
	uint32_t varint;
	int8_t varlen;
	readed=varlen=VarIntToUint(data, &varint, length);//PacketID
	if(varlen>0){
		proto_item_append_text(proto_tree_get_parent(proto_tree_get_parent_tree(packet_tree)), ", PID: %u", varint);
		proto_tree_add_uint(packet_tree, hf_protocol_packetid_cb, tvb, 0, varlen, varint);
		switch(varint){
			case PID_CB_PLAY_JOIN_GAME:
				proto_tree_add_int(packet_tree, hf_entity_id, tvb, readed, 4, be32toh(*(int32_t*)(data+readed)));
				readed+=4;
				proto_item_set_text(
					proto_tree_add_item(packet_tree, proto_mcpc, tvb, readed, 1, FALSE),
					"Gamemode: %hhu", *(uint8_t*)(data+readed));
				readed+=1;
				proto_item_set_text(
					proto_tree_add_item(packet_tree, proto_mcpc, tvb, readed, 4, FALSE),
					"Dimension: %d", be32toh(*(int32_t*)(data+readed)));
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
			case PID_CB_PLAY_RESPAWN:
				proto_item_set_text(
					proto_tree_add_item(packet_tree, proto_mcpc, tvb, readed, 4, FALSE),
					"Dimension: %d", be32toh(*(int32_t*)(data+readed)));
				readed+=4;
				proto_tree_add_int(packet_tree, hf_difficulty, tvb, readed, 4, *(uint8_t*)data+readed);
				readed+=1;
				proto_item_set_text(
					proto_tree_add_item(packet_tree, proto_mcpc, tvb, readed, 1, FALSE),
					"Gamemode: %hhu", *(uint8_t*)(data+readed));
				readed+=1;
				CUSTOM_STR_TO_TREE("Level Type: %s");
				break;
			case PID_CB_PLAY_SERVER_DIFFICULTY:
				proto_tree_add_int(packet_tree, hf_difficulty, tvb, readed, 4, *(uint8_t*)(data+readed));
				readed+=1;
				break;
			case PID_CB_PLAY_RESOURCE_PACK_SEND:
				CUSTOM_STR_TO_TREE("URL: %s");
				CUSTOM_STR_TO_TREE("Hash (SHA-1): %s");
				break;
			case PID_CB_PLAY_CHUNK_DATA:
				proto_item_set_text(
					proto_tree_add_item(packet_tree, proto_mcpc, tvb, readed, 1, FALSE),
					"Chunk X: %d", be32toh(*(int32_t*)(data+readed)));
				readed+=4;
				proto_item_set_text(
					proto_tree_add_item(packet_tree, proto_mcpc, tvb, readed, 1, FALSE),
					"Chunk Z: %d", be32toh(*(int32_t*)(data+readed)));
				readed+=4;
				proto_item_set_text(
					proto_tree_add_item(packet_tree, proto_mcpc, tvb, readed, 1, FALSE),
					"Ground-Up Continuous: %s", *(uint8_t*)(data+readed) ? "true" : "false");
				readed+=1;
				break;
			case PID_CB_PLAY_PLUGIN_MESSAGE:
				STR_TO_TREE(hf_channel_name);
				break;
		}
	}
}
