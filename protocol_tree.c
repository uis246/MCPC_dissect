#include "protocol_constants.h"
#include "protocol_tree.h"
#include "protocol_tree_internal.h"
#include "protocol.h"

#include <epan/packet.h>

int
	ett_strlen=-1,
	ett_metadata=-1;

int
	hf_string_length=-1,
	hf_player_name=-1,
	hf_uuid=-1,
	hf_compression_trxld=-1,
	hf_protocol_version=-1,
	hf_hs_next_state=-1,
	hf_server_address=-1,
	hf_entity_id=-1,
	hf_difficulty=-1,
	hf_resourcepack_state=-1,
	hf_channel_name=-1,
	hf_chunk_x=-1,
	hf_chunk_z=-1,
	hf_pos_x=-1,
	hf_pos_y=-1,
	hf_pos_z=-1,
	hf_metadata=-1,
	hf_metadata_index=-1,
	hf_metadata_type=-1;

void tree_register_fields(void) {
	static gint *ett[] = { &ett_strlen, &ett_metadata };
	static hf_register_info hf[] = {
		{ &hf_string_length,
			{
				"String length", "mcpc.string.length",
				FT_UINT8, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{ &hf_uuid,
			{
				"UUID", "mcpc.player.uuid",
				FT_STRING, STR_ASCII,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{ &hf_player_name,
			{
				"Player name", "mcpc.player.name",
				FT_STRING, STR_ASCII,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{ &hf_compression_trxld,
			{
				"Compression treshold", "mcpc.trxld",
				FT_INT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{ &hf_protocol_version,
			{
				"Protocol version", "mcpc.protocol.version",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{ &hf_hs_next_state,
			{
				"Next state", "mcpc.handshake.nextstate",
				FT_UINT16, BASE_DEC,
				VALS(states), 0x0,
				NULL, HFILL
			}
		},
		{ &hf_server_address,
			{
				"Server address", "mcpc.address",
				FT_STRING, STR_ASCII,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{ &hf_entity_id,
			{
				"Entity ID", "mcpc.entity.id",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{ &hf_difficulty,
			{
				"Difficulty", "mcpc.difficulty",
				FT_UINT8, BASE_DEC,
				VALS(difficulty_levels), 0x0,
				NULL, HFILL
			}
		},
		{ &hf_resourcepack_state,
			{
				"Resource Pack Status", "mcpc.resourcepack.status",
				FT_UINT8, BASE_DEC,
				VALS(resourcepack_status), 0x0,
				NULL, HFILL
			}
		},
		{ &hf_channel_name,
			{
				"Channel name", "mcpc.channel",
				FT_STRING, STR_ASCII,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{ &hf_chunk_x,
			{
				"Chunk X", "mcpc.chunk.x",
				FT_INT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{ &hf_chunk_z,
			{
				"Chunk Z", "mcpc.chunk.z",
				FT_INT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{ &hf_pos_x,
			{
				"X coordinate", "mcpc.coord.x",
				FT_DOUBLE, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{ &hf_pos_y,
			{
				"Y coordinate", "mcpc.coord.y",
				FT_DOUBLE, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{ &hf_pos_z,
			{
				"Z coordinate", "mcpc.coord.z",
				FT_DOUBLE, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{ &hf_metadata,
			{
				"Metadata", "mcpc.metadata",
				FT_NONE, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{ &hf_metadata_index,
			{
				"Metadata index", "mcpc.metadata.index",
				FT_UINT8, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{ &hf_metadata_type,
			{
				"Metadata type", "mcpc.metadata.type",
				FT_UINT32, BASE_DEC,
				VALS(metadata_types), 0x0,
				NULL, HFILL
			}
		}
	};
	proto_register_field_array(proto_mcpc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void tree_server_slp(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const void *data, guint length){
	uint32_t varint;
	int8_t varlen;
	varlen=VarIntToUint(data, &varint, length);//PacketID
	if(varlen>0){
		proto_item_append_text(proto_tree_get_parent(proto_tree_get_parent_tree(packet_tree)), ", PID: 0x%X", varint);
		proto_tree_add_uint(packet_tree, hf_protocol_packetid_sb_slp, tvb, 0, varlen, varint);
	}
}
void tree_client_slp(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo, const void *data, guint length){
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
					"Response: %s:%hu", addr, g_ntohs(*(const uint16_t*)(data+readed)));
				break;
		}
	}
}

void tree_server_login(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const void *data, guint length){
	guint readed;
	uint32_t varint;
	int8_t varlen;
	readed=varlen=VarIntToUint(data, &varint, length);//PacketID
	if(varlen>0){
		proto_item_append_text(proto_tree_get_parent(proto_tree_get_parent_tree(packet_tree)), ", PID: 0x%X", varint);
		proto_tree_add_uint(packet_tree, hf_protocol_packetid_sb_login, tvb, 0, varlen, varint);
		switch(varint){
			case PID_SB_LOGIN_START:
				STR_TO_TREE(packet_tree, hf_player_name);
				break;
		}
	}
}
void tree_client_login(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const void *data, guint length){
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

				STR_TO_TREE(packet_tree, hf_uuid);

				STR_TO_TREE(packet_tree, hf_player_name);
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
					"Address: %s:%hu", addr, be16toh(*(const uint16_t*)(data+readed)));
				readed+=2;//Skip short

				varlen=VarIntToUint(data+readed, &varint, length-readed);//Next State
				proto_tree_add_uint(packet_tree, hf_hs_next_state, tvb, readed, varlen, varint);
				break;
		}
	}
	return;
}
