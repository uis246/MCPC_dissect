#include "protocol.h"
#include "protocol_constants.h"
#include "protocol_tree.h"
#include "protocol_tree_internal.h"

static guint add_metadata(proto_tree *packet_tree, tvbuff_t *tvb, const void *data, guint length, guint readed);

#define HANDLER_ARGS proto_tree *packet_tree, tvbuff_t *tvb, const void *data, guint length, guint readed
#define HANDLER(func) static void func(HANDLER_ARGS)

typedef void (*play_handler)(HANDLER_ARGS);

HANDLER(sb_respack_stat) {
	int8_t varlen;
	uint32_t varint;
	varlen=VarIntToUint(data, &varint, length);
	proto_tree_add_uint(packet_tree, hf_resourcepack_state, tvb, (gint)readed, varlen, varint);
}

HANDLER(sb_plugin_channel) {
	int8_t varlen;
	uint32_t varint;
	STR_TO_TREE(packet_tree, hf_channel_name);
}

HANDLER(cb_join) {
	int8_t varlen;
	uint32_t varint;
	proto_tree_add_uint(packet_tree, hf_entity_id, tvb, (gint)readed, 4, be32toh(*(const uint32_t*)(data+readed)));
	readed+=4;
	proto_item_set_text(
		proto_tree_add_item(packet_tree, proto_mcpc, tvb, (gint)readed, 1, FALSE),
		"Gamemode: %hhu", *(const uint8_t*)(data+readed));
	readed+=1;
	proto_item_set_text(
		proto_tree_add_item(packet_tree, proto_mcpc, tvb, (gint)readed, 4, FALSE),
		"Dimension: %d", be32toh(*(const int32_t*)(data+readed)));
	readed+=4;
	proto_tree_add_uint(packet_tree, hf_difficulty, tvb, (gint)readed, 1, *(const uint8_t*)(data+readed));
	readed+=1;
	proto_item_set_text(
		proto_tree_add_item(packet_tree, proto_mcpc, tvb, (gint)readed, 1, FALSE),
		"Max Players: %hhu", *(const uint8_t*)(data+readed));
	readed+=1;
	CUSTOM_STR_TO_TREE(packet_tree, "Level Type: %s");
	proto_item_set_text(
		proto_tree_add_item(packet_tree, proto_mcpc, tvb, (gint)readed, 1, FALSE),
		"Reduced Debug Info: %s", *(const uint8_t*)(data+readed) ? "true" : "false");
}

HANDLER(cb_entity_metadata) {
	int8_t varlen;
	uint32_t varint;
	varlen=VarIntToUint(data+readed, &varint, length-(guint)readed);
	proto_tree_add_uint(packet_tree, hf_entity_id, tvb, (gint)readed, varlen, varint);
	readed+=varlen;
	add_metadata(packet_tree, tvb, data, length, readed);
}

HANDLER(cb_spawn_player) {
	int8_t varlen;
	uint32_t varint;
	varlen=VarIntToUint(data+readed, &varint, length-(guint)readed);
	proto_tree_add_uint(packet_tree, hf_entity_id, tvb, (gint)readed, varlen, varint);
	readed+=varlen;//Entity ID
	UUID_TO_TREE(packet_tree);//UUID
	POS_TO_TREE(packet_tree);//XYZ
	readed+=2;//Skip rotation
	add_metadata(packet_tree, tvb, data, length, readed);
}

HANDLER(cb_chunk_data) {
	int8_t varlen;
	uint32_t varint;

	//Chunk coo
	proto_tree_add_int(packet_tree, hf_chunk_x, tvb, (gint)readed, 4, be32toh(*(const uint32_t*)(data+readed)));
	readed+=4;
	proto_tree_add_int(packet_tree, hf_chunk_z, tvb, (gint)readed, 4, be32toh(*(const uint32_t*)(data+readed)));
	readed+=4;

	//GUC
	proto_item_set_text(
		proto_tree_add_item(packet_tree, proto_mcpc, tvb, (gint)readed, 1, FALSE),
		"Ground-Up Continuous: %s", *(const uint8_t*)(data+readed) ? "true" : "false");
	readed+=1;

	//PBM
	uint32_t pbm;
	varlen=VarIntToUint(data+readed, &pbm, length-(guint)readed);
	proto_tree_add_uint(packet_tree, hf_primary_bit_mask, tvb, (gint)readed, varlen, pbm);
	readed+=varlen;

	varlen=VarIntToUint(data+readed, &varint, length-(guint)readed);
	proto_tree_add_uint(packet_tree, hf_size, tvb, (gint)readed, varlen, varint);
	readed+=varlen;
	proto_item *data_item = proto_tree_add_item(packet_tree, proto_mcpc, tvb, (gint)readed, varint, FALSE);
	proto_item_set_text(data_item, "Data");
	proto_tree *data_tree = proto_item_add_subtree(data_item, 0);
	for(uint8_t i=0; i < 16; i++) {
		if(!(pbm >> i))
			break;
		else if (!((pbm >> i)&1))
			continue;

		uint32_t psz;
		guint sectionSize = 0;

		proto_item *section_item = proto_tree_add_uint(data_tree, hf_section_number, tvb, (gint)readed, (gint)sectionSize, i);
		proto_tree *section_tree = proto_item_add_subtree(section_item, 0);

		proto_tree_add_uint(section_tree, hf_bits_per_block, tvb, (gint)readed, 1, *(const uint8_t*)(data+readed));
		sectionSize+=1;

		varlen=VarIntToUint(data+readed+sectionSize, &psz, length-(guint)readed-sectionSize);
		proto_tree_add_uint(section_tree, hf_palette_length, tvb, (gint)(readed+sectionSize), varlen, psz);
		sectionSize+=varlen;
		if(psz!=0) {
			proto_item *palette= proto_tree_add_item(section_tree, hf_palette, tvb, (gint)(readed+sectionSize), varlen, ENC_NA);
			for(uint32_t pl=0; pl<psz; pl++) {
				varlen=VarIntToUint(data+readed+sectionSize, &varint, length-(guint)readed-sectionSize);
				sectionSize+=varlen;
			}
			proto_item_set_end(palette, tvb, (gint)(readed+sectionSize));
		}

		varlen=VarIntToUint(data+readed+sectionSize, &varint, length-(guint)readed-sectionSize);
		sectionSize+=varlen;

		sectionSize+=varint*8;//Skip blocks data
		sectionSize+=2048;//Skip block light
		//FIXME skylight only in overworld
		sectionSize+=2048;//Skip sky light


		readed+=sectionSize;
		proto_item_set_end(section_item, tvb, (gint)readed);
	}
}

HANDLER(cb_unload_chunk) {
	length;
	//Chunk coords
	proto_tree_add_int(packet_tree, hf_chunk_x, tvb, (gint)readed, 4, be32toh(*(const uint32_t*)(data+readed)));
	readed+=4;
	proto_tree_add_int(packet_tree, hf_chunk_z, tvb, (gint)readed, 4, be32toh(*(const uint32_t*)(data+readed)));
	readed+=4;
	
}

//Jump tables
static play_handler cb_340[0x50];
static play_handler sb_340[0x21];

void fill_table(void) {
	memset(cb_340, 0, sizeof(cb_340));
	cb_340[PID_CB_PLAY_SPAWN_PLAYER]=cb_spawn_player;
	cb_340[PID_CB_PLAY_UNLOAD_CHUNK]=cb_unload_chunk;
	cb_340[PID_CB_PLAY_CHUNK_DATA]=cb_chunk_data;
	cb_340[PID_CB_PLAY_JOIN_GAME]=cb_join;
	cb_340[PID_CB_PLAY_ENTITY_METADATA]=cb_entity_metadata;

	memset(sb_340, 0, sizeof(sb_340));
	sb_340[PID_SB_PLAY_RESOURCE_PACK_STAT]=sb_respack_stat;
	sb_340[PID_SB_PLAY_PLUGIN_MESSAGE]=sb_plugin_channel;
}



static guint add_metadata(proto_tree *packet_tree, tvbuff_t *tvb, const void *data, guint length, guint readed) {
	while(*((const uint8_t*)data+readed)!=0xFF) {
		proto_item *ti;
		proto_tree *metadata;
		uint32_t varint;
		int8_t varlen;
		ti=proto_tree_add_item(packet_tree, hf_metadata, tvb, (gint)readed, 0, ENC_NA);
		metadata=proto_item_add_subtree(ti, ett_metadata);

		const uint8_t index=*(const uint8_t*)(data+readed);
		proto_tree_add_uint(metadata, hf_metadata_index, tvb, (gint)readed, 1, index);
		proto_item_set_text(ti, "Metadata: %u", index);
		readed+=1;

		varlen=VarIntToUint(data+readed, &varint, length);
		proto_tree_add_uint(metadata, hf_metadata_type, tvb, (gint)readed, varlen, varint);
		readed+=varlen;//Type

		proto_item *value=proto_tree_add_item(metadata, proto_mcpc, tvb, (gint)readed, 0, ENC_NA);

		switch(varint) {
			case 0://Byte
				proto_item_set_len(value, 1);
				proto_item_set_text(value, "Byte: %u", *(const uint8_t*)(data+readed));
				readed+=1;
				break;
			case 1://VarInt
				varlen=VarIntToUint(data+readed, &varint, length);
				proto_item_set_len(value, varlen);
				proto_item_set_text(value, "VerInt: %u", varint);
				readed+=varlen;
				break;
			case 2: {//Float
				varint=be32toh(*(const uint32_t*)(data+readed));
				proto_item_set_len(value, 4);
				proto_item_set_text(value, "Float: %f", (double)*((float*)&varint));
				readed+=4;
				break;
			}
			case 3: {//String
				varlen=VarIntToUint(data+readed, &varint, length);
				{gchar *name=wmem_alloc(wmem_packet_scope(), varint+1);
				memcpy(name, data+readed+varlen, varint);
				name[varint]=0x00;
				proto_item_set_text(value, "String: %s", name);
				proto_tree_add_uint(
					proto_item_add_subtree(value, ett_strlen),
					hf_string_length, tvb, (gint)readed, varlen, varint);

				wmem_free(wmem_packet_scope(), name);}
				readed+=(uint)varlen+varint;
				break;
			}
			case 4://Chat
			case 5://Slot
				return -1;
			case 6://Boolean
				proto_item_set_len(value, 1);
				proto_item_set_text(value, "Boolean: %s", *(const uint8_t*)(data+readed) ? "true" : "false");
				readed+=1;
				break;
			case 7://Rotation
			case 8://Position
			case 9://OptPosition
			case 10://Direction(VarInt)
			case 11://OptUUID
			case 12://OptBlockID(VarInt)
			case 13://NBT tag
				return -1;

			default:
				return -1;//Stop parsing on unknown type
		}
		proto_item_set_end(value, tvb, (gint)readed);
		proto_item_set_end(ti, tvb, (gint)readed);
	}
	return readed;
}

void tree_server_play(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const void *data, guint length){
	guint readed;
	uint32_t varint;
	int8_t varlen;
	readed=varlen=VarIntToUint(data, &varint, length);//PacketID
	if(varlen>0){
		proto_item_append_text(proto_tree_get_parent(proto_tree_get_parent_tree(packet_tree)), ", PID: 0x%X", varint);
		proto_tree_add_uint(packet_tree, hf_protocol_packetid_sb, tvb, 0, varlen, varint);
		if (sb_340[varint]!=0) {
			sb_340[varint](packet_tree, tvb, data, length, readed);
			return;
		}
		switch(varint){
			case PID_SB_PLAY_POS_AND_VIEW:
				proto_tree_add_double(packet_tree, hf_pos_x, tvb, (gint)readed, 8, (double)be64toh(*(const uint64_t*)(data+readed)));
				readed+=8;
				proto_tree_add_double(packet_tree, hf_pos_y, tvb, (gint)readed, 8, (double)be64toh(*(const uint64_t*)(data+readed)));
				readed+=8;
				proto_tree_add_double(packet_tree, hf_pos_z, tvb, (gint)readed, 8, (double)be64toh(*(const uint64_t*)(data+readed)));
				readed+=8;
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
		proto_item_append_text(proto_tree_get_parent(proto_tree_get_parent_tree(packet_tree)), ", PID: 0x%X", varint);
		proto_tree_add_uint(packet_tree, hf_protocol_packetid_cb, tvb, 0, varlen, varint);
		if (cb_340[varint]!=0) {
			cb_340[varint](packet_tree, tvb, data, length, readed);
			return;
		}
		switch(varint){
			case PID_CB_PLAY_RESPAWN:
				proto_item_set_text(
					proto_tree_add_item(packet_tree, proto_mcpc, tvb, (gint)readed, 4, FALSE),
					"Dimension: %d", be32toh(*(const int32_t*)(data+readed)));
				readed+=4;
				proto_tree_add_uint(packet_tree, hf_difficulty, tvb, (gint)readed, 4, *(const uint8_t*)(data+readed));
				readed+=1;
				proto_item_set_text(
					proto_tree_add_item(packet_tree, proto_mcpc, tvb, (gint)readed, 1, FALSE),
					"Gamemode: %hhu", *(const uint8_t*)(data+readed));
				readed+=1;
				CUSTOM_STR_TO_TREE(packet_tree, "Level Type: %s");
				break;
			case PID_CB_PLAY_SERVER_DIFFICULTY:
				proto_tree_add_uint(packet_tree, hf_difficulty, tvb, (gint)readed, 4, *(const uint8_t*)(data+readed));
				readed+=1;
				break;
			case PID_CB_PLAY_RESOURCE_PACK_SEND:
				CUSTOM_STR_TO_TREE(packet_tree, "URL: %s");
				CUSTOM_STR_TO_TREE(packet_tree, "Hash (SHA-1): %s");
				break;
			case PID_CB_PLAY_PLUGIN_MESSAGE:
				STR_TO_TREE(packet_tree, hf_channel_name);
				break;
		}
	}
}
