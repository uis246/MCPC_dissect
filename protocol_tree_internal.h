#pragma once

#include "mcpc.h"

extern int
	hf_string_length,
	hf_player_name,
	hf_uuid,
	hf_compression_trxld,
	hf_protocol_version,
	hf_hs_next_state,
	hf_server_address,
	hf_entity_id,
	hf_difficulty,
	hf_resourcepack_state,
	hf_channel_name,
	hf_chunk_x,
	hf_chunk_z,
	hf_pos_x,
	hf_pos_y,
	hf_pos_z,
	hf_metadata,
	hf_metadata_index,
	hf_metadata_type,
	hf_size,
	hf_primary_bit_mask,
	hf_bits_per_block,
	hf_section_number,
	hf_palette,
	hf_palette_length;

#define CUSTOM_STR_TO_TREE(tree, format)	varlen=VarIntToUint(data+readed, &varint, length-readed);\
																				{gchar *name=wmem_alloc(wmem_packet_scope(), varint+1);\
                                                                                memcpy(name, data+readed+varlen, varint);\
                                                                                name[varint]=0x00;\
																				proto_item *string_item=proto_tree_add_item(tree, proto_mcpc, tvb, readed, varint+varlen, FALSE);\
																				proto_item_set_text(string_item, format, name);\
                                                                                proto_tree_add_uint(\
																						proto_item_add_subtree(string_item, ett_strlen),\
																						hf_string_length, tvb, (gint)readed, varlen, varint);\
                                                                                \
																				wmem_free(wmem_packet_scope(), name);}\
																				readed+=varlen+varint


#define STR_TO_TREE(tree, to_hf)			varlen=VarIntToUint(data+readed, &varint, length-readed);\
												{gchar *name=wmem_alloc(wmem_packet_scope(), varint+1);\
												memcpy(name, data+readed+varlen, varint);\
												name[varint]=0x00;\
												proto_tree_add_uint(\
												proto_item_add_subtree(\
													proto_tree_add_string(tree, to_hf, tvb, readed, varint+varlen, name),\
														ett_strlen),\
													hf_string_length, tvb, (gint)readed, varlen, varint);\
												wmem_free(wmem_packet_scope(), name);}\
											readed+=varlen+varint

#define POS_TO_TREE(tree)					proto_tree_add_double(tree, hf_pos_x, tvb, readed, 8, (double)be64toh(*(const uint64_t*)(data+readed)));\
											readed+=8;\
											proto_tree_add_double(tree, hf_pos_y, tvb, readed, 8, (double)be64toh(*(const uint64_t*)(data+readed)));\
											readed+=8;\
											proto_tree_add_double(tree, hf_pos_z, tvb, readed, 8, (double)be64toh(*(const uint64_t*)(data+readed)));\
											readed+=8

//Skip UUID
#define UUID_TO_TREE(tree)					readed+=16
