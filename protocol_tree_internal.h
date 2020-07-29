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
	hf_difficulty,
	hf_resourcepack_state,
	hf_channel_name;
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
