//#include <stdio.h>

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdint.h>
#include <stdio.h>

#include <epan/prefs.h>
#include <epan/packet.h>
#include <epan/proto_data.h>
#include <epan/column-info.h>
#include <epan/dissectors/packet-tcp.h>
#include <ws_version.h>

#include <epan/wmem/wmem.h>

#ifndef ENABLE_STATIC
WS_DLL_PUBLIC_DEF const gchar plugin_version[] = "0.0.3";
WS_DLL_PUBLIC_DEF const gchar plugin_release[] = VERSION;//e.g. "3.2"
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;
#endif

#define PROTO_PORT 25565
#define PROTO_TAG "MCPC"
#define PROTO_TAG_PARTIAL "MCPC partial"

#include "protocol.h"
#include "protocol_tree.h"
#include "protocol_constants.h"



static int
	ett_mcpc=-1,
	ett_proto=-1;
int
	ett_strlen=-1;
static dissector_handle_t mcpc_handle, conv_handle, ignore_handle;

static int
	hf_packet_length=-1,
	hf_packet_data_length=-1;
int proto_mcpc=-1;
int
	hf_protocol_packetid_sb=-1,
	hf_protocol_packetid_cb=-1,
	hf_protocol_packetid_sb_hs=-1,
	hf_protocol_packetid_sb_login=-1,
	hf_protocol_packetid_cb_login=-1,
	hf_protocol_packetid_sb_slp=-1,
	hf_protocol_packetid_cb_slp=-1;
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
	hf_chunk_z=-1;

int8_t VarIntToUint(const guint8 *varint, uint32_t *result, guint maxlen){
	int8_t i=0;
	*result=0;
	do{
		if(i>5)
			return -1;
		if((guint)i>maxlen)
			return -1;
		*result |= (varint[i]&0x7F) << (i*7);
	}while((varint[i++]&0x80) != 0);
	return i;
}

static guint getlen(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data _U_){
	int ret;
	uint32_t len;
	guint packet_length;

	packet_length=tvb_reported_length(tvb);//To read
	if(packet_length==0)
		return 0;
//		return tvb_captured_length(tvb);

	const guint8 *dt;
	dt=tvb_get_ptr(tvb, offset, packet_length-offset);
	ret=VarIntToUint(dt, &len, packet_length-offset);
	if(ret==-1){//Invalidate
		conversation_t *conv;
		mcpc_protocol_context *ctx;
		col_add_str(pinfo->cinfo, COL_INFO, "[INVALID] Failed to parse payload length");
		conv=find_or_create_conversation(pinfo);
		ctx=conversation_get_proto_data(conv, proto_mcpc);
		ctx->state=STATE_INVALID;
		conversation_set_dissector(conv, ignore_handle);
		return 0;
	}else
		return len+ret;
}

static void subdissect_mcpc_proto(guint length, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, mcpc_protocol_context *ctx, gboolean visited){
	const guint8 *dat;
	dat=tvb_get_ptr(tvb, pinfo->desegment_offset, length);

	if(visited){
		if(tree){
			if(pinfo->destport==25565){
				switch (ctx->state) {
					case STATE_PLAY:
						tree_server_play(tree, tvb, pinfo, dat, length);
						break;
					case STATE_LOGIN:
						tree_server_login(tree, tvb, pinfo, dat, length);
						break;
					case STATE_HANDSHAKE:
						tree_server_handshake(tree, tvb, pinfo, dat, length);
						break;
					case STATE_SLP:
						tree_server_slp(tree, tvb, pinfo, dat, length);
						break;
				}
			}else{
				switch (ctx->state) {
					case STATE_PLAY:
						tree_client_play(tree, tvb, pinfo, dat, length);
						break;
					case STATE_LOGIN:
						tree_client_login(tree, tvb, pinfo, dat, length);
						break;
					case STATE_SLP:
						tree_client_slp(tree, tvb, pinfo, dat, length);
						break;
				}
			}
		}
		return;
	}else{
		if(pinfo->destport==25565){
			switch (ctx->state) {
				case STATE_PLAY:
					return;
				case STATE_LOGIN:
					if(tree)
						tree_server_login(tree, tvb, pinfo, dat, length);
//						proto_tree_add_uint(packet_item, hf_protocol_packetid_sb_login, tvb, base_offset, varlen, varint);
					return;
				case STATE_HANDSHAKE:
					if(parse_server_handshake(dat, length, ctx)==-1)
						break;
					if(tree)
						tree_server_handshake(tree, tvb, pinfo, dat, length);
					return;
				case STATE_SLP:
					col_add_str(pinfo->cinfo, COL_INFO, "[SLP]");
					return;
				}
		}else{
			switch (ctx->state) {
				case STATE_PLAY:
					return;
				case STATE_LOGIN:
					if(parse_client_login(dat, length, ctx)==-1)
						break;
					if(tree)
						tree_client_login(tree, tvb, pinfo, dat, length);
					return;
				case STATE_SLP:
					col_add_str(pinfo->cinfo, COL_INFO, "[SLP]");
					return;
			}
		}
	}
		col_add_str(pinfo->cinfo, COL_INFO, "[INVALID]");
	if(!visited){
		ctx->state=STATE_INVALID;
		conversation_t *conv;
		conv=find_or_create_conversation(pinfo);
		conversation_set_dissector(conv, ignore_handle);
	}
}

static int subdissect_mcpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_){
	mcpc_protocol_context *ctx;
	proto_item *packet_item;
	proto_tree *mcpc_tree, *sub_mcpc_tree;
	const guint8 *dt;
	guint packet_length;
	gint readed;
	uint32_t protocol_length, varint;
	guint8 protocol_length_length;
	gint8 varlen;
	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG);//Set MCPC protocol tag

	pinfo->fd->subnum++;

	if(pinfo->fd->visited){
		ctx=p_get_proto_data(wmem_file_scope(), pinfo, proto_mcpc, pinfo->fd->subnum);
	}else{
		conversation_t *conv;
		conv=find_or_create_conversation(pinfo);
		ctx=conversation_get_proto_data(conv, proto_mcpc);
		mcpc_protocol_context *save;
		save=wmem_alloc(wmem_file_scope(), sizeof(mcpc_protocol_context));
		*save=*ctx;
		p_add_proto_data(wmem_file_scope(), pinfo, proto_mcpc, pinfo->fd->subnum, save);
	}

	packet_length=tvb_reported_length(tvb);//To read

	dt=tvb_get_ptr(tvb, pinfo->desegment_offset, packet_length);

	protocol_length_length=readed=VarIntToUint(dt, &protocol_length, packet_length);

	col_append_fstr(pinfo->cinfo, COL_INFO, " %u bytes", protocol_length+protocol_length_length);

	if(tree){
		proto_item *ti;

		ti = proto_tree_add_item(tree, proto_mcpc, tvb, 0, -1, FALSE);
		mcpc_tree = proto_item_add_subtree(ti, ett_mcpc);
		proto_tree_add_uint(mcpc_tree, hf_packet_length, tvb, 0, protocol_length_length, packet_length);
		proto_item_append_text(ti, ", state: %d, len: %u", ctx->state, protocol_length+protocol_length_length);
	}

	tvbuff_t *new_tvb;
	if(ctx->compressTrxld<0){
		new_tvb=tvb_new_subset_remaining(tvb, protocol_length_length);
		if(tree){
			packet_item=proto_tree_add_item(mcpc_tree, proto_mcpc, new_tvb, 0, -1, FALSE);
			proto_item_set_text(packet_item, "MC:JE packet");
			sub_mcpc_tree=proto_item_add_subtree(packet_item, ett_proto);
		}else
			sub_mcpc_tree=NULL;
		subdissect_mcpc_proto(protocol_length, new_tvb, pinfo, sub_mcpc_tree, ctx, pinfo->fd->visited);
	}else{
		varlen=VarIntToUint(dt+protocol_length_length, &varint, packet_length-readed);
		if(varlen<0)
			return 0;

		if(tree)
			proto_tree_add_uint(mcpc_tree, hf_packet_data_length, tvb, readed, varlen, varint);
		readed+=varlen;

		if((int32_t)varint>0){
			new_tvb=tvb_uncompress(tvb, readed, packet_length-readed);//Decompress
			if(new_tvb==NULL)
				return 0;
			add_new_data_source(pinfo, new_tvb, "Uncompressed packet");
		}else{
			new_tvb=tvb_new_subset_remaining(tvb, readed);
		}

		if(tree){
			packet_item=proto_tree_add_item(mcpc_tree, proto_mcpc, new_tvb, 0, -1, FALSE);
			proto_item_set_text(packet_item, "MC:JE packet");
			sub_mcpc_tree=proto_item_add_subtree(packet_item, ett_proto);
		}else
			sub_mcpc_tree=NULL;
		subdissect_mcpc_proto(tvb_captured_length(new_tvb), new_tvb, pinfo, sub_mcpc_tree, ctx, pinfo->fd->visited);
	}

	return tvb_captured_length(tvb);
//	return protocol_length;
}
static int conv_dissect_mcpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data){
	if(pinfo->destport==25565)
		col_set_str(pinfo->cinfo, COL_INFO, "[C->S]");
	else
		col_set_str(pinfo->cinfo, COL_INFO, "[S->C]");

	pinfo->fd->subnum=0;
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 0,
					 getlen, subdissect_mcpc, data);
	return tvb_captured_length(tvb);
}

static int dissect_mcpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data){
	conversation_t *conv;
	mcpc_protocol_context *ctx;
	conv=find_or_create_conversation(pinfo);
	ctx=conversation_get_proto_data(conv, proto_mcpc);
	if(!ctx){
		ctx=wmem_alloc(wmem_file_scope(), sizeof(mcpc_protocol_context));
		ctx->compressTrxld=-1;
		ctx->state=STATE_HANDSHAKE;
		conversation_add_proto_data(conv, proto_mcpc, ctx);
		conversation_set_dissector(conv, conv_handle);
	}
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 0,
					 getlen, subdissect_mcpc, data);
	return tvb_captured_length(tvb);
}

static int dissect_ignore(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data){
	conversation_t *conv;
	mcpc_protocol_context *ctx;

	pinfo->fd->subnum=0;
	conv=find_or_create_conversation(pinfo);
	if(!(ctx=p_get_proto_data(wmem_file_scope(), pinfo, proto_mcpc, pinfo->fd->subnum)))
		ctx=conversation_get_proto_data(conv, proto_mcpc);

	if(ctx->state==STATE_INVALID){
		col_add_str(pinfo->cinfo, COL_INFO, "[INVALID] before");
	}else{
		tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 0,
						 getlen, subdissect_mcpc, data);
	}
	return tvb_captured_length(tvb);
}

//Protocol register functions
static void proto_reg_handoff_mcpc(void){//Register dissector
	mcpc_handle =	create_dissector_handle(dissect_mcpc, proto_mcpc);
	conv_handle =	create_dissector_handle(conv_dissect_mcpc, proto_mcpc);
	ignore_handle =	create_dissector_handle(dissect_ignore, proto_mcpc);
	dissector_add_uint("tcp.port", PROTO_PORT, mcpc_handle);
}
static void proto_register_mcpc(){
	static gint *ett[] = { &ett_mcpc, &ett_proto, &ett_strlen };
	static hf_register_info hf[] = {
		{ &hf_packet_length,
			{
				"Payload length", "mcpc.length",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{ &hf_packet_data_length,
			{
				"Uncompressed data length", "mcpc.data_length",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{ &hf_protocol_packetid_sb,
			{
				"Packet ID", "mcpc.packetid.serverbound",
				FT_UINT8, BASE_HEX,
				VALS(sbpackettypes), 0x0,
				NULL, HFILL
			}
		},
		{ &hf_protocol_packetid_cb,
			{
				"Packet ID", "mcpc.packetid.clientbound",
				FT_UINT8, BASE_HEX,
				VALS(cbpackettypes), 0x0,
				NULL, HFILL
			}
		},
		{ &hf_protocol_packetid_sb_hs,
			{
				"Packet ID(handshake)", "mcpc.packetid.serverbound.handshake",
				FT_UINT8, BASE_HEX,
				VALS(sbpackettypes_handshake), 0x0,
				NULL, HFILL
			}
		},
		{ &hf_protocol_packetid_sb_login,
			{
				"Packet ID(login)", "mcpc.packetid.serverbound.login",
				FT_UINT8, BASE_HEX,
				VALS(sbpackettypes_login), 0x0,
				NULL, HFILL
			}
		},
		{ &hf_protocol_packetid_cb_login,
			{
				"Packet ID(login)", "mcpc.packetid.clientbound.login",
				FT_UINT8, BASE_HEX,
				VALS(cbpackettypes_login), 0x0,
				NULL, HFILL
			}
		},
		{ &hf_protocol_packetid_sb_slp,
			{
				"Packet ID(SLP)", "mcpc.packetid.serverbound.status",
				FT_UINT8, BASE_HEX,
				VALS(sbpackettypes_slp), 0x0,
				NULL, HFILL
			}
		},
		{ &hf_protocol_packetid_cb_slp,
			{
				"Packet ID(SLP)", "mcpc.packetid.clientbound.status",
				FT_UINT8, BASE_HEX,
				VALS(cbpackettypes_slp), 0x0,
				NULL, HFILL
			}
		},
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
				FT_INT32, BASE_DEC,
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
		}
	};

	//Register protocol
	proto_mcpc = proto_register_protocol ("Minecraft: Java Edition", "Minecraft", "mcpc");

	//Register protocol fields
	proto_register_field_array(proto_mcpc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}


//Plugin register function
#ifndef ENABLE_STATIC
WS_DLL_PUBLIC void plugin_register(){
	/* register the new protocol, protocol fields, and subtrees */
	if (proto_mcpc == -1) { /* execute protocol initialization only once */
		static proto_plugin plug;
		plug.register_handoff=proto_reg_handoff_mcpc;
		plug.register_protoinfo=proto_register_mcpc;
		proto_register_plugin(&plug);
	}
}
#endif
