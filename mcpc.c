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
WS_DLL_PUBLIC_DEF const gchar plugin_version[] = "0.0.2-pre-b1";
WS_DLL_PUBLIC_DEF const gchar plugin_release[] = "3.2"; //VERSION_RELEASE
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;
#endif

#define PROTO_PORT 25565
#define PROTO_TAG "MCPC"
#define PROTO_TAG_PARTIAL "MCPC partial"

#include "protocol.h"




static int
	proto_mcpc=-1,
	ett_mcpc=-1,
	ett_proto=-1;
static dissector_handle_t mcpc_handle, conv_handle, ignore_handle;

static int
	hf_packet_length=-1,
	hf_packet_data_length=-1;
int
	hf_protocol_packetid_sb=-1,
	hf_protocol_packetid_cb=-1,
	hf_protocol_packetid_sb_hs=-1,
	hf_protocol_packetid_sb_login=-1,
	hf_protocol_packetid_cb_login=-1,
	hf_protocol_packetid_sb_slp=-1,
	hf_protocol_packetid_cb_slp=-1;

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

static guint getlen(packet_info *pinfo, tvbuff_t *tvb, int offset _U_, void *data _U_){
	int ret;
	uint32_t len;
	guint packet_length;
	packet_length=tvb_reported_length(tvb);//To read
	if(packet_length==0)
		return 0;
//		return tvb_captured_length(tvb);

	const guint8 *dt;
	dt=tvb_get_ptr(tvb, pinfo->desegment_offset, packet_length);
	ret=VarIntToUint(dt, &len, packet_length);
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

static void subdissect_mcpc_proto(guint length, tvbuff_t *tvb, packet_info *pinfo, proto_item *packet_item, mcpc_protocol_context *ctx, gboolean visited){
	proto_tree *packet_tree;
	const guint8 *dat;
	dat=tvb_get_ptr(tvb, pinfo->desegment_offset, length);
	if(packet_item)
		packet_tree=proto_item_add_subtree(packet_item, ett_proto);
	else
		packet_tree=NULL;

	if(visited){
		if(packet_tree){
			if(pinfo->destport==25565){
				switch (ctx->state) {
					case STATE_PLAY:
						break;;
					case STATE_LOGIN:
						tree_server_login(packet_tree, tvb, dat, length);
						break;
					case STATE_HANDSHAKE:
						tree_server_handshake(packet_tree, tvb, dat, length);
						break;
				}
			}else{
				switch (ctx->state) {
					case STATE_PLAY:
						break;;
					case STATE_LOGIN:
						tree_client_login(packet_tree, tvb, dat, length);
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
//					if(packet_tree)
//						proto_tree_add_uint(packet_tree, hf_protocol_packetid_sb_login, tvb, base_offset, varlen, varint);
					return;
				case STATE_HANDSHAKE:
					if(parse_server_handshake(dat, length, ctx)==-1)
						break;
					if(packet_tree)
						tree_server_handshake(packet_tree, tvb, dat, length);
					return;
				}
		}else{
			return;
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
	conversation_t *conv;
	mcpc_protocol_context *ctx;
	proto_item *packet_item;
	const guint8 *dt;
	guint packet_length;
	gint readed;
	uint32_t protocol_length;
	guint8 packet_length_length;
	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG);//Set MCPC protocol tag

	conv=find_or_create_conversation(pinfo);
	if(pinfo->fd->visited)
		ctx=p_get_proto_data(wmem_file_scope(), pinfo, proto_mcpc, pinfo->curr_layer_num);
	else{
		ctx=conversation_get_proto_data(conv, proto_mcpc);
		mcpc_protocol_context *save;
		save=wmem_alloc(wmem_file_scope(), sizeof(mcpc_protocol_context));//
		*save=*ctx;
		p_add_proto_data(wmem_file_scope(), pinfo, proto_mcpc, pinfo->curr_layer_num, save);
	}

	packet_length=tvb_reported_length(tvb);//To read

	dt=tvb_get_ptr(tvb, pinfo->desegment_offset, packet_length);

	packet_length_length=readed=VarIntToUint(dt, &protocol_length, packet_length);
	if(readed<0){
		return -1;
	}

	if(pinfo->destport==25565)
		col_add_fstr(pinfo->cinfo, COL_INFO, "Result: [C->S] %u bytes", protocol_length+packet_length_length);
	else
		col_add_fstr(pinfo->cinfo, COL_INFO, "Result: [S->C] %u bytes", protocol_length+packet_length_length);

	if(tree){
		proto_item *ti;
		proto_tree *mcpc_tree;

		ti = proto_tree_add_item(tree, proto_mcpc, tvb, 0, -1, FALSE);
		mcpc_tree = proto_item_add_subtree(ti, ett_mcpc);
		proto_tree_add_uint(mcpc_tree, hf_packet_length, tvb, 0, packet_length_length, packet_length);
		proto_item_append_text(ti, ", State: %d", ctx->state);
	}

	tvbuff_t *new_tvb;
	if(ctx->compressTrxld<0){
		if(tree){
			packet_item=proto_tree_add_item(tree, proto_mcpc, tvb, packet_length_length, -1, FALSE);
			proto_item_set_text(packet_item, "MC:JE packet");
		}else
			packet_item=NULL;
		new_tvb=tvb_new_subset_remaining(tvb, packet_length_length);
		subdissect_mcpc_proto(protocol_length, new_tvb, pinfo, packet_item, ctx, pinfo->fd->visited);
	}else{
		col_set_str(pinfo->cinfo, COL_INFO, "[COMPRESSED]");
		//Decompress
	}

	return tvb_captured_length(tvb);
//	return protocol_length;
}
static int conv_dissect_mcpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data){
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

static int dissect_ignore(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_, void *data _U_){
	col_add_str(pinfo->cinfo, COL_INFO, "[INVALID] before");
	return 0;
}

//Protocol register functions
static void proto_reg_handoff_mcpc(void){//Register dissector
	mcpc_handle =	create_dissector_handle(dissect_mcpc, proto_mcpc);
	conv_handle =	create_dissector_handle(conv_dissect_mcpc, proto_mcpc);
	ignore_handle =	create_dissector_handle(dissect_ignore, proto_mcpc);
	dissector_add_uint("tcp.port", PROTO_PORT, mcpc_handle);
}
static void proto_register_mcpc(){
	static gint *ett[] = { &ett_mcpc, &ett_proto };
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
				"Packet ID", "mcpc.protocol.packetid.serverbound",
				FT_UINT8, BASE_DEC,
				VALS(sbpackettypes), 0x0,
				NULL, HFILL
			}
		},
		{ &hf_protocol_packetid_cb,
			{
				"Packet ID", "mcpc.protocol.packetid.clientbound",
				FT_UINT8, BASE_DEC,
				VALS(cbpackettypes), 0x0,
				NULL, HFILL
			}
		},
		{ &hf_protocol_packetid_sb_hs,
			{
				"Packet ID(handshake)", "mcpc.protocol.packetid.serverbound.handshake",
				FT_UINT8, BASE_DEC,
				VALS(sbpackettypes_handshake), 0x0,
				NULL, HFILL
			}
		},
		{ &hf_protocol_packetid_sb_login,
			{
				"Packet ID(login)", "mcpc.protocol.packetid.serverbound.login",
				FT_UINT8, BASE_DEC,
				VALS(sbpackettypes_login), 0x0,
				NULL, HFILL
			}
		},
		{ &hf_protocol_packetid_cb_login,
			{
				"Packet ID(login)", "mcpc.protocol.packetid.clientbound.login",
				FT_UINT8, BASE_DEC,
				VALS(cbpackettypes_login), 0x0,
				NULL, HFILL
			}
		},
		{ &hf_protocol_packetid_sb_slp,
			{
				"Packet ID(SLP)", "mcpc.protocol.packetid.serverbound.status",
				FT_UINT8, BASE_DEC,
				VALS(sbpackettypes_slp), 0x0,
				NULL, HFILL
			}
		},
		{ &hf_protocol_packetid_cb_slp,
			{
				"Packet ID(SLP)", "mcpc.protocol.packetid.clientbound.status",
				FT_UINT8, BASE_DEC,
				VALS(cbpackettypes_slp), 0x0,
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
