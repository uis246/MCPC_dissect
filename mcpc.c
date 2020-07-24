//#include <stdio.h>

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdint.h>
#include <epan/prefs.h>
#include <epan/packet.h>
#include <epan/column-info.h>
#include <epan/dissectors/packet-tcp.h>
#include <ws_version.h>

#ifndef ENABLE_STATIC
WS_DLL_PUBLIC_DEF const gchar plugin_version[] = "0.0.2-pre-b1";
WS_DLL_PUBLIC_DEF const gchar plugin_release[] = "3.2"; //VERSION_RELEASE
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;
#endif

#define PROTO_PORT 25565
#define PROTO_TAG "MCPC"
#define PROTO_TAG_PARTIAL "MCPC partial"

//#include "VarUtils.h"
#include <stdio.h>

static int proto_mcpc=-1;
static dissector_handle_t mcpc_handle;

int8_t VarIntToUint(const guint8 *varint, uint32_t *result, uint_fast8_t maxlen){
	int8_t i=0;
	*result=0;
	do{
		if(i>5)
			break;
		*result |= (varint[i]&0x7F) << (i*7);
		if(i>maxlen)
			return -1;
	}while((varint[i++]&0x80) != 0);
	return i;
}

static guint getlen(packet_info *pinfo, tvbuff_t *tvb, int offset _U_, void *data _U_){
	int8_t ret;
	uint32_t len;
	guint8 packet_length;
	packet_length=tvb_reported_length(tvb);//To read
	if(packet_length==0)
		return 0;
//		return tvb_captured_length(tvb);

	const guint8 *dt;
	dt=tvb_get_ptr(tvb, pinfo->desegment_offset, packet_length);
	ret=VarIntToUint(dt, &len, packet_length);
	if(ret==-1)
		return 0;
	else if(ret==0){
		return 1;
	}else
		return len+ret;
}

static int subdissect_mcpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_){
	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG);//Set MCPC protocol tag

	uint32_t protocol_length, varint;
	guint8 packet_length, readed;
	int8_t varlen;
	const guint8 *dt;

	packet_length=tvb_reported_length(tvb);//To read

	dt=tvb_get_ptr(tvb, pinfo->desegment_offset, packet_length);

	readed=VarIntToUint(dt, &protocol_length, packet_length);
	if(readed<0)
		return -1;
	else if(packet_length<protocol_length)
		return packet_length-protocol_length;

	static char buf[32];

	if(protocol_length<=pinfo->fd->pkt_len){
		varlen=VarIntToUint(dt+readed, &varint, packet_length-readed);
		if(varlen>0&&varlen>5)
			readed+=varlen;
		else{
			if(pinfo->destport==25565)
				sprintf(buf, "Result: [C->S] %u bytes, failed to parse PacketID", packet_length);
			else
				sprintf(buf, "Result: [S->C] %u bytes, failed to parse PacketID", packet_length);

			col_set_str(pinfo->cinfo, COL_INFO, "");

			if(varlen>5)
				return 0;
			else
				return -1;
		}
	}


//	if(u>10000)
//		__asm("int $3");
	if(pinfo->destport==25565)
		sprintf(buf, "Result: [C->S] %u bytes, 0x%.2X", packet_length, varint);
	else
		sprintf(buf, "Result: [S->C] %u bytes, 0x%.2X", packet_length, varint);
	col_set_str(pinfo->cinfo, COL_INFO, buf);

	return tvb_captured_length(tvb);
}
static int dissect_mcpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data){
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 0,
						 getlen, subdissect_mcpc, data);
	return tvb_captured_length(tvb);
}


//Protocol register functions
static void proto_reg_handoff_mcpc(void)
{
	mcpc_handle = create_dissector_handle(dissect_mcpc, proto_mcpc);
	dissector_add_uint("tcp.port", PROTO_PORT, mcpc_handle);
}
static void proto_register_mcpc(){
	proto_mcpc = proto_register_protocol ("Minecraft PC version",
											   "Minecraft",
											   "mcpc");
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
