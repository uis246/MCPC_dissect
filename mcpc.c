//#include <stdio.h>

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdint.h>
#include <epan/prefs.h>
#include <epan/packet.h>
#include <epan/column-info.h>
#include <epan/dissectors/packet-tcp.h>

#ifndef ENABLE_STATIC
WS_DLL_PUBLIC_DEF const gchar plugin_version[] = "0.0.1-pre-b6";
WS_DLL_PUBLIC_DEF const gchar plugin_release[] = "2.6"; //VERSION_RELEASE
#endif

#define PROTO_PORT 25565
#define PROTO_TAG "MCPC"

#include "VarUtils.h"
#include <stdio.h>

static int proto_mcpc=-1;

// "_U_" not using
static int dissect_mcpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data){
col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG);
//__asm("int $3");
static int32_t u=0;
//if(u!=0)
//	__asm("int $3");
static uint8_t l;
l=VarIntToInt(tvb_get_ptr(tvb, pinfo->desegment_offset, tvb_reported_length(tvb)), &u);
if(u>pinfo->fd->pkt_len){
	__asm("int $3");
	u=0;
	static const char *gb;
	gb=tvb_get_ptr(tvb, pinfo->desegment_offset, tvb_reported_length(tvb));
	l=VarIntToInt(gb, &u);
}
static char buf[32];
if(l>5)
	col_set_str(pinfo->cinfo, COL_INFO, "VarInt parse error");
else{
//	if(u>10000)
//		__asm("int $3");
	sprintf(buf, "Len: %u", u);
	col_set_str(pinfo->cinfo, COL_INFO, buf);
}
return tvb_captured_length(tvb);
}


static dissector_handle_t mcpc_handle;
static void proto_reg_handoff_mcpc(void)
{
	mcpc_handle = create_dissector_handle(dissect_mcpc, proto_mcpc);
	dissector_add_uint("tcp.port", PROTO_PORT, mcpc_handle);
}
static void proto_register_mcpc(){
	/* name */ /* short name */ /* abbrev */
	proto_mcpc = proto_register_protocol ("Minecraft PC version",
											   "Minecraft",
											   "mcpc");
}
#ifndef ENABLE_STATIC
//#if 0
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
