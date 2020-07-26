#pragma once
#include <stdint.h>

#include <epan/value_string.h>
#include <epan/proto.h>

#define STATE_INVALID 0
#define STATE_HANDSHAKE 1
#define STATE_LOGIN 2
#define STATE_PLAY 3
#define STATE_SLP 4 //Server List Ping
#define STATE_SLP_OLD 5 //Old-style Server List Ping

typedef struct {
	int32_t compressTrxld;
	uint_fast8_t state;
} mcpc_protocol_context;

extern const value_string sbpackettypes_handshake[];
extern const value_string cbpackettypes_slp[], sbpackettypes_slp[];
extern const value_string cbpackettypes_login[], sbpackettypes_login[];
extern const value_string cbpackettypes[], sbpackettypes[];

int8_t VarIntToUint(const guint8 *varint, uint32_t *result, guint maxlen);

void tree_server_handshake(proto_tree *packet_tree, tvbuff_t *tvb, const void *data, guint length);

void tree_server_login(proto_tree *packet_tree, tvbuff_t *tvb, const void *data, guint length);
void tree_client_login(proto_tree *packet_tree, tvbuff_t *tvb, const void *data, guint length);

void tree_server_play(proto_tree *packet_tree, tvbuff_t *tvb, const void *data, guint length);
void tree_client_play(proto_tree *packet_tree, tvbuff_t *tvb, const void *data, guint length);

int parse_server_handshake(const void *data, guint length, mcpc_protocol_context *ctx);

int parse_server_login(const void *data, guint length, mcpc_protocol_context *ctx _U_);
int parse_client_login(const void *data, guint length, mcpc_protocol_context *ctx);


