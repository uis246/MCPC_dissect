#pragma once
#include <stdint.h>

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

int8_t VarIntToUint(const guint8 *varint, uint32_t *result, guint maxlen);

int parse_server_handshake(const void *data, guint length, mcpc_protocol_context *ctx);

int parse_server_login(const void *data, guint length, mcpc_protocol_context *ctx _U_);
int parse_client_login(const void *data, guint length, mcpc_protocol_context *ctx);


