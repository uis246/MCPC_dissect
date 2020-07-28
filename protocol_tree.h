#pragma once

#include <epan/proto.h>

void tree_server_handshake(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo, const void *data, guint length);

void tree_server_login(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo, const void *data, guint length);
void tree_client_login(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo, const void *data, guint length);

void tree_server_play(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo, const void *data, guint length);
void tree_client_play(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo, const void *data, guint length);

void tree_server_slp(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const void *data, guint length);
void tree_client_slp(proto_tree *packet_tree, tvbuff_t *tvb, packet_info *pinfo _U_, const void *data, guint length);
