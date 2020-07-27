#pragma once
#include <epan/value_string.h>

#define PID_SB_HS_LOGIN 0x00

#define PID_CB_LOGIN_DISCONNECT 0x00
#define PID_CB_LOGIN_CRYPT_RQ 0x01
#define PID_CB_LOGIN_SUCCESS 0x02
#define PID_CB_LOGIN_SET_COMPRESSION 0x03

#define PID_SB_LOGIN_START 0x00
#define PID_SB_LOGIN_CRYPT_RESPONSE 0x01

#define PID_CB_PLAY_JOIN_GAME 0x23

//#define

extern const value_string sbpackettypes_handshake[];
extern const value_string cbpackettypes_slp[], sbpackettypes_slp[];
extern const value_string cbpackettypes_login[], sbpackettypes_login[];
extern const value_string cbpackettypes[], sbpackettypes[];

extern const value_string states[], difficulty_levels[];
