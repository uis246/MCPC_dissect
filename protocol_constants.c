#include "protocol.h"
#include "protocol_constants.h"

const value_string
direction[]={
	{0, "Down"},
	{1, "Up"},
	{2, "North"},
	{3, "South"},
	{4, "West"},
	{5, "East"},
};

const value_string
metadata_types[]={
	{0, "Byte"},
	{1, "VarInt"},
	{2, "Float"},
	{3, "String"},
	{4, "Chat"},
	{5, "Slot"},
	{6, "Boolean"},
	{7, "Rotation"},
	{8, "Position"},
	{9, "Optional Position"},
	{10, "Direction (VarInt!)"},
	{11, "Optional UUID"},
	{12, "Optional Block ID"},
	{13, "NBT Tag"}
};

const value_string
resourcepack_status[]={//Statuses of ResourcePackStatus
	{0x00, "successfully loaded"},
	{0x01, "declined"},
	{0x02, "failed download"},
	{0x03, "accepted"},
	{0, NULL}
};

const value_string
difficulty_levels[]={//State types
	{0x00, "peaceful"},
	{0x01, "easy"},
	{0x02, "normal"},
	{0x03, "hard"},
	{0, NULL}
};

const value_string
states[]={//State types
	{0x00, "Handshake"},
	{0x01, "Status"},
	{0x02, "Login"},
	{0, NULL}
};

const value_string
sbpackettypes_handshake[]={//Serverbound handshake packet types
	{PID_SB_HS_LOGIN, "Login"},
	{0, NULL}
};

const value_string
cbpackettypes_login[]={//Clientbound login packet types
	{0x00, "Disconnect"},
	{0x01, "Encryption Request"},
	{PID_CB_LOGIN_SUCCESS, "Login Success"},
	{PID_CB_LOGIN_SET_COMPRESSION, "Set Compression"},
	{0, NULL}
},
sbpackettypes_login[]={//Serverbound login packet types
	{PID_SB_LOGIN_START, "Login Start"},
	{0x01, "Encryption Response"},
	{0, NULL}
};

const value_string
cbpackettypes_slp[]={//Clientbound SLP packet types
	{0x00, "Response"},
	{0x01, "Pong"},
	{0, NULL}
},
sbpackettypes_slp[]={//Serverbound SLP packet types
	{0x00, "Request"},
	{0x01, "Ping"},
	{0, NULL}
};

const value_string
cbpackettypes[]={//Clientbound packet types
	{0x00, "Spawn Object"},
	{0x01, "Spawn Experience Orb"},
	{0x02, "Spawn Global Entity"},
	{0x03, "Spawn Mob"},
	{0x04, "Spawn Painting"},
	{0x05, "Spawn Player"},
	{0x06, "Animation (clientbound)"},
	{0x07, "Statistics"},
	{0x08, "Block Break Animation"},
	{0x09, "Update Block Entity"},
	{0x0A, "Block Action"},
	{0x0B, "Block Change"},
	{0x0C, "Boss Bar"},
	{0x0D, "Server Difficulty"},
	{0x0E, "Tab-Complete (clientbound)"},
	{0x0F, "Chat Message (clientbound)"},
	{0x10, "Multi Block Change"},
	{0x11, "Confirm Transaction (clientbound)"},
	{0x12, "Close Window (clientbound)"},
	{0x13, "Open Window"},
	{0x14, "Window Items"},
	{0x15, "Window Property"},
	{0x16, "Set Slot"},
	{0x17, "Set Cooldown"},
	{0x18, "Plugin Message (clientbound)"},
	{0x19, "Named Sound Effect"},
	{0x1A, "Disconnect (play)"},
	{0x1B, "Entity Status"},
	{0x1C, "Explosion"},
	{0x1D, "Unload Chunk"},
	{0x1E, "Change Game State"},
	{0x1F, "Keep Alive (clientbound)"},
	{0x20, "Chunk Data"},
	{0x21, "Effect"},
	{0x22, "Particle"},
	{0x23, "Join Game"},
	{0x24, "Map"},
	{0x25, "Entity"},
	{0x26, "Entity Relative Move"},
	{0x27, "Entity Look And Relative Move"},
	{0x28, "Entity Look"},
	{0x29, "Vehicle Move (clientbound)"},
	{0x2A, "Open Sign Editor"},
	{0x2B, "Craft Recipe Response"},
	{0x2C, "Player Abilities (clientbound)"},
	{0x2D, "Combat Event"},
	{0x2E, "Player List Item"},
	{0x2F, "Player Position And Look (clientbound)"},
	{0x30, "Use Bed"},
	{0x31, "Unlock Recipes"},
	{0x32, "Destroy Entities"},
	{0x33, "Remove Entity Effect"},
	{0x34, "Resource Pack Send"},
	{0x35, "Respawn"},
	{0x36, "Entity Head Look"},
	{0x37, "Select Advancement Tab"},
	{0x38, "World Border"},
	{0x39, "Camera"},
	{0x3A, "Held Item Change (clientbound)"},
	{0x3B, "Display Scoreboard"},
	{0x3C, "Entity Metadata"},
	{0x3D, "Attach Entity"},
	{0x3E, "Entity Velocity"},
	{0x3F, "Entity Equipment"},
	{0x40, "Set Experience"},
	{0x41, "Update Health"},
	{0x42, "Scoreboard Objective"},
	{0x43, "Set Passengers"},
	{0x44, "Teams"},
	{0x45, "Update Score"},
	{0x46, "Spawn Position"},
	{0x47, "Time Update"},
	{0x48, "Title"},
	{0x49, "Sound Effect"},
	{0x4A, "Player List Header And Footer"},
	{0x4B, "Collect Item"},
	{0x4C, "Entity Teleport"},
	{0x4D, "Advancements"},
	{0x4E, "Entity Properties"},
	{0x4F, "Entity Effect"},
	{0, NULL}
},
sbpackettypes[]={//Serverbound(to server) packet types
	{0x00, "Teleport Confirm"},
	{0x01, "Tab-Complete (serverbound)"},
	{0x02, "Chat Message (serverbound)"},
	{0x03, "Client Status"},
	{0x04, "Client Settings"},
	{0x05, "Confirm Transaction (serverbound)"},
	{0x06, "Enchant Item"},
	{0x07, "Click Window"},
	{0x08, "Close Window (serverbound)"},
	{0x09, "Plugin Message (serverbound)"},
	{0x0A, "Use Entity"},
	{0x0B, "Keep Alive (serverbound)"},
	{0x0C, "Player"},
	{0x0D, "Player Position"},
	{0x0E, "Player Position And Look (serverbound)"},
	{0x0F, "Player Look"},
	{0x10, "Vehicle Move (serverbound)"},
	{0x11, "Vehicle Move (serverbound)"},
	{0x12, "Craft Recipe Request"},
	{0x13, "Player Abilities (serverbound)"},
	{0x14, "Player Digging"},
	{0x15, "Entity Action"},
	{0x16, "Steer Vehicle"},
	{0x17, "Crafting Book Data"},
	{0x18, "Resource Pack Status"},
	{0x19, "Advancement Tab"},
	{0x1A, "Held Item Change (serverbound)"},
	{0x1B, "Creative Inventory Action"},
	{0x1C, "Update Sign"},
	{0x1D, "Animation (serverbound)"},
	{0x1E, "Spectate"},
	{0x1F, "Player Block Placement"},
	{0x20, "Use Item"},
	{0, NULL}
};
