#include <stdint.h>
uint8_t VarIntToInt(char *loc, int32_t *to){
	static uint8_t ind;
	ind=0;
	do{
		*to |= (loc[ind]&0x7F) << (ind*7);
		if(ind>5)
			break;
	}while((loc[ind++]&0x80) != 0);
	return ind;
}
