#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <lua.h>
#include <lauxlib.h>

static char const b64_lookup[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/*
#!/usr/bin/env lua
b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
rev_lut = setmetatable({}, {
    __index = function(t,k)
        t[k] = 0
        return t[k]
    end
})
for i = 1,#b64 do
    rev_lut[b64:byte(i)] = i-1
end
for i = 0,255 do
    io.write(rev_lut[i], ",")
end
print""
*/
static char const b64_reverse[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,62,0,0,0,63,52,53,54,55,56,57,58,59,60,61,0,0,0,0,0,0,0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,0,0,0,0,0,0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

int hex2bin(lua_State *L) {
    size_t len;
    char const *str = luaL_checklstring(L, 1, &len);

    if (len%2 != 0) {
        luaL_error(L, "hex2bin only accepts strings with a multiple of 8 bits");
    }
    
    int new_len = len/2;
    char *res = (char *) malloc(new_len);
    if (!res) {
        luaL_error(L, "out of memory");
    }
    int pos = 0;

    //There are ways to do this faster, but we'll only 
    //optimize when we need to
    int rd_pos = 0;
    while (rd_pos < len) {
        char b0 = toupper(str[rd_pos++]);
        char b1 = toupper(str[rd_pos++]);

        if (isalpha(b0)) b0 = b0 - 'A' + 10;
        else             b0 = b0 - '0';
        
        if (isalpha(b1)) b1 = b1 - 'A' + 10;
        else             b1 = b1 - '0';

        res[pos++] = (b0<<4) | b1;
    }
    
    if (pos != new_len) luaL_error(L, "Assertion failure, pos != new_len");
    
    lua_pushlstring(L, res, new_len);
    free(res);
    return 1;
}

int bin2hex(lua_State *L) {
    size_t len;
    char const *str = luaL_checklstring(L, 1, &len);

    //printf("bin2hex: len = %lu, [0] = %#02x\n", len, str[0] & 0xFF);
    
    int new_len = 2*len;

    char *res = (char*) malloc(new_len);
    if (!res) luaL_error(L, "out of memory");
    
    static char const lookup[] = "0123456789abcdef";

    int pos = 0;
    for (int i = 0; i < len; i++) {
        res[pos++] = lookup[(str[i] >> 4) & 0xF];
        res[pos++] = lookup[str[i] & 0xF];
    }

    if (pos != new_len) {
        luaL_error(L, "Assertion failure, pos != new_len");
    }

    lua_pushlstring(L, res, new_len);
    free(res);
    return 1;
}

int b642bin(lua_State *L) {
    size_t len;
    char const *str = luaL_checklstring(L, 1, &len);

    if (len%4 != 0) {
        luaL_error(L, "b642bin does not work with fractional bytes");
    }

    uint padding = (str[len - 1] == '=') + (str[len - 2] == '=');
    
    uint new_len = 3*len/4 - padding;
    char *res = (char*) malloc(new_len);
    if (!res) luaL_error(L, "out of memory");

    int pos = 0;

    for (int i = 0; i+3 < len - padding; i += 4) {
        uint b3 = b64_reverse[str[i+0]];
        uint b2 = b64_reverse[str[i+1]];
        uint b1 = b64_reverse[str[i+2]];
        uint b0 = b64_reverse[str[i+3]];

        res[pos++] = (b3 << 2) | (b2 >> 4);
        res[pos++] = ((b2&0xF) << 4) | (b1 >> 2);
        res[pos++] = ((b1&0x3) << 6) | b0;
    }

    if (padding) {
        uint b3 = b64_reverse[str[len-4]];
        uint b2 = b64_reverse[str[len-3]];
        uint b1 = b64_reverse[str[len-2]];
        //uint b0 = b64_reverse[str[len-1]];

        res[pos++] = (b3 << 2) | (b2 >> 4);
        if (padding < 2)
            res[pos++] = ((b2&0xF) << 4) | (b1 >> 2);
    }
    
    if (pos != new_len) {
        luaL_error(L, "Assertion failed, pos != new_len");
    }

    lua_pushlstring(L, res, new_len);
    free(res);
    return 1;
}

int bin2b64(lua_State *L) {
    size_t len;
    char const *str = luaL_checklstring(L, 1, &len);

    int new_len = 4*((len+2)/3);
    
    char *result = (char *) malloc(new_len);
    if (!result) {
        luaL_error(L, "out of memory");
    }
    int pos = 0;

    uint const full_chunks = len/3;
    for (int i = 0; i+2 < len; i+=3) {
        //Might be fun to write inline assembly for this
        uint b0 = str[i];
        uint b1 = str[i+1];
        uint b2 = str[i+2];

        result[pos++] = b64_lookup[b0 >> 2];
        result[pos++] = b64_lookup[((b0 & 0x3) << 4) | (b1 >> 4)];
        result[pos++] = b64_lookup[((b1 & 0xF) << 2) | (b2 >> 6)];
        result[pos++] = b64_lookup[b2 & 0x3F];
    }
    
    uint const stragglers = len%3;
    switch(stragglers) {
        case 0:
            break;
        case 1: {
            uint b0 = str[len-1];
            
            result[pos++] = b64_lookup[b0 >> 2];
            result[pos++] = b64_lookup[(b0 & 0x3) << 4];
            result[pos++] = '=';
            result[pos++] = '=';
            break;
        }
        case 2: {
            uint b0 = str[len-2];
            uint b1 = str[len-1];
            
            result[pos++] = b64_lookup[b0 >> 2];
            result[pos++] = b64_lookup[((b0 & 0x3) << 4) | (b1 >> 4)];
            result[pos++] = b64_lookup[(b1 & 0xF) << 2];
            result[pos++] = '=';
            break;
        }
    }

    if (pos != new_len) luaL_error(L, "Assertion failure, pos != new_len");
    
    lua_pushlstring(L, result, new_len);
    free(result);
    return 1;
}

int binxor(lua_State *L) {
    char const *a; size_t a_len;
    a = luaL_checklstring(L, 1, &a_len);
    char const *b; size_t b_len;
    b = luaL_checklstring(L, 2, &b_len);

    int new_len = a_len > b_len ? a_len : b_len;
    char *res = malloc(new_len);
    if (!res) luaL_error(L, "out of memory");

    for (int i = 0; i < new_len; i++) {
        res[i] = a[i%a_len] ^ b[i%b_len];
    }

    lua_pushlstring(L, res, new_len);
    free(res);
    return 1;
}

//Returns 256-entry normalized frequencies of the ascii chars 
int charfreq(lua_State *L) {
    size_t len;
    char const *str = luaL_checklstring(L, 1, &len);

    if (len == 0) {
        luaL_error(L, "charfreq must be called with nonempty string");
    }

    uint tallies[256];
    memset(tallies, 0, sizeof(tallies));

    for (int i = 0; i < len; i++) tallies[str[i]&0xFF]++;
    
    lua_createtable(L, 256, 0);
    
    for (int i = 0; i < 256; i++) {
        lua_Number norm_freq = (lua_Number) tallies[i] / (lua_Number) len;
        lua_pushnumber(L, norm_freq);
        lua_rawseti(L, -2, i+1);
    }

    return 1;
}

int hamming(lua_State *L) {
    char const *a; size_t a_len;
    a = luaL_checklstring(L, 1, &a_len);
    char const *b; size_t b_len;
    b = luaL_checklstring(L, 2, &b_len);

    if (a_len != b_len) {
        luaL_error(L, "Can only take Hamming distance of two equal-length strings");
    }

    uint dist = 0;

    static uint const lookup[16] = {0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4};

    for (int i = 0; i < a_len; i++) {
        uint x = (a[i] ^ b[i]) & 0xFF;
        dist += lookup[x>>4];
        dist += lookup[x&0xF];
    }
    
    lua_pushinteger(L, dist);
    return 1;
}

//Take every character from offset,offset+stride,offset+2*stride...
//Since Lua does everything with 1-indexing, we will honour that
int downsample(lua_State *L) {
    size_t len;
    char const *str = luaL_checklstring(L, 1, &len);
    lua_Integer stride = luaL_checkinteger(L, 2);
    lua_Integer offset = luaL_checkinteger(L, 3);

    int new_len = 1 + (len - offset) / stride;
    char *res = (char *) malloc(new_len);
    if (!res) luaL_error(L, "out of memory");

    int pos = 0;
    for (int i = offset - 1; i < len; i += stride) {
        res[pos++] = str[i];
    }

    if (pos != new_len) {
        luaL_error(L, "Assertion failed, pos != new_len");
    }

    lua_pushlstring(L, res, new_len);
    free(res);
    return 1;
}

int luaopen_cp(lua_State *L) {
    lua_register(L, "hex2bin", hex2bin);
    lua_register(L, "b642bin", b642bin);
    lua_register(L, "bin2b64", bin2b64);
    lua_register(L, "bin2hex", bin2hex);
    lua_register(L, "binxor", binxor);
    lua_register(L, "charfreq", charfreq);
    lua_register(L, "downsample", downsample);
    lua_register(L, "hamming", hamming);
    return 0;
}