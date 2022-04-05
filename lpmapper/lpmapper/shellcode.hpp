#pragma once

namespace shellcode
{
	static const uint8_t data[] = {
	  0x48, 0x31, 0xC0, 					 // 0x0: xor rax, rax
	  0xC3								 // 0x3: ret
	};
}
