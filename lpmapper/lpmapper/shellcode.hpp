#pragma once

namespace shellcode
{
	uint8_t data[] = {
	0x48, 0x89, 0x6C, 0x24, 0x08, 			 // 0x0: mov [rsp+8],rbp
	0x56, 								 // 0x5: push rsi
	0x57, 								 // 0x6: push rdi
	0x41, 0x56, 						 // 0x7: push r14
	0x48, 0x83, 0xEC, 0x40, 				 // 0x9: sub rsp,40h
	0x48, 0x8B, 0x82, 0xB8, 0x00, 0x00, 0x00, 	 // 0xD: mov rax,[rdx+0B8h]
	0x48, 0x89, 0xD6, 					 // 0x14: mov rsi,rdx
	0x4C, 0x8B, 0x72, 0x70, 				 // 0x17: mov r14,[rdx+70h]
	0x8B, 0x50, 0x18, 					 // 0x1B: mov edx,[rax+18h]
	0x48, 0x8B, 0x78, 0x20, 				 // 0x1E: mov rdi,[rax+20h]
	0x81, 0xFA, 0x03, 0x20, 0x00, 0x80, 		 // 0x22: cmp edx,80002003h
	0x0F, 0x84, 0xB3, 0x00, 0x00, 0x00, 		 // 0x28: je near 00000000000000B9h
	0x81, 0xFA, 0x07, 0x20, 0x00, 0x80, 		 // 0x2E: cmp edx,80002007h
	0x74, 0x2A, 						 // 0x34: je short 000000000000002Ch
	0x81, 0xFA, 0x0B, 0x20, 0x00, 0x80, 		 // 0x36: cmp edx,8000200Bh
	0x74, 0x0E, 						 // 0x3C: je short 0000000000000010h
	0x48, 0x89, 0xF2, 					 // 0x3E: mov rdx,rsi
	0xFF, 0x15, 0xFA, 0x00, 0x00, 0x00, 		 // 0x41: call qword [100h]
	0xE9, 0xE7, 0x00, 0x00, 0x00, 			 // 0x47: jmp near 00000000000000ECh
	0x4D, 0x85, 0xF6, 					 // 0x4C: test r14,r14
	0x0F, 0x84, 0xC8, 0x00, 0x00, 0x00, 		 // 0x4F: je near 00000000000000CEh
	0x0F, 0x20, 0xD8, 					 // 0x55: mov rax,cr3
	0x49, 0x89, 0x06, 					 // 0x58: mov [r14],rax
	0xE9, 0xBD, 0x00, 0x00, 0x00, 			 // 0x5B: jmp near 00000000000000C2h
	0x48, 0x85, 0xFF, 					 // 0x60: test rdi,rdi
	0x0F, 0x84, 0xB4, 0x00, 0x00, 0x00, 		 // 0x63: je near 00000000000000BAh
	0x48, 0x8B, 0x0F, 					 // 0x69: mov rcx,[rdi]
	0x48, 0x8D, 0x54, 0x24, 0x68, 			 // 0x6C: lea rdx,[rsp+68h]
	0x48, 0x83, 0x64, 0x24, 0x68, 0x00, 		 // 0x71: and qword [rsp+68h],0
	0xFF, 0x15, 0xCC, 0x00, 0x00, 0x00, 		 // 0x77: call qword [0D2h]
	0x48, 0x8B, 0x6C, 0x24, 0x68, 			 // 0x7D: mov rbp,[rsp+68h]
	0x48, 0x85, 0xED, 					 // 0x82: test rbp,rbp
	0x0F, 0x84, 0x92, 0x00, 0x00, 0x00, 		 // 0x85: je near 0000000000000098h
	0x83, 0x7F, 0x18, 0x00, 				 // 0x8B: cmp dword [rdi+18h],0
	0x74, 0x16, 						 // 0x8F: je short 0000000000000018h
	0xFF, 0x15, 0xBA, 0x00, 0x00, 0x00, 		 // 0x91: call qword [0C0h]
	0x83, 0x7F, 0x18, 0x00, 				 // 0x97: cmp dword [rdi+18h],0
	0x48, 0x89, 0xC5, 					 // 0x9B: mov rbp,rax
	0x74, 0x07, 						 // 0x9E: je short 9
	0x48, 0x8B, 0x44, 0x24, 0x68, 			 // 0xA0: mov rax,[rsp+68h]
	0xEB, 0x06, 						 // 0xA5: jmp short 8
	0xFF, 0x15, 0xA4, 0x00, 0x00, 0x00, 		 // 0xA7: call qword [0AAh]
	0x4C, 0x8B, 0x47, 0x20, 				 // 0xAD: mov r8,[rdi+20h]
	0x48, 0x8D, 0x4C, 0x24, 0x70, 			 // 0xB1: lea rcx,[rsp+70h]
	0x48, 0x83, 0x64, 0x24, 0x70, 0x00, 		 // 0xB6: and qword [rsp+70h],0
	0x4C, 0x8B, 0x4F, 0x10, 				 // 0xBC: mov r9,[rdi+10h]
	0x48, 0x8B, 0x57, 0x08, 				 // 0xC0: mov rdx,[rdi+8]
	0x48, 0x89, 0x4C, 0x24, 0x30, 			 // 0xC4: mov [rsp+30h],rcx
	0x48, 0x89, 0xE9, 					 // 0xC9: mov rcx,rbp
	0xC6, 0x44, 0x24, 0x28, 0x00, 			 // 0xCC: mov byte [rsp+28h],0
	0x4C, 0x89, 0x44, 0x24, 0x20, 			 // 0xD1: mov [rsp+20h],r8
	0x49, 0x89, 0xC0, 					 // 0xD6: mov r8,rax
	0xFF, 0x15, 0x92, 0x00, 0x00, 0x00, 	// 0xD9: call qword [98h]
	0xEB, 0x31, 						 // 0xDF: jmp short 0000000000000033h
	0x48, 0x85, 0xFF, 					 // 0xE1: test rdi,rdi
	0x74, 0x37, 						 // 0xE4: je short 0000000000000039h
	0x4D, 0x85, 0xF6, 					 // 0xE6: test r14,r14
	0x74, 0x32, 						 // 0xE9: je short 0000000000000034h
	0x48, 0x8B, 0x0F, 					 // 0xEB: mov rcx,[rdi]
	0x48, 0x8D, 0x54, 0x24, 0x68, 			 // 0xEE: lea rdx,[rsp+68h]
	0x48, 0x83, 0x64, 0x24, 0x68, 0x00, 		 // 0xF3: and qword [rsp+68h],0
	0xFF, 0x15, 0x4A, 0x00, 0x00, 0x00, 		 // 0xF9: call qword [50h]
	0x48, 0x8B, 0x4C, 0x24, 0x68, 			 // 0xFF: mov rcx,[rsp+68h]
	0x48, 0x85, 0xC9, 					 // 0x104: test rcx,rcx
	0x74, 0x14, 						 // 0x107: je short 0000000000000016h
	0xFF, 0x15, 0x4A, 0x00, 0x00, 0x00, 		 // 0x109: call qword [50h]
	0x49, 0x89, 0x06, 					 // 0x10F: mov [r14],rax
	0x48, 0x8B, 0x4C, 0x24, 0x68, 			 // 0x112: mov rcx,[rsp+68h]
	0xFF, 0x15, 0x44, 0x00, 0x00, 0x00, 		 // 0x117: call qword [4Ah]
	0x48, 0x83, 0x66, 0x38, 0x00, 			 // 0x11D: and qword [rsi+38h],0
	0x31, 0xD2, 						 // 0x122: xor edx,edx
	0x83, 0x66, 0x30, 0x00, 				 // 0x124: and dword [rsi+30h],0
	0x48, 0x89, 0xF1, 					 // 0x128: mov rcx,rsi
	0xFF, 0x15, 0x38, 0x00, 0x00, 0x00, 		 // 0x12B: call qword [3Eh]
	0x31, 0xC0, 						 // 0x131: xor eax,eax
	0x48, 0x8B, 0x6C, 0x24, 0x60, 			 // 0x133: mov rbp,[rsp+60h]
	0x48, 0x83, 0xC4, 0x40, 				 // 0x138: add rsp,40h
	0x41, 0x5E, 						 // 0x13C: pop r14
	0x5F, 								 // 0x13E: pop rdi
	0x5E, 								 // 0x13F: pop rsi
	0xC3,								 // 0x140: ret

	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // 0x141: Function Table Entry --> OriginalDispatch
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // 0x149: Function Table Entry --> PsLookupProcessByProcessId
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // 0x151: Function Table Entry --> IoGetCurrentProcess
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // 0x159: Function Table Entry --> PsGetProcessSectionBaseAddress
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // 0x161: Function Table Entry --> ObfDereferenceObject
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // 0x169: Function Table Entry --> IofCompleteRequest
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // 0x171: Function Table Entry --> MmCopyVirtualMemory
	};

#define FUNCTION_TABLE_OFFSET 0x141
}
