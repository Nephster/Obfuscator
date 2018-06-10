#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "distorm.h"
#include <Dbghelp.h>
#include <string>
#include <wincrypt.h>
#include <conio.h>
#include <winsock.h>


// Link with the Advapi32.lib file.
#pragma comment (lib, "advapi32")
#pragma comment	(lib,"Ws2_32.lib")
#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_AES_128
#define ENCRYPT_BLOCK_SIZE 16 
#define MAX_PATH_LEN 200
// Link the library into our project.
#pragma comment(lib, "./distorm.lib")
// The number of the array of instructions the decoder function will use to return the disassembled instructions.
#define MAX_INSTRUCTIONS (100)
//#define _CRT_SECURE_NO_DEPRECATE 


BOOL MyEncryptFile(
	LPTSTR szSource,
	LPTSTR szDestination,
	LPTSTR pKeyfile);

void MyHandleError(LPTSTR psz,
				   int nErrorNumber);

DWORD align(DWORD size, 
			DWORD align, 
			DWORD addr);

DWORD Disassembling(FILE *fp, 
					FILE *fcall, 
					unsigned char *buf, 
					unsigned char *buf2, 
					DWORD dwCodeSize, 
					DWORD offset);

DWORD RVAToOffset(DWORD pMapping, DWORD dwRVA);
bool AddSection(char *filepath, 
				char *sectionName, 
				DWORD sizeOfSection);


int rewriteAddress(DWORD addrOfCodeSection);

DWORD * readAddress();

bool AddCode(char *filepath);

DWORD PeSectionEnum(DWORD *ArrayOfaddressesComeFrom, char path[MAX_PATH_LEN]);
__int64 myFileSeek(HANDLE hf, __int64 distance, DWORD MoveMethod);
BYTE *SpcExportKeyData(HCRYPTPROV hProvider, HCRYPTKEY hKey, DWORD *cbData);
HANDLE ObfFile;
int count_underscores(char *s);
int main(int argc, char **argv)
{

	// Handling file.
	HANDLE hFile;
	HANDLE hFileMapping;

	//output disassebled file
	FILE *fp, *fcall;


	//using variable
	unsigned long dver = 0;
	LPVOID lpFileBase;
	PIMAGE_NT_HEADERS PEheader = {0};
	PIMAGE_DOS_HEADER dosHeader;
	DWORD dwImageBase;
	DWORD dwRelativeVirtualAddress;
	DWORD dwCodeSize;
	DWORD dwTargetOffset = 0;
	DWORD dwNumbersCharacters = 0;
	DWORD i;
	DWORD dwEntryPoint = 0;

    DWORD offset=0;
	IMAGE_OPTIONAL_HEADER optionalHeader = { 0 };

	//allocating memory 
	char * pSourceFile =(char *)malloc(MAX_PATH_LEN*sizeof(char));
	char * pDestinationFile = (char *)malloc(MAX_PATH_LEN*sizeof(char));
	char * pKeyFile = (char *)malloc(MAX_PATH_LEN*sizeof(char));

	char * errch = NULL;

	// Index to file name in argv.
	int param = 1;

	//Size
	DWORD filesize, bytesread, dwCountCALL;


	// Buffer to disassemble.
	unsigned char *buf, *buf2;

	//buffer for path
	char *pOutFilePath = new char[MAX_PATH];
	char *pathCall = new char[MAX_PATH];
	//buffer for current folder
	LPTSTR currentFolder = NULL;

	//for file pointer
	LARGE_INTEGER liDistanceToMove;

	// get current folder
	//dwNumbersCharacters = GetCurrentDirectory(100, currentFolder);


	GetModuleFileNameA(NULL, pOutFilePath, MAX_PATH);


	fp = fopen("./disassembly.txt", "w+");
	fcall = fopen("./CALL.txt", "w+");
	if (fp == NULL)
	{
		printf("Cannot creates ouput file\n");
		return -1;
	}
	// Check params.
	if (argc < 2 || argc > 4) {
	printf(	"Usage: obfuscator.exe filename \r\n"
	"Memory offset is origin of binary file in memory (address in hex).\r\n"
	"Default decoding mode is 32.\r\n"
	"example: disasm demo.exe\r\n");
	return -1;
	}

	
	if (argv[1] == NULL) {
	printf("Filename is missing.");
	return -1;
	}

		
	hFile = CreateFile(argv[1], GENERIC_WRITE | GENERIC_READ, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Could not open file %s (error %d)\n", GetLastError());
		getchar();
		return -2;
	}


	if ((filesize = GetFileSize(hFile, NULL)) < 0) {
		printf("Error getting filesize (error %d)\n", GetLastError());
		CloseHandle(hFile);
		return -3;
	}



	hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	DWORD tmp = GetLastError();
	if (hFileMapping == 0)
	{
		CloseHandle(hFile);
		printf("Couldn't open file mapping with CreateFileMapping()\n");
		return -1;
	}


	lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (lpFileBase == 0)
	{
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		printf("Couldn't map view of file with MapViewOfFile()\n");
		return -1;
	}

	dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
	if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		printf("It is MZ file\n");

		DWORD dwOffsetPEheader = (dosHeader->e_lfanew);
		LPVOID lpAddressOfPEheader = (LPVOID *)(lpFileBase)+dwOffsetPEheader / 4;												// deleno 4 lebo 4 byti
		PEheader = (PIMAGE_NT_HEADERS)lpAddressOfPEheader;
		PIMAGE_SECTION_HEADER pSectionHeader;

		if (PEheader->Signature == 0x4550)
		{
			printf("It is PE file\n");

			optionalHeader = PEheader->OptionalHeader;
			dwImageBase = optionalHeader.ImageBase;
			dwRelativeVirtualAddress = optionalHeader.BaseOfCode;
			dwTargetOffset = optionalHeader.SizeOfHeaders;
			dwCodeSize = optionalHeader.SizeOfCode;

			for (i = 0, pSectionHeader = IMAGE_FIRST_SECTION(PEheader);
				i < PEheader->FileHeader.NumberOfSections; i++) {

				DWORD VirtualAddressOfSection = (dwImageBase + pSectionHeader[i].VirtualAddress);

				DWORD sizeOfSection = pSectionHeader[i].SizeOfRawData;
				if (!strcmp((char *)pSectionHeader[i].Name, ".text")){
					offset = VirtualAddressOfSection;
					dwEntryPoint = pSectionHeader[i].VirtualAddress;
				}

			}
		}
	}

	DWORD entryInFileObject = dwEntryPoint + (DWORD)lpFileBase;

	UnmapViewOfFile(lpFileBase);

	CloseHandle(hFileMapping);




	//_OffsetType off=dwImageBase + dwRelativeVirtualAddress;//setting offset of file 
	//LPVOID buf4=NULL;
	//LPVOID buf3 = (LPVOID *) lpFileBase + dwTargetOffset/4;


	liDistanceToMove.QuadPart = dwTargetOffset;
	if (!SetFilePointerEx(hFile, liDistanceToMove, NULL, FILE_BEGIN)){				//setting pointer to start of code
		printf("Error  file pointer  (error %d)\n", GetLastError());
		CloseHandle(hFile);

		return -5;
	}



	buf = buf2 = (unsigned char *)malloc(dwCodeSize);

	if (!ReadFile(hFile, buf, dwCodeSize, &bytesread, NULL)) {
		printf("Error reading file (error %d)\n", GetLastError());
		CloseHandle(hFile);
		free(buf);
		return -3;
	}

	CloseHandle(hFile);

	dwCountCALL = Disassembling(fp, fcall, buf, buf2, dwCodeSize, offset); //disassembling code section of program to obfuscate
	
	fclose(fcall);
	fclose(fp);

	DWORD *ArrayOfaddressesComeFrom=readAddress(); //read addresses from file CALL.txt

	char * name = (char *)malloc(MAX_PATH);
	char * name2 = (char *)malloc(MAX_PATH);

	GetCurrentDirectoryA(MAX_PATH, name);
	GetCurrentDirectoryA(MAX_PATH, name2);

	lstrcatA(name, "\\");
	lstrcatA(name, argv[1]);
	lstrcatA(name2, "\\");
	lstrcatA(name2, argv[1]);
	
	lstrcatA(name2, ".obf.exe");
	CopyFileA(name, name2, FALSE);


	if (!AddSection(name2, ".obf", 4000))
	{
		printf("Cannot create a section");
		getchar();
		return -8;
	}

	if (!AddCode(name2))
	{
		printf("Cannot insert code");
		getchar();
		return -8;	
	}




	DWORD value = PeSectionEnum(ArrayOfaddressesComeFrom,name2);
	printf("Program information\n");
	printf("ImageBase %x (Address in HEX)\n"
		"Relative virtual address: %x (Address in HEX)\n"
		"Virtual size of code: %d (BYTE in DEC)\n"
		"CALL counter: %d (count in DEC)\n", dwImageBase, dwRelativeVirtualAddress, dwCodeSize, dwCountCALL);

	//scanf("%s", (char *)pPassword);
	//GetModuleFileName(NULL, pSource, MAX_PATH_LEN);
	GetCurrentDirectoryA(MAX_PATH_LEN,pSourceFile);
	GetCurrentDirectoryA(MAX_PATH_LEN, pDestinationFile);
	GetCurrentDirectoryA(MAX_PATH_LEN, pKeyFile);
	lstrcat(pSourceFile, "\\CALL.txt");
	lstrcat(pDestinationFile, "\\CALLen.txt");
	lstrcat(pKeyFile, "\\key.txt");

	if (MyEncryptFile(pSourceFile, (LPTSTR)pDestinationFile, (LPTSTR)pKeyFile))
	{
		printf(
			"Encryption of the file %s was successful. \n",
			pSourceFile);
		printf(
			TEXT("The encrypted data is in file %s.\n"),
			pDestinationFile);
	}
	else
	{
		MyHandleError(
			TEXT("Error encrypting file!\n"),
			GetLastError());
	}

	
	



	return 0;

}



DWORD * readAddress(){
	//FILE *rCall;
	int addrOfCall[100] = {0};
	HANDLE hFile;
	DWORD dwBytesReaded = 0;
	DWORD tmp = 0;
	DWORD *ArrayOfaddressesComeFrom;

	char tmp_array[9] = { 0 };
	char tmp_array2[7] = { 0 };
	char * pathOfCall = (char *)malloc(MAX_PATH_LEN*sizeof(char));
	GetCurrentDirectoryA(MAX_PATH_LEN, pathOfCall);
	lstrcat(pathOfCall, "\\CALL.txt");
	hFile = CreateFileA(pathOfCall, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD sizeOfFile = GetFileSize(hFile, NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Could not open file (error %d) %s \n", GetLastError(), pathOfCall);
		getchar();
		return 0;
	}
	char* ReadBuffer = (char *)VirtualAlloc(NULL, sizeOfFile, MEM_COMMIT, PAGE_READWRITE);

	ReadFile(hFile, ReadBuffer, sizeOfFile, &dwBytesReaded, NULL);
	
	ArrayOfaddressesComeFrom =(DWORD *) VirtualAlloc(NULL, sizeOfFile, MEM_COMMIT, PAGE_READWRITE);

	char nulaX[3] = { '0', 'x', '\0' };
	char nnula[3] = { '0', '0', '\0' };
	char newline[3] = { '\n', '\r', '\0' };


	for (int i = 0;; i++){

		if (memcmp(nnula, ReadBuffer, 2))
			break;
		
		memcpy(tmp_array, ReadBuffer, 8);
		tmp_array[8] = '\0';

		ArrayOfaddressesComeFrom[i] = (long)strtol(tmp_array, NULL, 16);
		ArrayOfaddressesComeFrom[i] -= 0x400000;
		while (1){
			ReadBuffer++;
			if (!memcmp(nulaX, ReadBuffer, 2)){
				ReadBuffer += 2;
				memcpy(tmp_array2, ReadBuffer, 6);
				tmp_array2[6] = '\0';
	


				while (1){
					ReadBuffer++;
					if (!memcmp(newline, ReadBuffer, 1)){
						ReadBuffer++;
						break;
					}
				}
				break;
			}
		}

	}

	CloseHandle(hFile);

	return ArrayOfaddressesComeFrom;

}
DWORD Disassembling(FILE *fp, FILE *fcall, unsigned char *buf, unsigned char *buf2, DWORD dwCodeSize, DWORD offset)
{
	// Holds the result of the decoding.
	_DecodeResult res;
	long long counter = 0;

	// Decoded instruction information.
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
	// next is used for instruction's offset synchronization.
	// decodedInstructionsCount holds the count of filled instructions' array by the decoder.
	unsigned int decodedInstructionsCount = 0, i, next;

	// Default decoding mode is 32 bits, could be set by command line.
	_DecodeType dt = Decode32Bits;

	// Default offset for buffer is 0, could be set in command line.
	_OffsetType offset1 = 0x00401000;


	// Decode the buffer at given offset (virtual address).
	while (1) {
		// If you get an unresolved external symbol linker error for the following line,
		// change the SUPPORT_64BIT_OFFSET in distorm.h.

		res = distorm_decode(offset, (const unsigned char*)buf, dwCodeSize, dt, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);
		if (res == DECRES_INPUTERR) {
			// Null buffer? Decode type not 16/32/64?
			printf("Input error, halting!");
			free(buf2);
			return -4;
		}

		for (i = 0; i < decodedInstructionsCount; i++) {

			fprintf(fp, "%0*I64x (%02d) %-24s %s%s%s\n", dt != Decode64Bits ? 8 : 16, decodedInstructions[i].offset, decodedInstructions[i].size, (char*)decodedInstructions[i].instructionHex.p, (char*)decodedInstructions[i].mnemonic.p, decodedInstructions[i].operands.length != 0 ? " " : "", (char*)decodedInstructions[i].operands.p);
			if (!strcmp((char*)decodedInstructions[i].mnemonic.p, "CALL")){
				if (!strstr((char*)decodedInstructions[i].operands.p, "E")){
					fprintf(fcall, "%0*I64x=%s\n", 8, decodedInstructions[i].offset, decodedInstructions[i].operands.p);
					counter++;
				}
			}


		}

		if (res == DECRES_SUCCESS) break; // All instructions were decoded.
		else if (decodedInstructionsCount == 0) break;

		// Synchronize:
		next = (unsigned long)(decodedInstructions[decodedInstructionsCount - 1].offset - offset);
		next += decodedInstructions[decodedInstructionsCount - 1].size;

		// Advance ptr and recalc offset.
		buf += next;
		dwCodeSize -= next;
		offset += next;
	}

	return counter;
}

bool AddSection(char *filepath, char *sectionName, DWORD sizeOfSection){
	HANDLE file = CreateFileA(filepath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD tmp = GetLastError();
	if (file == INVALID_HANDLE_VALUE)
		return false;
	DWORD fileSize = GetFileSize(file, NULL);
	//so we know how much buffer to allocate
	BYTE *pByte = new BYTE[fileSize];
	DWORD dw;
	//lets read the entire file,so we can use the PE information
	ReadFile(file, pByte, fileSize, &dw, NULL);

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pByte;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return false; //invalid PE
	PIMAGE_FILE_HEADER FH = (PIMAGE_FILE_HEADER)(pByte + dos->e_lfanew + sizeof(DWORD));
	PIMAGE_OPTIONAL_HEADER OH = (PIMAGE_OPTIONAL_HEADER)(pByte + dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER SH = (PIMAGE_SECTION_HEADER)(pByte + dos->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	ZeroMemory(&SH[FH->NumberOfSections], sizeof(IMAGE_SECTION_HEADER));
	CopyMemory(&SH[FH->NumberOfSections].Name, sectionName, 8);
	//We use 8 bytes for section name,cause it is the maximum allowed section name size

	//lets insert all the required information about our new PE section
	SH[FH->NumberOfSections].Misc.VirtualSize = align(sizeOfSection, OH->SectionAlignment, 0);
	SH[FH->NumberOfSections].VirtualAddress = align(SH[FH->NumberOfSections - 1].Misc.VirtualSize, OH->SectionAlignment, SH[FH->NumberOfSections - 1].VirtualAddress);
	SH[FH->NumberOfSections].SizeOfRawData = align(sizeOfSection, OH->FileAlignment, 0);
	SH[FH->NumberOfSections].PointerToRawData = align(SH[FH->NumberOfSections - 1].SizeOfRawData, OH->FileAlignment, SH[FH->NumberOfSections - 1].PointerToRawData);
	SH[FH->NumberOfSections].Characteristics = 0xE00000E0;

	SetFilePointer(file, SH[FH->NumberOfSections].PointerToRawData + SH[FH->NumberOfSections].SizeOfRawData, NULL, FILE_BEGIN);
	//end the file right here,on the last section + it's own size
	SetEndOfFile(file);

	//now lets change the size of the image,to correspond to our modifications
	//by adding a new section,the image size is bigger now

	OH->SizeOfImage = SH[FH->NumberOfSections].VirtualAddress + SH[FH->NumberOfSections].Misc.VirtualSize;

	//and we added a new section,so we change the NOS too
	FH->NumberOfSections += 1;
	SetFilePointer(file, 0, NULL, FILE_BEGIN);

	//and finaly,we add all the modifications to the file
	WriteFile(file, pByte, fileSize, &dw, NULL);
	free(pByte);
	CloseHandle(file);
	return true;
}

DWORD align(DWORD size, DWORD align, DWORD addr)
{
	if (!(size % align))
		return addr + size;
	return addr + (size / align + 1) * align;
}

bool AddCode(char *filepath){
	ObfFile = CreateFileA(filepath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (ObfFile == INVALID_HANDLE_VALUE)
		return false;
	DWORD filesize = GetFileSize(ObfFile, NULL);
	BYTE *pByte = new BYTE[filesize];
	DWORD dw;
	ReadFile(ObfFile, pByte, filesize, &dw, NULL);
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pByte;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pByte + dos->e_lfanew);

	PIMAGE_SECTION_HEADER first = IMAGE_FIRST_SECTION(nt);
	PIMAGE_SECTION_HEADER last = first + (nt->FileHeader.NumberOfSections - 1);

	SetFilePointer(ObfFile, last->PointerToRawData, NULL, FILE_BEGIN);

	char * name = (char *)malloc(MAX_PATH);
	GetCurrentDirectoryA(MAX_PATH, name);
	lstrcatA(name, "\\obFun.exe");
	HANDLE hFile = CreateFileA(name, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Could not open file %s (error %d)\n", GetLastError());
		getchar();
		return false;
	}

	DWORD fileSize = GetFileSize(hFile, NULL);
	char * buf = (char *)malloc(fileSize);
	DWORD bytesRead;
	if (!ReadFile(hFile, buf, fileSize, &bytesRead, NULL)) {
		printf("Error reading file (error %d)\n", GetLastError());
		CloseHandle(hFile);
		free(buf);
		return false;
	}

	WriteFile(ObfFile, buf, fileSize, &dw, 0);
	free(buf);
	return TRUE;
}

DWORD RVAToOffset(DWORD pMapping, DWORD dwRVA)
{
		//Defines
		DWORD pNTDst = 0;
		IMAGE_DOS_HEADER* pidh = (IMAGE_DOS_HEADER*)pMapping;
		pNTDst = pMapping + pidh->e_lfanew;
		DWORD pSeDst = pNTDst;
		IMAGE_NT_HEADERS* pinh = (IMAGE_NT_HEADERS*)pNTDst;
		IMAGE_SECTION_HEADER* pish = NULL;

		//First Session
		pSeDst = pNTDst + sizeof(IMAGE_NT_HEADERS);
		pish = (IMAGE_SECTION_HEADER*)pSeDst;

		//Session Count
		UINT nCount = pinh->FileHeader.NumberOfSections;
		DWORD dwPosTmp = 0;

		//Scan
		for (UINT i = 0; i<nCount; i++)
		{
			if (dwRVA >= pish->VirtualAddress)
			{
				dwPosTmp = pish->VirtualAddress;
				dwPosTmp += pish->SizeOfRawData;
			}
			if (dwRVA<dwPosTmp)
			{
				dwRVA = dwRVA - pish->VirtualAddress;
				return dwRVA + pish->PointerToRawData;
			}
			pish = pish + 1;//sizeof(IMAGE_SECTION_HEADER);
		}
		return -1;
}



__int64 myFileSeek(HANDLE hf, __int64 distance, DWORD MoveMethod)
{
	LARGE_INTEGER li;

	li.QuadPart = distance;

	li.LowPart = SetFilePointer(hf,
		li.LowPart,
		&li.HighPart,
		MoveMethod);

	if (li.LowPart == INVALID_SET_FILE_POINTER && GetLastError()
		!= NO_ERROR)
	{
		li.QuadPart = -1;
	}

	return li.QuadPart;
}


DWORD PeSectionEnum(DWORD *ArrayOfaddressesComeFrom, char path[MAX_PATH_LEN])
{
	PIMAGE_DOS_HEADER		pDosHeader;
	PIMAGE_NT_HEADERS		pNtHeaders = {};
	PIMAGE_SECTION_HEADER	pSectionHeader;
	LPVOID					pMappedFile;
	char*					pMappedFileCall;
	char*					pMappedStrAES;
	char*					pMappedPushStr;
	IMAGE_OPTIONAL_HEADER optionalHeader = { 0 };
	DWORD virtualAddressOfSectionObf;
	DWORD sizeOfVirtualSectonObf;
	DWORD filesize = GetFileSize(ObfFile, NULL);
	HANDLE hFileMapping = CreateFileMapping(ObfFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	DWORD dwImageBase = 0;
	LPVOID pHelpFunctionCall = 0;
	LPVOID RVApBaseStringAES = 0;
	LPVOID RVAsetString = 0;
	LPVOID pBaseFunctionAbsoluteCall = 0;
	LPVOID pBaseFunctionRelativeCall = 0;
	DWORD virtualAddressOfCode = 0;
	DWORD sizeOfVirtualSectionOfCode = 0;
	DWORD dwBytesWritten = 0;
	int i = 0;
	if (hFileMapping == 0)
	{
		CloseHandle(ObfFile);
		printf("Couldn't open file mapping with CreateFileMapping()\n");
		return -1;
	}


	const LPVOID	BaseOfpMappedFile = MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (BaseOfpMappedFile == 0)
	{
		CloseHandle(hFileMapping);
		printf("Couldn't map view of file with MapViewOfFile()\n");
		return -1;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)BaseOfpMappedFile;
	if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{

		DWORD dwOffsetPEheader = (pDosHeader->e_lfanew);
		LPVOID lpAddressOfPEheader = (LPVOID *)(BaseOfpMappedFile)+dwOffsetPEheader / 4;												// deleno 4 lebo 4 byti
		pNtHeaders = (PIMAGE_NT_HEADERS)lpAddressOfPEheader;
		optionalHeader = pNtHeaders->OptionalHeader;
		dwImageBase = optionalHeader.ImageBase;

		if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
			return -1;

		for (i = 0, pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders); i < pNtHeaders->FileHeader.NumberOfSections; i++) {

			DWORD VirtualAddressOfSection = (dwImageBase + pSectionHeader[i].VirtualAddress);
			DWORD sizeOfSection = pSectionHeader[i].SizeOfRawData;
			printf("Section Name: %s %x\n", pSectionHeader[i].Name, VirtualAddressOfSection);

			if (!strcmp((char *)pSectionHeader[i].Name, ".text")){
				virtualAddressOfCode = pSectionHeader[i].VirtualAddress;
				sizeOfVirtualSectionOfCode = pSectionHeader[i].SizeOfRawData;
			}
			if (!strcmp((char *)pSectionHeader[i].Name, ".obf")){
				virtualAddressOfSectionObf = pSectionHeader[i].VirtualAddress;
				
				sizeOfVirtualSectonObf = pSectionHeader[i].SizeOfRawData;
			}
		}
	}

	//pBuffer =(char *) pBuffer + virtualAddressOfSectionObf;
	//liDistanceToMove.QuadPart = virtualAddressOfSectionObf;
	printf("stop\n");
	//pMappedFile = (char *)VirtualAlloc(NULL, GetFileSize(hFileMapping, NULL), MEM_COMMIT, 0);
	//DWORD tmp = RVAToOffset((DWORD) BaseOfpMappedFile, ArrayOfaddressesComeFrom[8]);
	
	pMappedFile = BaseOfpMappedFile;
	pMappedFileCall = (char *)BaseOfpMappedFile;	
	pBaseFunctionAbsoluteCall = (char *)(virtualAddressOfSectionObf + 0x328);
	pBaseFunctionRelativeCall = (char *)(virtualAddressOfSectionObf + 0x34A);
	RVApBaseStringAES = (char *)(virtualAddressOfSectionObf + 0xA40);			//mapping string AES....	
	RVAsetString = (char *)(virtualAddressOfSectionObf + 0x8fd);				//mapping push string AES to function	
	//pMappedFile = (char *)pBaseFunctionAbsoluteCall+0x73;
	//pMappedFile = (char *)pMappedFile + virtualAddressOfSectionObf;
	//pMappedFileCall = (char *)pMappedFileCall + 0x18FD;

	
	//pHelpFunctionCall = (char *)pMappedFile + 0xA26;
	//DWORD tmp = RVAToOffset((DWORD)BaseOfpMappedFile, ArrayOfaddressesComeFrom[0]);
	//RVApBaseStringAES = (char *)(virtualAddressOfSectionObf + 0xA40);
	
	//printf("%s", RVApBaseStringAES);
	pMappedPushStr = (char *)pMappedFileCall + RVAToOffset((DWORD)BaseOfpMappedFile, (DWORD)RVAsetString) + sizeof(char);

	//pMappedStrAES = (char *)RVAsetString + dwImageBase; //mapped string AES ......
	*((DWORD *)pMappedPushStr) = (DWORD)RVApBaseStringAES + dwImageBase;
	


	int j = 0;
	
		while (ArrayOfaddressesComeFrom[j]){			//rewrite address of CALL functions 

			pMappedFileCall = (char *)pMappedFileCall + RVAToOffset((DWORD)BaseOfpMappedFile, ArrayOfaddressesComeFrom[j]);

			if (*((WORD *)pMappedFileCall) == 0x15FF){
				*((char *)pMappedFileCall) = 0xE8;
				(char *)pMappedFileCall += 1;
				*((DWORD *)pMappedFileCall) = (DWORD)pBaseFunctionRelativeCall - ArrayOfaddressesComeFrom[j] + 0x69E;
				(char *)pMappedFileCall += 4;
				*((char *)pMappedFileCall) = 0x90;
			}

			if (*((char *)pMappedFileCall) == (char)0xE8){
				(char *)pMappedFileCall += 1;

				*((DWORD *)pMappedFileCall) = (DWORD)pBaseFunctionAbsoluteCall - ArrayOfaddressesComeFrom[j] + 0x69C;
			}
			j++;
			pMappedFileCall = (char *)BaseOfpMappedFile;
		}
	




	CloseHandle(ObfFile);


	HANDLE hFile = CreateFile(path, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Could not open file %s (error %d)\n", path, GetLastError());
		getchar();
		return -2;
	}
	DWORD fileSize=GetFileSize(ObfFile,NULL);
	SetFilePointer(hFile, 0, 0, FILE_BEGIN);
 if (!WriteFile(ObfFile, BaseOfpMappedFile, fileSize, &dwBytesWritten, NULL)){
		printf("Could not write to obj.exe rewritted calls %s (error %d)\n", GetLastError());
		getchar();
		return -2;		
	}

	
		return 0;
}



int MyEncryptFile(
	LPTSTR pszSourceFile,
	LPTSTR pszDestinationFile,
	LPTSTR pKeyFile)
{
	//---------------------------------------------------------------
	// Declare and initialize local variables.
	bool fReturn = false;
	HANDLE hSourceFile = INVALID_HANDLE_VALUE;
	HANDLE hDestinationFile = INVALID_HANDLE_VALUE;
	HANDLE hKeyFile = INVALID_HANDLE_VALUE;

	HCRYPTPROV hProvider=NULL;
	HCRYPTKEY hKey = NULL;
	HCRYPTKEY hExpKey = NULL;
	HCRYPTHASH hHash = NULL;

	PBYTE pbKeyBlob = NULL;
	DWORD dwKeyBlobLen;

	PBYTE pbBuffer = NULL;
	DWORD dwBlockLen;
	DWORD dwBufferLen;
	DWORD dwCount;


	//---------------------------------------------------------------
	// Open the source file. 
	hSourceFile = CreateFileA(
		TEXT(pszSourceFile),
		GENERIC_ALL,          // open for reading
		0,       // share for reading
		NULL,                  // default security
		OPEN_ALWAYS,         // existing file only
		FILE_ATTRIBUTE_NORMAL, // normal file
		NULL);
	if (INVALID_HANDLE_VALUE != hSourceFile)
	{
		printf(
			"The source plaintext file, %s, is open. \n",
			pszSourceFile);
	}
	else
	{
		MyHandleError(
			"Error opening source plaintext file!\n",
			GetLastError());
		goto Exit_MyEncryptFile;
	}

	//---------------------------------------------------------------
	// Open the destination file. 
	hDestinationFile = CreateFileA(
		pszDestinationFile,
		GENERIC_ALL,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE != hDestinationFile)
	{
		printf(
			"The destination file, %s, is open. \n",
			pszDestinationFile);
	}
	else
	{
		MyHandleError(
			"Error opening destination file!\n",
			GetLastError());
		goto Exit_MyEncryptFile;
	}
	hKeyFile = CreateFile(
		pKeyFile,
		FILE_WRITE_DATA,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE != hDestinationFile)
	{
		printf(
			"The destination file, %s, is created. \n",
			pszDestinationFile);
	}
	else
	{
		MyHandleError(
			"Error creates keyfile!\n",
			GetLastError());
		goto Exit_MyEncryptFile;
	}


	//---------------------------------------------------------------
	// Get the handle to the default provider. 


	if (CryptAcquireContext(&hProvider,
							 0, 
							 MS_ENH_RSA_AES_PROV, 
							 PROV_RSA_AES,
							 NULL))
	{
		printf(
			"A cryptographic provider has been acquired. \n");
	}
	else
	{
		MyHandleError(
			"Error during CryptAcquireContext!\n",
			GetLastError());
		goto Exit_MyEncryptFile;
	}
	//---------------------------------------------------------------
	// Create the session key.
		
		//-----------------------------------------------------------
		// No password was passed.
		// Encrypt the file with a random session key, and write the 
		// key to a file. 

		//-----------------------------------------------------------
		// Create a random session key. 
		if (CryptGenKey(
			hProvider,
			ENCRYPT_ALGORITHM,
			KEYLENGTH | CRYPT_EXPORTABLE,
			&hKey))
		{
			printf("A session key has been created. \n");
		}
		else
		{
			MyHandleError(
				"Error during CryptGenKey. \n",
				GetLastError());
			goto Exit_MyEncryptFile;
		}

	
		

		//-----------------------------------------------------------
		// Determine size of the key BLOB, and allocate memory. 
		if (CryptExportKey(
			hKey,
			NULL,
			PLAINTEXTKEYBLOB,
			0,
			NULL,
			&dwKeyBlobLen))
		{
			printf(
				"The key BLOB is %d bytes long. \n",
				dwKeyBlobLen);
		}
		else
		{
			MyHandleError(
				"Error computing BLOB length! \n",
				GetLastError());
			goto Exit_MyEncryptFile;
		}

		if (pbKeyBlob = (BYTE *)malloc(dwKeyBlobLen))		//allocates memory for export key
		{
			printf(
				   "Memory is allocated for the key BLOB. \n");
		}
		else
		{
			MyHandleError("Out of memory. \n", E_OUTOFMEMORY);
			goto Exit_MyEncryptFile;
		}

		//-----------------------------------------------------------
		// Encrypt and export the session key into a simple key 
		// BLOB. 
	if (CryptExportKey(
			hKey,
			NULL,
			PLAINTEXTKEYBLOB,
			0,
			pbKeyBlob,
			&dwKeyBlobLen))
		{
			printf("The key has been exported. \n");
		}
		else
		{
			MyHandleError(
				"Error during CryptExportKey!\n",
				GetLastError());
			goto Exit_MyEncryptFile;
		}


		//-----------------------------------------------------------
		// Write the size of the key BLOB to the destination file. 

		//-----------------------------------------------------------
		// Write the key BLOB to the destination file. 
		if (!WriteFile(
			hKeyFile,
			pbKeyBlob,
			dwKeyBlobLen,
			&dwCount,
			NULL))
		{
			MyHandleError(
				TEXT("Error writing header.\n"),
				GetLastError());
			goto Exit_MyEncryptFile;
		}
		else
		{
			printf(
				"The key BLOB has been written to the "
				"file. \n");
		}

		// Free memory.
		free(pbKeyBlob);
		CloseHandle(hKeyFile);
	
	
	//---------------------------------------------------------------
	// The session key is now ready. If it is not a key derived from 
	// a  password, the session key encrypted with the private key 
	// has been written to the destination file.

	//---------------------------------------------------------------
	// Determine the number of bytes to encrypt at a time. 
	// This must be a multiple of ENCRYPT_BLOCK_SIZE.
	// ENCRYPT_BLOCK_SIZE is set by a #define statement.
	DWORD FileSize=GetFileSize(hSourceFile,NULL);

	dwBlockLen = FileSize - FileSize % ENCRYPT_BLOCK_SIZE;

	//---------------------------------------------------------------
	// Determine the block size. If a block cipher is used, 
	// it must have room for an extra block. 
	if (ENCRYPT_BLOCK_SIZE > 1)
	{
		dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE;
	}
	else
	{
		dwBufferLen = dwBlockLen;
	}

	//---------------------------------------------------------------
	// Allocate memory. 
	if (pbBuffer = (BYTE *)malloc(dwBufferLen))
	{
		printf("Memory has been allocated for the buffer. \n");
	}
	else
	{
		MyHandleError("Out of memory. \n", E_OUTOFMEMORY);
		goto Exit_MyEncryptFile;
	}

	//---------------------------------------------------------------
	// In a do loop, encrypt the source file, 
	// and write to the source file. 
	bool fEOF = FALSE;
	do
	{
		//-----------------------------------------------------------
		// Read up to dwBlockLen bytes from the source file. 
		if (!ReadFile(
			hSourceFile,
			pbBuffer,
			dwBlockLen,
			&dwCount,
			NULL))
		{
			MyHandleError(
				"Error reading plaintext!\n",
				GetLastError());
			goto Exit_MyEncryptFile;
		}

		if (dwCount < dwBlockLen)
		{
			fEOF = TRUE;
		}

		//-----------------------------------------------------------
		// Encrypt data. 

		if (!CryptEncrypt(
			hKey,
			0,
			fEOF,
			0,
			pbBuffer,
			&dwCount,
			dwBufferLen))
		{
			MyHandleError(
				"Error during CryptEncrypt. \n",
				GetLastError());
			goto Exit_MyEncryptFile;
		}

		//-----------------------------------------------------------
		// Write the encrypted data to the destination file. 
		if (!WriteFile(
			hDestinationFile,
			pbBuffer,
			dwCount,
			&dwCount,
			NULL))
		{
			MyHandleError(
				"Error writing ciphertext.\n",
				GetLastError());
			goto Exit_MyEncryptFile;
		}

		//-----------------------------------------------------------
		// End the do loop when the last block of the source file 
		// has been read, encrypted, and written to the destination 
		// file.
	} while (!fEOF);

	fReturn = true;

Exit_MyEncryptFile:
	//---------------------------------------------------------------
	// Close files.
	if (hSourceFile)
	{
		CloseHandle(hSourceFile);
	}

	if (hDestinationFile)
	{
		CloseHandle(hDestinationFile);
	}

	//---------------------------------------------------------------
	// Free memory. 
	if (pbBuffer)
	{
		free(pbBuffer);
	}


	//-----------------------------------------------------------
	// Release the hash object. 
	if (hHash)
	{
		if (!(CryptDestroyHash(hHash)))
		{
			MyHandleError(
				"Error during CryptDestroyHash.\n",
				GetLastError());
		}

		hHash = NULL;
	}

	//---------------------------------------------------------------
	// Release the session key. 
	if (hKey)
	{
		if (!(CryptDestroyKey(hKey)))
		{
			MyHandleError(
				"Error during CryptDestroyKey!\n",
				GetLastError());
		}
	}

	//---------------------------------------------------------------
	// Release the provider handle. 
	if (hProvider)
	{
		if (!(CryptReleaseContext(hProvider, 0)))
		{
			MyHandleError(
				"Error during CryptReleaseContext!\n",
				GetLastError());
		}
	}

	return fReturn;
} // End Encryptfile.








//-------------------------------------------------------------------
//  This example uses the function MyHandleError, a simple error
//  handling function, to print an error message to the  
//  standard error (stderr) file and exit the program. 
//  For most applications, replace this function with one 
//  that does more extensive error reporting.

void MyHandleError(LPTSTR psz, int nErrorNumber)
{
	printf("An error occurred in the program. \n");
	printf("%s\n", psz);
	printf("Error number 0x%x.\n", nErrorNumber);
}
