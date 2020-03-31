#include <windows.h>
#include "stdio.h"
typedef int(*lpAddFun)();
int main(int argc, char* argv[]) { 
	HINSTANCE hDll;
	lpAddFun addFun;
	hDll = LoadLibrary("Dll1.dll");
	if (hDll != NULL) {
		addFun = (lpAddFun)GetProcAddress(hDll, "add"); 
		if (addFun != NULL) { int result = addFun();  
		printf("%d", result);
		}  
		FreeLibrary(hDll);
	} 
	return 0; 
}