#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <mscoree.h>
#include <MetaHost.h>
#include <strsafe.h>
#include <string>
#include <iostream>

// Include necessary directories for .NET
#import "mscorlib.tlb" raw_interfaces_only, auto_rename \
    high_property_prefixes("_get","_put","_putref") \
    rename("ReportEvent", "InteropServices_ReportEvent")
#pragma comment(lib, "mscoree.lib")
using namespace mscorlib;

ICorRuntimeHost* g_Runtime = NULL;
HANDLE g_OriginalStdOut = INVALID_HANDLE_VALUE;
HANDLE g_OriginalStdErr = INVALID_HANDLE_VALUE;
HANDLE g_hNamedPipe = INVALID_HANDLE_VALUE;
LPCSTR PipeName = "\\\\.\\pipe\\myNamedPipe";

// Create a named pipe server
BOOL CreateNamedPipeServer() {
    g_hNamedPipe = CreateNamedPipeA(
        PipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        512,
        512,
        0,
        NULL
    );

    if (g_hNamedPipe == INVALID_HANDLE_VALUE) {
        printf("CreateNamedPipe failed with %d\n", GetLastError());
        return FALSE;
    }

    printf("Named pipe created successfully.\n");
    return TRUE;
}

// Read output from the named pipe
BOOL ReadFromPipe(std::string& output) {
    CHAR buffer[512];
    DWORD bytesRead = 0;

    if (!ConnectNamedPipe(g_hNamedPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        printf("ConnectNamedPipe failed with %d\n", GetLastError());
        return FALSE;
    }

    printf("Client connected. Reading from pipe...\n");

    while (ReadFile(g_hNamedPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
        buffer[bytesRead] = '\0'; // Null-terminate the string
        output += buffer;
        if (bytesRead < sizeof(buffer) - 1)
            break; // Exit loop if all data has been read
    }

    if (GetLastError() != ERROR_BROKEN_PIPE) {
        printf("ReadFile failed with %d\n", GetLastError());
    }

    DisconnectNamedPipe(g_hNamedPipe);
    return TRUE;
}

HRESULT LoadCLR() {
    HRESULT hr;
    ICLRMetaHost* pMetaHost = NULL;
    ICLRRuntimeInfo* pRuntimeInfo = NULL;
    BOOL bLoadable;

    hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMetaHost);
    if (FAILED(hr)) {
        printf("Failed to create CLR instance. HRESULT: 0x%lx\n", hr);
        return hr;
    }

    hr = pMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (LPVOID*)&pRuntimeInfo);
    if (FAILED(hr)) {
        printf("Failed to get CLR runtime. HRESULT: 0x%lx\n", hr);
        pMetaHost->Release();
        return hr;
    }

    hr = pRuntimeInfo->IsLoadable(&bLoadable);
    if (FAILED(hr) || !bLoadable) {
        printf("CLR runtime is not loadable. HRESULT: 0x%lx\n", hr);
        pRuntimeInfo->Release();
        pMetaHost->Release();
        return hr;
    }

    hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (LPVOID*)&g_Runtime);
    if (FAILED(hr)) {
        printf("Failed to get CLR runtime host. HRESULT: 0x%lx\n", hr);
        pRuntimeInfo->Release();
        pMetaHost->Release();
        return hr;
    }

    hr = g_Runtime->Start();
    if (FAILED(hr)) {
        printf("Failed to start CLR. HRESULT: 0x%lx\n", hr);
        g_Runtime->Release();
        pRuntimeInfo->Release();
        pMetaHost->Release();
        return hr;
    }

    printf("CLR v4.0.30319 loaded successfully.\n");

    pRuntimeInfo->Release();
    pMetaHost->Release();
    return S_OK;
}

HRESULT CallMethod(std::string assembly, std::string args, std::string& outputString) {
    HRESULT hr = S_OK;
    SAFEARRAY* psaArguments = NULL;
    IUnknownPtr pUnk = NULL;
    _AppDomainPtr pAppDomain = NULL;
    _AssemblyPtr pAssembly = NULL;
    _MethodInfo* pEntryPt = NULL;
    SAFEARRAYBOUND bounds[1];
    SAFEARRAY* psaBytes = NULL;
    LONG rgIndices = 0;
    wchar_t* w_ByteStr = NULL;
    LPWSTR* szArglist = NULL;
    int nArgs = 0;
    VARIANT vReturnVal;
    VARIANT vEmpty;
    VARIANT vtPsa;

    SecureZeroMemory(&vReturnVal, sizeof(VARIANT));
    SecureZeroMemory(&vEmpty, sizeof(VARIANT));
    SecureZeroMemory(&vtPsa, sizeof(VARIANT));
    vEmpty.vt = VT_NULL;
    vtPsa.vt = (VT_ARRAY | VT_BSTR);

    printf("Loading the default app domain...\n");
    hr = g_Runtime->GetDefaultDomain(&pUnk);
    if (FAILED(hr)) {
        printf("Failed to get default app domain. HRESULT: 0x%lx\n", hr);
        return hr;
    }

    hr = pUnk->QueryInterface(IID_PPV_ARGS(&pAppDomain));
    if (FAILED(hr)) {
        printf("Failed to get app domain. HRESULT: 0x%lx\n", hr);
        return hr;
    }

    bounds[0].cElements = (ULONG)assembly.size();
    bounds[0].lLbound = 0;

    psaBytes = SafeArrayCreate(VT_UI1, 1, bounds);
    SafeArrayLock(psaBytes);
    memcpy(psaBytes->pvData, assembly.data(), assembly.size());
    SafeArrayUnlock(psaBytes);

    printf("Loading the assembly into the app domain...\n");
    hr = pAppDomain->Load_3(psaBytes, &pAssembly);
    SafeArrayDestroy(psaBytes);
    if (FAILED(hr)) {
        printf("Failed to load assembly. HRESULT: 0x%lx\n", hr);
        return hr;
    }

    printf("Retrieving entry point of the assembly...\n");
    hr = pAssembly->get_EntryPoint(&pEntryPt);
    if (FAILED(hr)) {
        printf("Failed to get entry point. HRESULT: 0x%lx\n", hr);
        return hr;
    }

    if (args.empty()) {
        vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, 0);
    }
    else {
        w_ByteStr = (wchar_t*)malloc((sizeof(wchar_t) * args.size() + 1));
        mbstowcs(w_ByteStr, args.c_str(), args.size() + 1);
        szArglist = CommandLineToArgvW(w_ByteStr, &nArgs);

        vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, nArgs);
        for (long i = 0; i < nArgs; i++) {
            BSTR strParam = SysAllocString(szArglist[i]);
            SafeArrayPutElement(vtPsa.parray, &i, strParam);
        }
    }

    psaArguments = SafeArrayCreateVector(VT_VARIANT, 0, 1);
    hr = SafeArrayPutElement(psaArguments, &rgIndices, &vtPsa);

    printf("Invoking the assembly entry point...\n");
    hr = pEntryPt->Invoke_3(vEmpty, psaArguments, &vReturnVal);

    if (FAILED(hr)) {
        printf("Failed to invoke entry point. HRESULT: 0x%lx\n", hr);
    }

    VariantClear(&vReturnVal);
    if (psaArguments)
        SafeArrayDestroy(psaArguments);
    if (pAssembly)
        pAssembly->Release();

    return hr;
}

std::string ExecuteAssembly(std::string& assembly, std::string args) {
    HRESULT hr;
    std::string output;

    if (!CreateNamedPipeServer()) {
        printf("Failed to create named pipe\n");
        return "Pipe creation failed";
    }

    hr = LoadCLR();
    if (FAILED(hr)) {
        printf("Failed to load CLR: HRESULT 0x%lx\n", hr);
        return "CLR Load Failure";
    }

    printf("Successfully loaded CLR.\n");

    std::string methodOutput;
    hr = CallMethod(assembly, args, methodOutput);
    if (FAILED(hr)) {
        printf("Failed to execute method: HRESULT 0x%lx\n", hr);
        return "Method Execution Failed";
    }

    if (!ReadFromPipe(output)) {
        printf("Failed to read output from named pipe.\n");
    }

    CloseHandle(g_hNamedPipe);
    return output;
}

int main() {
    DWORD lpNumberOfBytesRead = 0;
    DWORD dwFileSize = 0;
    PVOID lpFileBuffer = NULL;
    std::string args = "";

    HANDLE hFile = CreateFileA("Z:\\Hacking\\Seatbelt\\Seatbelt\\bin\\Release\\Seatbelt.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open file. Error: %d\n", GetLastError());
        return 1;
    }

    dwFileSize = GetFileSize(hFile, NULL);
    lpFileBuffer = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!ReadFile(hFile, lpFileBuffer, dwFileSize, &lpNumberOfBytesRead, NULL)) {
        printf("Failed to read file. Error: %d\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    std::string assemblyStr((char*)lpFileBuffer, lpNumberOfBytesRead);
    std::string response = ExecuteAssembly(assemblyStr, args);

    VirtualFree(lpFileBuffer, dwFileSize, MEM_DECOMMIT | MEM_RELEASE);
    CloseHandle(hFile);

    printf("Output from assembly: %s\n", response.c_str());
    return 0;
}
