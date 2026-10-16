"""Catalogue of APIs that are *commonly abused* — and commonly used legitimately.

A hit is evidence of capability, never proof of intent. Names are matched after
stripping the ANSI/Wide suffix (CreateProcessA/W -> CreateProcess).
"""
from __future__ import annotations

CATALOGUE: dict[str, dict[str, str]] = {
    "process_injection": {
        "VirtualAllocEx": "allocates memory inside another process",
        "WriteProcessMemory": "writes into another process's memory",
        "CreateRemoteThread": "starts a thread inside another process",
        "NtUnmapViewOfSection": "unmaps a process image (used in process hollowing)",
        "QueueUserAPC": "queues code to run in another thread",
        "SetThreadContext": "alters a thread's registers/instruction pointer",
        "NtWriteVirtualMemory": "native-API write into another process",
    },
    "dynamic_api_resolution": {
        "LoadLibrary": "loads a DLL at runtime",
        "LoadLibraryEx": "loads a DLL at runtime",
        "GetProcAddress": "resolves API addresses at runtime (hides real imports)",
    },
    "anti_analysis": {
        "IsDebuggerPresent": "checks whether a debugger is attached",
        "CheckRemoteDebuggerPresent": "checks whether a debugger is attached",
        "NtQueryInformationProcess": "queries process info, often for debugger detection",
        "OutputDebugString": "debug output, sometimes used as an anti-debug trick",
    },
    "persistence": {
        "RegSetValueEx": "writes registry values",
        "RegCreateKeyEx": "creates registry keys",
        "CreateService": "installs a Windows service",
        "StartService": "starts a Windows service",
    },
    "network": {
        "InternetOpen": "WinINet session (HTTP/FTP client)",
        "InternetOpenUrl": "opens a URL via WinINet",
        "InternetReadFile": "reads data from a WinINet handle",
        "URLDownloadToFile": "downloads a URL to disk",
        "WinHttpOpen": "WinHTTP session",
        "WSAStartup": "initialises Winsock networking",
        "connect": "opens a socket connection",
        "send": "sends data on a socket",
        "recv": "receives data on a socket",
    },
    "process_execution": {
        "CreateProcess": "starts another process",
        "ShellExecute": "launches a program or document",
        "ShellExecuteEx": "launches a program or document",
        "WinExec": "legacy process launch",
    },
    "input_capture": {
        "SetWindowsHookEx": "installs a system-wide hook (keyboard/mouse)",
        "GetAsyncKeyState": "polls keyboard state",
        "GetKeyState": "polls keyboard state",
    },
    "privilege": {
        "AdjustTokenPrivileges": "changes token privileges",
        "OpenProcessToken": "opens a process token",
        "LookupPrivilegeValue": "looks up a privilege identifier",
    },
    "cryptography": {
        "CryptEncrypt": "CryptoAPI encryption",
        "CryptAcquireContext": "acquires a CryptoAPI provider",
        "BCryptEncrypt": "CNG encryption",
    },
}

_INDEX: dict[str, tuple[str, str]] = {
    api: (cat, desc) for cat, apis in CATALOGUE.items() for api, desc in apis.items()
}


def match(function_name: str) -> tuple[str, str, str] | None:
    """Return (canonical_api, category, description) or None."""
    candidates = [function_name]
    if function_name.endswith(("A", "W")):
        candidates.append(function_name[:-1])
    for cand in candidates:
        if cand in _INDEX:
            cat, desc = _INDEX[cand]
            return cand, cat, desc
    return None
