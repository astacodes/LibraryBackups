import ctypes
from ctypes import *
from ctypes.wintypes import *
from dataclasses import dataclass

NTSTATUS = ctypes.c_ulong
HANDLE = HANDLE
PVOID = ctypes.c_void_p
ULONG = ctypes.c_ulong
ULONG_PTR = ctypes.POINTER(ULONG)
USHORT = ctypes.c_ushort
SIZE_T = ctypes.c_size_t
PSIZE_T = ctypes.POINTER(SIZE_T)
ACCESS_MASK = DWORD
BOOLEAN = BOOL
LPVOID = ctypes.c_void_p
HMODULE = LPVOID

MEM_COMMIT = 4096
MEM_RESERVE = 8192
PAGE_READWRITE = 4

PROCESS_ALL_ACCESS = (
    983040 | 1048576 | 65535
)

class PROCESSENTRY32(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ProcessID", DWORD),
        ("th32DefaultHeapID", ULONG_PTR),
        ("th32ModuleID", DWORD),
        ("cntThreads", DWORD),
        ("th32ParentProcessID", DWORD),
        ("pcPriClassBase", LONG),
        ("dwFlags", DWORD),
        ("szExeFile", CHAR * 260),
    ]

class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", ctypes.c_ulong),
        ("__alignment1", ctypes.c_ulong),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
        ("__alignment2", ctypes.c_ulong),
    ]

class UNICODE_STRING(Structure):
    _fields_ = [("Length", USHORT), ("MaximumLength", USHORT), ("Buffer", PWSTR)]

class OBJECT_ATTRIBUTES(Structure):
    _fields_ = [
        ("Length", ULONG),
        ("RootDirectory", HANDLE),
        ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
        ("Attributes", ULONG),
        ("SecurityDescriptor", PVOID),
        ("SecurityQualityOfService", PVOID),
    ]

class CLIENT_ID(Structure):
    _fields_ = [("UniqueProcess", PVOID), ("UniqueThread", PVOID)]

class SYSTEM_HANDLE_TABLE_ENTRY_INFO(Structure):
    _fields_ = [
        ("ProcessId", ULONG),
        ("ObjectTypeNumber", ctypes.c_byte),
        ("Flags", ctypes.c_byte),
        ("Handle", ctypes.c_ushort),
        ("Object", PVOID),
        ("GrantedAccess", ACCESS_MASK),
    ]

class SYSTEM_HANDLE_INFORMATION(Structure):
    _fields_ = [("HandleCount", ULONG), ("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO * 1)]

class MEMORY_STATE(Enumeration.IntEnum):
    MEM_COMMIT = 4096
    MEM_FREE = 65536
    MEM_RESERVE = 8192
    MEM_DECOMMIT = 16384
    MEM_RELEASE = 32768

class MEMORY_TYPES(Enumeration.IntEnum):
    MEM_IMAGE = 16777216
    MEM_MAPPED = 262144
    MEM_PRIVATE = 131072

kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
ntdll = ctypes.WinDLL("Ntdll.dll", use_last_error=True)

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.restype = PVOID

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [DWORD, BOOL, DWORD]
OpenProcess.restype = HANDLE

CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]
CreateToolhelp32Snapshot.restype = HANDLE

Process32First = kernel32.Process32First
Process32First.argtypes = [HANDLE, POINTER(PROCESSENTRY32)]
Process32First.restype = BOOL

Process32Next = kernel32.Process32Next
Process32Next.argtypes = [HANDLE, POINTER(PROCESSENTRY32)]
Process32Next.restype = BOOL

NtAllocateVirtualMemory = ntdll.NtAllocateVirtualMemory
NtAllocateVirtualMemory.argtypes = [HANDLE, PVOID, ULONG_PTR, PSIZE_T, ULONG, ULONG]

@dataclass
class Process:
    id: int
    name: str

def get_processes() -> list:
    """Retrieve a list of processes currently running on the system."""
    pe32 = PROCESSENTRY32()
    pe32.dwSize = sizeof(pe32)
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    process_list = []
    
    if not Process32First(hProcessSnap, ctypes.byref(pe32)):
        return process_list
    
    process_list.append(Process(pe32.th32ProcessID, pe32.szExeFile.decode()))
    while Process32Next(hProcessSnap, ctypes.byref(pe32)):
        process_list.append(Process(pe32.th32ProcessID, pe32.szExeFile.decode()))
    
    return process_list

class Memory:
    def __init__(self):
        self.process_handle = None

    def open_process(self, process_id: int):
        """Open a process with all access rights."""
        self.process_handle = OpenProcess(PROCESS_ALL_ACCESS, True, process_id)

    def suspend(self):
        """Suspend the process."""
        ntdll.NtSuspendProcess(self.process_handle)

    def resume(self):
        """Resume the process."""
        ntdll.NtResumeProcess(self.process_handle)

    def is_physical_memory(self, address: int) -> bool:
        """Check if the address is physical memory."""
        mbi = MEMORY_BASIC_INFORMATION()
        size = ctypes.sizeof(MEMORY_BASIC_INFORMATION)
        if kernel32.VirtualQueryEx(ctypes.c_void_p(address), ctypes.byref(mbi), size) == size:
            return mbi.State == MEMORY_STATE.MEM_COMMIT and mbi.Type in {MEMORY_TYPES.MEM_MAPPED, MEMORY_TYPES.MEM_PRIVATE}
        return False

    def is_memory_valid(self, address: int) -> bool:
        """Check if the address points to valid memory."""
        mbi = MEMORY_BASIC_INFORMATION()
        result = kernel32.VirtualQueryEx(self.process_handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
        return result != 0 and mbi.State == MEMORY_STATE.MEM_COMMIT

    def read(self, address: int, ctype) -> any:
        """Read data from the process's memory."""
        buffer = ctype()
        if not self._wait_for_valid_memory(address):
            raise ValueError("Memory address is not valid or accessible.")
        status = kernel32.ReadProcessMemory(self.process_handle, ctypes.c_void_p(address), ctypes.byref(buffer), ctypes.sizeof(buffer), None)
        if not status:
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer

    def _wait_for_valid_memory(self, address: int) -> bool:
        """Wait until the memory at the address is valid and accessible."""
        for _ in range(5):
            if self.is_memory_valid(address) and self.is_physical_memory(address):
                return True
            time.sleep(1)
        return False

    def read_long_long(self, address: int) -> int:
        return self.read(address, ctypes.c_ulonglong).value

    def read_bytes(self, address: int, size: int) -> bytes:
        return self.read(address, ctypes.c_char * size).raw

    def read_int(self, address: int) -> int:
        return self.read(address, ctypes.c_int).value

    def read_long(self, address: int) -> int:
        return self.read(address, ctypes.c_long).value

    def read_float(self, address: int) -> float:
        return self.read(address, ctypes.c_float).value

    def allocate_memory(self, size: int, address: int = None) -> PVOID:
        """Allocate memory in the process's address space."""
        return VirtualAllocEx(self.process_handle, ctypes.c_void_p(address), SIZE_T(size), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)

    def write(self, address: int, value: any) -> bool:
        """Write data to the process's memory."""
        if not self._wait_for_valid_memory(address):
            raise ValueError("Memory address is not valid or accessible.")
        size = ctypes.sizeof(value)
        status = kernel32.WriteProcessMemory(self.process_handle, ctypes.c_void_p(address), ctypes.pointer(value), size, None)
        if not status:
            raise ctypes.WinError(ctypes.get_last_error())
        return True

    def write_bytes(self, address: int, value: bytes) -> bool:
        value = (ctypes.c_char * len(value))(*value)
        return self.write(address, value)

    def write_long_long(self, address: int, value: int) -> bool:
        return self.write(address, ctypes.c_longlong(value))

    def write_long(self, address: int, value: int) -> bool:
        return self.write(address, ctypes.c_long(value))

    def write_int(self, address: int, value: int) -> bool:
        return self.write(address, ctypes.c_int(value))

    def write_string(self, address: int, string: str) -> bool:
        """Write a string to the process's memory."""
        buffer = ctypes.create_string_buffer(string.encode('utf-8'))
        bytes_written = SIZE_T(0)
        result = kernel32.WriteProcessMemory(self.process_handle, ctypes.c_void_p(address), buffer, len(buffer), ctypes.byref(bytes_written))
        return result and bytes_written.value == len(buffer)

    def write_double(self, address: int, value: float) -> bool:
        """Write a double to the process's memory."""
        buffer = (ctypes.c_double * 1)(value)
        written = SIZE_T(0)
        result = kernel32.WriteProcessMemory(self.process_handle, ctypes.c_void_p(address), buffer, ctypes.sizeof(buffer), ctypes.byref(written))
        return result and written.value == ctypes.sizeof(buffer)
