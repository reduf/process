import argparse
import os
import signal
import sys
import time

from process import *

_PROCESS_IS_64_BITS = sys.maxsize > 2 ** 32

_GENERIC_EXECUTE    = 0x20000000
_GENERIC_WRITE      = 0x40000000
_GENERIC_READ       = 0x80000000

_FILE_SHARE_READ    = 0x00000001
_FILE_SHARE_WRITE   = 0x00000002
_FILE_SHARE_DELETE  = 0x00000004

_CREATE_NEW         = 1
_CREATE_ALWAYS      = 2
_OPEN_EXISTING      = 3
_OPEN_ALWAYS        = 4
_TRUNCATE_EXISTING  = 5

def read_LPCWSTR(proc, addr, maxlen):
    codepoints = proc.read(addr, '%dH' % maxlen)
    try:
        length = codepoints.index(0)
    except ValueError:
        length = maxlen
    codepoints = codepoints[:length]
    return ''.join(chr(c) for c in codepoints)

def read_LPCSTR(proc, addr, maxlen):
    return proc.read(addr, '%ds' % maxlen)

def access_to_str(dwAccess):
    accesses = []
    if dwAccess & _GENERIC_EXECUTE:
        accesses.append('GENERIC_EXECUTE')
    if dwAccess & _GENERIC_WRITE:
        accesses.append('GENERIC_WRITE')
    if dwAccess & _GENERIC_READ:
        accesses.append('GENERIC_READ')
    return ' | '.join(accesses)

def share_mode_to_str(dwShareMode):
    modes = []
    if dwShareMode & _FILE_SHARE_READ:
        modes.append('FILE_SHARE_READ')
    if dwShareMode & _FILE_SHARE_WRITE:
        modes.append('FILE_SHARE_WRITE')
    if dwShareMode & _FILE_SHARE_DELETE:
        modes.append('FILE_SHARE_DELETE')
    return ' | '.join(modes)

def create_disp_to_str(dwCreationDisposition):
    if dwCreationDisposition == _CREATE_NEW:
        return 'CREATE_NEW'
    if dwCreationDisposition == _CREATE_ALWAYS:
        return 'CREATE_ALWAYS'
    if dwCreationDisposition == _OPEN_EXISTING:
        return 'OPEN_EXISTING'
    if dwCreationDisposition == _OPEN_ALWAYS:
        return 'OPEN_ALWAYS'
    if dwCreationDisposition == _TRUNCATE_EXISTING:
        return 'TRUNCATE_EXISTING'
    return 'UNKNOW_DISPOSITION'

def OnCreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttribute, hTemplateFile):
    dir, file = os.path.split(lpFileName)
    access = access_to_str(dwDesiredAccess)
    share_mode = share_mode_to_str(dwShareMode)
    create_disp = create_disp_to_str(dwCreationDisposition)

    print('CreateFile')
    print(f"  Directory: '{dir}'")
    print(f"  File: '{file}'")
    print(f'  Access: {access}')
    print(f'  Share mode: {share_mode}')
    print(f'  Creation disposition: {create_disp}')

@Hook.stdcall(LPVOID, DWORD, DWORD, LPVOID, DWORD, DWORD, LPVOID)
def OnCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttribute, hTemplateFile):
    filename = read_LPCWSTR(proc, lpFileName, 512)
    OnCreateFile(filename, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttribute, hTemplateFile)

@Hook.stdcall(LPVOID, DWORD, DWORD, LPVOID, DWORD, DWORD, LPVOID)
def OnCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile):
    filename = read_LPCSTR(proc, lpFileName, 512)
    OnCreateFile(filename, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttribute, hTemplateFile)

def watch_process(proc):
    kernel32 = ctypes.WinDLL('kernel32.dll')
    hKernel32 = kernel32.GetModuleHandleA(b'kernel32.dll')
    if not hKernel32:
        raise Win32Exception()
    CreateFileW = kernel32.GetProcAddress(hKernel32, b'CreateFileW')
    if not CreateFileW:
        raise Win32Exception()
    CreateFileA = kernel32.GetProcAddress(hKernel32, b'CreateFileA')
    if not CreateFileA:
        raise Win32Exception()

    print(f'hKernel32:   {hKernel32:08X}')
    print(f'CreateFileW: {CreateFileW:08X}')
    print(f'CreateFileA: {CreateFileA:08X}')

    stop = False
    def signal_handler(sig, frame):
        nonlocal stop
        stop = True
    
    prev_handler = signal.signal(signal.SIGINT, signal_handler)

    dbg = ProcessDebugger(proc)
    dbg.add_hook(CreateFileW, OnCreateFileW)
    dbg.add_hook(CreateFileA, OnCreateFileA)

    while not stop:
        dbg.poll(32)

    signal.signal(signal.SIGINT, prev_handler)

if __name__ == '__main__':
    if _PROCESS_IS_64_BITS:
        print('This program only works with 32-bits processes for now.')
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description = 'Start watching a process for CreateFileA & CreateFileW in 32 bits')
    parser.add_argument(
        '--pid',
        type=int,
        metavar='process id',
        help='process id of the target')
    parser.add_argument(
        '--pname',
        type=str,
        metavar='process name',
        help='process name of the target')

    args = parser.parse_args()

    proc = None
    if args.pname is not None:
        processes = GetProcesses(args.pname)
        if len(processes) > 1:
            print(f"Several processes have the name '{args.pname}'")
            for proc in processes:
                print('   - ', proc)
            sys.exit(1)
        proc = processes[0]
    elif args.pid is not None:
        proc = Process(args.pid)

    if proc is None:
        print("Specified '--pname' or '--pid'")
        sys.exit(1)

    if watch_process(proc):
        sys.exit(0)
    else:
        sys.exit(1)
