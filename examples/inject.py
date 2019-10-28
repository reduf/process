import sys
import ctypes
import process
import argparse

# Work on 32-bits processes with 32-bits python and simlarly,
# on 64-bits processes with 64-bits python.

_kernel32 = ctypes.WinDLL('kernel32.dll')

def InjectDll(proc, name, entry = None):
    """Inject a dll with CreateRemoteThread in the remote process"""
    kernel32 = _kernel32.GetModuleHandleA(b'kernel32.dll')
    if not kernel32:
        raise process.Win32Exception()
    LoadLibraryA = _kernel32.GetProcAddress(kernel32, b'LoadLibraryA')
    if not LoadLibraryA:
        raise process.Win32Exception()
    size = len(name) + 1
    path = proc.mmap(size)
    proc.write(path, name.encode('ascii'), b'\0')
    thread = proc.spawn_thread(LoadLibraryA, path)
    thread.resume()
    retval = thread.join()
    proc.unmap(path)
    return retval

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'Inject the specified dll to a target process')
    parser.add_argument(
        '--dll',
        type=str,
        metavar='path',
        help='path of the dll to inject')
    parser.add_argument(
        '--pname',
        type=str,
        metavar='process name',
        help='process name of the target')
    parser.add_argument(
        '--pid',
        type=int,
        metavar='process id',
        help='process id of the target')

    args = parser.parse_args()

    proc = None
    if args.pname is not None:
        processes = process.GetProcesses(args.pname)
        if len(processes) > 1:
            print(f"Several processes have the name '{args.pname}'")
            for proc in processes:
                print('   - ', proc)
            sys.exit(1)
        proc = processes[0]
    elif args.pid is not None:
        proc = process.Process(args.pid)

    if proc is None:
        print("Specified '--pname' or '--pid'")
        sys.exit(1)

    if args.dll is None:
        print("Specified the parameter '--dll'")
        sys.exit(1)

    if InjectDll(proc, args.dll):
        sys.exit(0)
    else:
        sys.exit(1)
