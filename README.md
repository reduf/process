## process.py

*process* is a Python module meant to interact with remote processes on Windows,
allowing a user of the library to read, write, enumerate modules, create pattern
scanners and more.

There is certainly far more complete solutions like [frida](https://frida.re/),
but this library is very small, was written by me and consequently is very
comfortable for me. I make extensive uses of it while reversing or when testing
small stuff.

### Installing

You can easily install the module with *pip* after downloading or cloning the
repository to the directory `$repo`, by simply doing:
```
> python.exe -m pip install C:\Path\To\The\Repo
```

Alternatively, you can simply copy/paste `process.py` and integrate it in an
other project.

Finally, you can test the installation by:
1. Start an instance of `notepad.exe`.
2. Start a Python 3 instance (both 32 bits or 64 bits should work).
3. Test the following command. (The output will be slightly different)
```
>>> from process import *
>>> GetProcesses('notepad.exe')
[<Process 4976, handle 336 at 0x162159d6c50>]
>>> proc = GetProcesses('notepad.exe')[0]
>>> print(*proc.modules, sep='\n')
0x7ff7f3bd0000 notepad.exe
0x7ffd350d0000 ntdll.dll
0x7ffd33d80000 kernel32.dll
0x7ffd32970000 kernelbase.dll
0x7ffd33130000 gdi32.dll
0x7ffd32940000 win32u.dll
0x7ffd33020000 gdi32full.dll
...
```

### Testing examples without installing
You can simply leverage `PYTHONPATH` environment variable to tell Python where
to find `process.py`. For instance, on Windows you could do:
```
> set PYTHONPATH=%CURRENT_DIR%;%PYTHONPATH%
> python.exe examples\create_file_hook.py --proc notepad.exe
```

### Remote process hooks

One of the most interesting (and less stable) feature offered by *process.py*
is remote process file hooks. Technically, *process.py* starts debugging
the remote process, install software breakpoints and on trigger, call a
user-specified callback. An example can be found at [examples/create_file_hook.py](https://github.com/reduf/process/blob/master/examples/create_file_hook.py).

This feature shine when it's not feasible to manually use a debugger to analysis
a code flow. This could be done, because there is too many breakpoints triggered
and you want some non-trivial conditions.

#### Caveat
This feature is fairly broken, especially in 64 bits and would need additional
care to stabilize.
