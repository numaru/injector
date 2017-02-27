# Injector

A python DLL injector able to call exported functions.

## Minimal example

```python
from injector import Injector


injector = Injector()

# Enter your PID and DLL path.
pid = 42
path_dll = "path/to/dll"

# Load the process from a given pid.
injector.load_from_pid(pid)

# Inject the DLL.
injector.inject_dll(path_dll)

# Unload to close the process handle.
injector.unload()
```

## More advanced

This example show how to use `create_process()` to create a process and `call_from_injected()` to call exported function from the injected DLL.

```python
from injector import Injector


injector = Injector()

# Enter your paths.
path_exe = "path/to/exe"
path_dll = "path/to/dll"

# Create the given process
pid = injector.create_process(path_exe)

# Load it.
injector.load_from_pid(pid)

# Inject the DLL.
dll_addr = injector.inject_dll(path_dll)

# Calls some exported functions from the DLL.
injector.call_from_injected(path_dll, dll_addr, "function_int", struct.pack("I", 42))
injector.call_from_injected(path_dll, dll_addr, "function_short", struct.pack("H", 21))

# Unload to close the process handle.
injector.unload()
```

The arguments are given throught `void *` to C functions.

```c
__declspec(dllexport) void function_int(void * args)
{
    int argument = *((int *)args);

    // ...
}

__declspec(dllexport) void function_short(void * args)
{
    short argument = *((short *)args);

    // ...
}
```

# Injector CLI

You can use this small script to create a process from a path and inject a dll in it.

```python
python injector_cli.py path/to/exe path/to/dll
```

# Known issues

 - You shouldn't be able to inject a x86 process with a 64bit python and vice versa.
