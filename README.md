# **Titanox-C++ VERSION**

**`Titanox`** is a hooking framework for iOS. It utilizes `fishhook` for symbol rebinding and `MemX` for memory related tasks. This library supports function hooking, method swizzling, memory patching etc. It does not have any external dependencies and can be used on **non-jailbroken/non-rooted** IOS devices with full functionailty!!!

[Titanox Discord Server](https://discord.gg/VRJDUhBF)

**Join for support!**

*experimental*: This framework also uses ``breakpoint hooks``. Inspired by [The Ellekit Team](https://github.com/tealbathingsuit/ellekit).

## Features
**beta function**: brk hooking.
- **Breakpoint hooks**: Apply upto maximum 6 hooks via breakpoints at runtime.
-> Undetected*

- **Static Inline Hook & Patch**: 
-> Patch unlimited addresses
-> Hook unlimited addresses
-> Be able to call orig in hooks
-> Unlimited
-> Drawback: need to manually replace binary (From documents directory)

- **Function Hooking (by symbol)**: Hook functions and rebind symbols (fishhook). FUNCTIONS MUST BE EXPORTED!!!

- **Virtual Function hooking**: You can hook any pure C++ class virtual function with this. A wrapper for @Aethereux 's MemX.
-> Unlimited
-> Must be virtual
-> By address

- **Method Swizzling**: Replace methods in Objective-C classes.

- **Memory Patching**: Modify memory contents safely.
-> Read
-> Write
-> Patch (Insipred from Dobby's CodePatch, made to work on stock IOS)

- **Bool-Hooking**: Toggle bool values in memory, to the opposite of their original state. bool symbol must be exposed.

- **Is Hooked**: Check if a function is already hooked. *This is done automatically.*

- **Base Address & VM Address Slide Get**: Get ``BaseAddress`` i.e header of the target library and the ``vm addr`` slide.

**LOGS ARE SAVED TO DOCUMENT'S DIRECTORY AS ``TITANOX_LOGS.TXT``. NO NEED TO USE ``NSLog`` or ``Console`` app to view logs! You can take logging from ``utils/utils.mm``.**

## APIs:~

- **fishhook**: A library for symbol rebinding used by @facebook. [fishhook](https://github.com/facebook/fishhook.git)

- **MemX**: A memory management library by @Aethereux. (Modified) [MemX-Jailed](https://github.com/Aethereux/MemX-Jailed.git)

### Documentation:~
# Usage:~

**Static Inline Hook (NEW)**:

**A bit complex to use** ->

* Patch

* Get patched binary

* Replaced original binary with patched one

* re-inject titanox + your tweak/library in the target, but this time the target must be the patched one

**Required!**

```cpp
TitanoxHook hooker("hello.dylib");  // name of target Mach-O
```

**Patching address (Need to activate later)**
```cpp
std::string originalBytes = hooker.applyPatchAtVaddr(
    0x100003f20,
    "00008052C0035FD6"  // mov & ret asm
);
```

**Hook Function**
```cpp
void* originalFunction = hooker.hookFunctionAtVaddr(
    0x100004000,
    (void*)&myReplacementFunc
);
// call orig inside ur hook
```

**Activate patch**
```cpp
bool success = hooker.activatePatchAtVaddr(
    0x100003f20,
    "00008052C0035FD6"
);
if (success) {
    // worked
}
```

**Deactivate patch**
```cpp
bool success = hooker.deactivatePatchAtVaddr(
    0x100003f20,
    "00008052C0035FD6"
);
if (success) {
    // worked
}

```

**VMT (Virtual) Hook usage and helpers (NEW)**
```c++
class QAZ {
public:
    virtual int do_shit(int v) {
        printf("%d\n", v);
        return v;
    }
    virtual ~QAZ() = default;
};

int mt_do_shit(QAZ* s, int v) {
    printf("Hooked value -> %d\n", v);
    return 69420;
}

QAZ* obj = new QAZ();

void* hook = TitanoxHook::vmthookCreateWithNewFunction((void*)&mt_do_shit, 0);
if (!hook) {
    delete obj;
    return;
}

TitanoxHook::vmthookSwap(hook, obj);

int res1 = obj->do_shit(5);

TitanoxHook::vmthookReset(hook, obj);

int res2 = obj->do_shit(5);

TitanoxHook::vmthookDestroy(hook);

void* inv = TitanoxHook::vmtinvokerCreateWithInstance(obj, 0);
if (!inv) {
    delete obj;
    return;
}

typedef int (*fn_t)(QAZ*, int);
fn_t func = *(fn_t*)&inv;

int res3 = func(obj, 10);

TitanoxHook::vmtinvokerDestroy(inv);

delete obj;

// You can call orig and hook as many funcs as you want safely.
// However, they must be virtual. If they aren't, use brk hooks.
// I'd reccommend using brk hooks as a last resort though.
// prioritise this
// Example: Let's say you can't get a class instance for some reason
// You can use brk hooks to hook it, get instance, unhook, and use that to hook whatever target function you have (virtual)

```


**BRK Hook (Aarch64/arm64) FOR C/C++ FUNCTIONS BY ADDRESS**
```cpp
static void (*original_exit)(int) = nullptr;

void hooked_exit(int status) {
    printf("[HOOK] _exit called with status: %d\n", status);
}

void hook_exit() {
    original_exit = (void (*)(int))dlsym(RTLD_DEFAULT, "_exit");
    if (!original_exit) {
        printf("[ERROR] Failed to find _exit symbol\n");
        return;
    }
    if (TitanoxHook::addBreakpointAtAddress((void*)original_exit, (void*)hooked_exit)) {
        printf("[HOOK] _exit hooked successfully\n");
    } else {
        printf("[ERROR] Failed to hook _exit\n");
    }
}

void unhook_exit() {
    if (!original_exit) {
        printf("[ERROR] Cannot unhook _exit: original_exit is NULL\n");
        return;
    }
    if (TitanoxHook::removeBreakpointAtAddress((void*)original_exit)) {
        printf("[HOOK] _exit unhooked successfully\n");
    } else {
        printf("[ERROR] Failed to unhook _exit\n");
    }
}
```

**HAS a limit to 6 hooks. Unhooking frees those slots.**

**Function Hooking by fishhook (static) C/C++ Functions by SYMBOL**
Hook a function by symbol using fishhook (Will hook in main task process):

```cpp
TitanoxHook::hookStaticFunction("_funcsym", newFunction, "libName.dylib", &oldFunction);
```

**Hook a function in a specific library**:(Will hook in target library/Binary specified in 'inLibrary'.) Full name is required. i.e extension if any e.g .dylib. It auto loads in the target if not loaded in!
Can be the main executable or a loaded library in the application.**

```cpp
TitanoxHook::hookStaticFunction("_Zn5Get6Ten", newFunction, "ShooterGame", &oldFunction);
```

**Method Swizzling**
Swizzle a method in an objc class:

```cpp
TitanoxHook::swizzleMethod("origmethod:arg1:arg2", "yourselector", "targetclasssname");
```

**Method Overriding**
Over-ride a method in an objc class with a new implementation:

```cpp
TitanoxHook::overrideMethodInClass(
    "targetclass",
    "targetmethod",
    (void*)newFunction,
    (void**)&oldFunction
); // bit like fishhook
```

**Memory Modifications**
R/W memory at specified addresses.

```cpp
mach_vm_address_t targetAddress = 0x102345678;
uint8_t buffer[16] = {0};
mach_vm_size_t size = sizeof(buffer);

if (TitanoxHook::readMemoryAt(address, buffer, size)) {
    printf("Read successful.\n");
}

// OR

uintptr_t addr = 0x100;
uint8_t buf[16];
TitanoxHook::MemXreadMemory(addr, buf, sizeof(buf));
```

**Read String**
```cpp
uintptr_t strAddr = 0x102;
std::string result = TitanoxHook::MemXreadString(strAddr, 64); // size
log("Read string: %s\n", result.c_str());
```

**Write**
```cpp
mach_vm_address_t address = 0x1000000000;
uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
mach_vm_size_t size = sizeof(data);

if (TitanoxHook::writeMemoryAt(address, data, size)) {
    printf("Write successful.\n");
}


// OR

TitanoxHook::MemXwriteMemory(addr, "12345", "int");
```

**Is Address Valid?**
```cpp
uintptr_t addr = 0x100;
if (TitanoxHook::MemXisValidPointer(addr)) {
    printf("Valid pointer.\n");
}
```

**Change Memory protections with custom vm functions**
```cpp
mach_vm_address_t addr = 0x449ef78;
mach_vm_size_t size = 0x1000;
vm_prot_t prot = VM_PROT_READ | VM_PROT_WRITE;
kern_return_t res = TitanoxHook::protectMemoryAt(addr, size, false, prot);
```

**Patch Memory**:
```cpp
uint32_t nop[] = {0x1F2003D5};
void* addr = (void*)0x1000;
TitanoxHook::patchMemoryAtAddress(addr, (uint8_t*)nop, sizeof(nop));
```

**Boolean Hooking**
Toggle a boolean value in a dynamic library (add .dylib ext) / executable:

```cpp
TitanoxHook::hookBoolByName("bool-symbol", "TargetBinary");
```

**Base Address & VM Address Slide**
Get the base address of a dynamic library (add .dylib ext) / executable:

```cpp
uint64_t base = TitanoxHook::getbaseofbinary("libName.dylib");

// or memx one

```

Get the VM address slide of a dynamic library (add .dylib ext) / executable:

```cpp
intptr_t slide = TitanoxHook::getvmslideofbinary("libName.dylib");
```



## Compiling From Source:~

### Theos:~
[theos](https://theos.dev): A cross-platform build system for creating iOS, macOS, Linux, and Windows programs.
* Install theos based on your device.

**Prequisites:~**

For linux: ``sudo apt install bash curl sudo``. 
***Can vary depending on distribution. This is for kali/ubuntu/debian or other debian based distros.***

For macOS: Install [brew](https://brew.sh) & xcode-command-line utilities, aswell as xcode itself.
P.S: You do not need to code in xcode itself, but the installation for it is mandatory.

For Windows: Install WSL (Window's subsystem for Linux) and use any linux distribution. I recommend ``Ubuntu``.

Once that is done, copy paste this command:
```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/theos/theos/master/bin/install-theos)"
```
It will install theos for you. wait until installation is completed.

**For more detailed/well-explained steps, please head over to [theos's official documentation](https://theos.dev/docs) for installing theos on your platform**

## Compiling:~
* You can use **Theos** to build your own jailbroken or jailed/non-jailbroken IOS tweaks, frameworks, libraries etc.
* For this, git clone this repo:
```bash
git clone https://github.com/Ragekill3377/Titanox-CPP.git
```
* cd into the directory:
```bash
cd Titanox-CPP/Tit*/lib*
```

* Open ``Makefile`` in any editor.
* remove `theos` variable set in ``Makefile`` as ``/home/rage/theos``, or just replace that path with the path to your own theos.
* save the Makefile.
* Run ``build`` to compile the titanox library:
```bash
./build
```

You will get a .deb file in your output directory i.e ``packages``. Also, it will move the *.dylib* to your $THEOS/lib directory as **libtitanox.dylib** (Unless you changed TWEAK_NAME in ``Makefile``).
You can use this to link against your own code, or even you could merge Titanox's sources with your own.

### Using release builds:~
* Navigate to releases
* Download the latest ``libtitanox.dylib``.
* Put ``libtitanox.dylib`` in /home/{username}/theos/lib
* Link against ``libtitanox`` and include the header.

**In a Theos Makefile:**
```make
$(TWEAK_NAME)_LDFLAGS = -L$(THEOS)/lib -ltitanox -Wl,-rpath,@executable_path # TODO: Change 'YOURTWEAKNAME' to your actual tweak name.
```

This will link *libtitanox.dylib*. From there, you can inject your own library or binary which uses Titanox, & Titanox itself.

### License:
You are free to use this code and modify it however you want. I am not responsible for any illegal or malicious acts caused by the use of this code.

# **DISCLAIMER**
**Titanox is in no way a JAILBREAK or a TWEAK INJECTION LIBRARY.**  
It is a **HOOKING framework for IN-APP.**

This is used to, say, make modifications to processes **within a sandbox** however you'd like—giving you more freedom while still respecting iOS constraints.

The **libhooker functionality DID NOT make jailbroken tweaks work without a jailbreak.**  
This was **removed** because it did not function properly outside of a jailbreak.  

**Please do not spread misinformation without consulting the developer or contributors first on what can be said about Titanox.**

Titanox **can** be used for what was mentioned—**IF** you have a jailbreak! But you guys don't.  
Maybe you want **mods for apps,** maybe you want to **patch things in apps,** maybe you want to **hook functions in apps.**
That's what **Titanox is for.**

Titanox is meant for **developers** to create tools like that for users.

Titanox is **still being tested and developed.** Expect bugs. Report them.
Don't expect everything to be working well. For bug reports, you must test multiple cases and see if the issue is a bug with Titanox or something you're doing wrong.
**Titanox feels...empty now. By this, I mean the features. I would love recommendations (feasible, ofcourse) for Titanox and community PRs!**

# Credits:
**Ragekill3377** -> Owner + Main Developer

**Aethereux** -> developer

**timi2506** -> developer

**WhySooooFurious** -> developer

**UnrealSrcZ** -> developer

**Speedyfriend67** -> developer
