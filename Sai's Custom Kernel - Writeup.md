# Sai's Custom Kernel - Writeup

This is a writeup of the intended solution if you are struggling / don't have enough time to spend fully solving my challenge. My answer to cyber2 is on here. To access this, successfully figure out where it is hidden and how it is hidden.

Check the end of this page to find the solution TL;DR / summary.



## Running Instructions

Unzip the file

(Hints) Different ways of running the system 

```bash
$ qemu-system-i386 -kernel mykernel # Normal

$ qemu-system-i386 -kernel mykernel -gdb tcp::1234 # Debugging
$ gdb ./mykernel
(gdb) target remote localhost:1234
```



## Reversing

### Basic Static Reversing 

Performing strings on the binary reveals a base64 string that when decoded appears encrypted

```bash
$ strings mykernel
...
PkETGR0KCEQTGBYAUlkbBBdVBgERWUJBV0EWFRsZDkMYVBANBwhSQBwBFhkXSQMQQV0SURJBHRkMQwRLQw0KAFJAHBYXVRQcGB9EXV5aGQZSGgYHHkEGCkxFOw0RAA8cFx8RWVlZW0BXCAFXCwYITBYKB0UbWVMSChkeSRUVQV5FExoEUgMGQx5DBxwQFgZMHQFDARoMVBBDRUBaFAARHgwQS0QNWRYNFw0cFQYHEx0dF0oRQUoEFRcaRUMcRQoaCkU7DRIIQxABGREaRFBeXw5BGxkdBhlIEA0HAVJEHUtDORcIBhdEX1UTFgMdAh1DH0UGCgdFBkIDDAAGUh4dFUERVFoZAB4bEEMOQwIbDgBSQBZFFxpSHBodSENBRxYPFlcBDBwNDgBCBh1AAxAXEABJGwlIQ1NHEhJSHgdDCEINExcLEVkaCg1VBQAAEQ1CXVUDFhMFDEMKXkMOBwkeDRIWQx0dHlQNRVQSQBgHBgAIEQ4NDhgMDAJYHwQXEAFJABFIEVpSBQUFFhsGS14MWQcDFEQQDAYbBgUNVw13R0EDCRcFBAwZSE9ZK0UQSB8MBgMXSQARSBFbXRMIBB4NFgpBQwkQChhIEBFDFAZJABFIEVddE0EdEUkXA0hDHwsLE0FTHAYUAEkDEEFdElIbEh1XCwZLSBsNEAAfSB8cQxMHBRIQQV1bXRBNUhYaQyINFBAOCVJPFkUCFx4MVA1CEUFbGBYRFhoGS1kLHEIOHEIECQYRFQxUMA1ZU0USQRUWAA0OSUMfEAofDQcNBlURBgELXlQSWhlBE1cKEQ5MFxAUAFJOHAsXEAodWlknO3sTFg8GHgoKG0wXHEIRGkhTLA0THRsZGFlYXV1XMhcUHBECWRpZAwsWDQcNBlU7BxIWX1xTRx4OHFc7ChhGQzQDCxNKFggGGwZJGRZJRF5WBEEGGEkBDg0XEQdFH0IAEUMWGggYFUhfVVoZBl5XCBBLWQscG0UTXQMJGlUBDBcMX1hGSlcVHVcIQxlIAhVPCRtLFkUAGhwdEQFZHxJnHwQBEkkXBF0KGhFFE18WRRYbGxgBHA1FXRMSABEfSQIFSUMcFAAAVFMWCgEHCAAQQl8eEwUEAwIAEQJDBFkGHBxMHgwAHAYQVBhDVRJHHwRSFgsKB0QXAEIRHQ0SAQIFBkkQDEgRRlxXAh0ZHQYTWRYYDkUbQxUKERgTHR0WQx8SelcDFxsABh1IQw0KDAENBAwPGVILEVlOWVNfGwQcEAANDA0CCkIMBg0aFkMbHR1UGA1CWVobDVIDAQIfDQAYDEUQSFMKAQETABocSRFGWwUOBxABQxhCDxwOHFJBFgQRGxsHE1lZWVdcBRhSFRwXS18GCBcMAEgARQYNBgwaCkRHVxMHExMUHQoISEMYDAFSTAMVDxwRCAAQQl8cEzYSUgAMDwcNAgpCERpEAElDPFIIGVlBXl1YHg8VVw8MGVoCCwZFBkJTChUQAAobFERfVRMDCRdXCgsKQQ8cDAIXDRwDQxcXABoeDVhcVxIRFxkNBgVZQxgMAVJBFgQVHBwOVBFCXFcdVyhSAwEKBUZDDQoEBg0cFwQUHAAHEENWEl4OQQYeBAZHDQAWDQ4bQxRFAhsWSRcVSFBcWhkGUgAADwcNARxCBAENGwQREVIIB1lBVFNBGQgcEEkXA0gMCxtFFF8cCEMBGgxUGkJEQEASQRsDGgYHS01ZaA==
...
```



Performing `file` on the binary reveals it is a stripped statically linked 32 bit binary

```bash
$ file mykernel
mykernel: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, stripped
```



### EntrySetupFunction

Opening the file in Ghidra, you can also see the file is stripped. Running the kernel using QEMU gives no other hints.

Selecting the `entry` function decompiles to 

```c
void entry(void)

{
    DAT_0010401c = 0x10036d;
    FUN_001002de();
    do {
                    /* WARNING: Do nothing block with infinite loop */
    } while( true );
}
```

`FUN_001002de` looks to be a setup function, so I renamed it as such - `EntrySetupFunction`.

Decompiling that function gives

```c
void EntrySetupFunction(void)

{
    int iVar1;
    int iVar2;
    
    FUN_001002b4();
    iVar2 = 0;
    while( true ) {
        iVar1 = FUN_001003e8(&DAT_00101c20);
        if (iVar1 <= iVar2) break;
        FUN_0010059a((int)(char)((&DAT_00101c20)[iVar2] + -0x80));
        iVar2 = iVar2 + 1;
    }
    do {
                    /* WARNING: Do nothing block with infinite loop */
    } while( true );
}
```



Since the global variable`DAT_00101c20`  is referenced a couple times, I decided to take a look at it, but it appeared to be garbage. However, after applying `-0x80` to it, it decoded into a string. This appears to be the same as `XOR 0x80` (what I did in the source code).

```asm
     00101c20 d3            ??        D3h
     00101c21 e1            ??        E1h
     00101c22 e9            ??        E9h
     00101c23 a7            ??        A7h
     00101c24 f3            ??        F3h
       
     ... Becomes
     00101c20 d3            ??        53h (D3 - 80)
     00101c21 e1            ??        61h (E1 - 80)
     00101c22 e9            ??        69h (E9 - 80)
     00101c23 a7            ??        27h (A7 - 80)
     00101c24 f3            ??        73h (F3 - 80)
```

Translating the whole data we get

`Sai's Custom Kernel ... it only takes keyboard input for now\n`

This means that `FUN_0010059` must be a `puts` alternative, so I renamed it as such.

Looking closer at `FUN_001003e8`, we realise that it's an alternative for a `strlen` function

```c
int FUN_001003e8(char *param_1)
{
    int iVar1;
    
    if (*param_1 != '\0') {
        iVar1 = 0;
        do {
            iVar1 = iVar1 + 1;
        } while (param_1[iVar1] != '\0');
        return iVar1;
    }
    return 0;
}
```



### SetupFunction

So the latter part of `EntrySetupFunction` focusses on displaying the message. This means that `FUN_001002b4` must be the true setup function for this kernel, so I named it `SetupFunction`.

```c
void SetupFunction(void)

{
    FUN_00100160();
    FUN_00100143();
    FUN_001004a0(0xc,0);
    return;
}

```



Taking a look at `FUN_00100160`, we can see that it is calling the same function multiple times.

```c
void FUN_00100160(void)
{
    undefined4 local_14;
    undefined4 local_10;
    
    DAT_00105148 = 0x36f;
    DAT_0010514e = 0x10;
    DAT_0010514a = 8;
    DAT_0010514d = 0x8e;
    FUN_00100441(0x20,0x11);
    FUN_00100441(0xa0,0x11);
    FUN_00100441(0x21,0x20);
    FUN_00100441(0xa1,0x28);
    FUN_00100441(0x21,0);
    FUN_00100441(0xa1,0);
    FUN_00100441(0x21,1);
    FUN_00100441(0xa1,1);
    FUN_00100441(0x21,0xffffffff);
    FUN_00100441(0xa1,0xffffffff);
    local_14 = 0x50400800;
    local_10 = 0x10;
    FUN_00100375(&local_14);
    return;
}
```

If you are familiar with kernel development, you will realise this function is writing to ports. However this is also evident if you take a closer look, yet again, at `FUN_00100441`.

```c
# ASM
00100441 8b 54 24      MOV       EDX,dword ptr [ESP + param_1]
04
00100445 8b 44 24      MOV       EAX,dword ptr [ESP + param_2]
08
00100449 ee            OUT       DX,AL
0010044a c3            RET


# Decompiled
undefined8 FUN_00100441(undefined4 param_1,undefined4 param_2)

{
    out((short)param_1,(char)param_2);
    return CONCAT44(param_1,param_2);
}
```

The `out` instruction outputs byte in `AL` to I/O port address in `DX`  - [source](https://c9x.me/x86/html/file_module_x86_id_222.html)

`FUN_00100375` uses the assembly instructions `LIDT (param_1)`.

`LIDT` stands for Load value into Interrupt Descriptor Table. This means that this function registering an interrupt handler.

```asm
                         *******************************************************
                         *                      FUNCTION                       *
                         *******************************************************
                         undefined FUN_00100375(undefined4 param_1)
           undefined       AL:1         <RETURN>
           undefined4      Stack[0x4]:4 param_1                            XREF[1]:   00100375(R)  
                         FUN_00100375                              XREF[1]:   FUN_00100160:0010023e(c)  
      00100375 8b 54 24      MOV       EDX,dword ptr [ESP + param_1]
               04
      00100379 0f 01 1a      LIDT      dword ptr [EDX]
      0010037c fb            STI
      0010037d c3            RET

```



Taking a closer look at the assembly for this function, I noticed a difference in the decompilation and assembly. The assembly is as follows

```asm
...
      0010016a 81 c3 9a      ADD       EBX,0x1e9a
               1e 00 00
      00100170 c7 c6 40      MOV       ESI,DAT_00105040                           = ??
               50 10 00
      00100176 c7 c0 6f      MOV       EAX,LAB_0010036f
               03 10 00
      0010017c 66 89 86      MOV       word ptr [ESI + 0x108]=>DAT_00105148,AX    = ??
               08 01 00 
               00
      00100183 c1 e8 10      SHR       EAX,0x10
      00100186 66 89 86      MOV       word ptr [ESI + 0x10e]=>DAT_0010514e,AX    = ??
               0e 01 00 
               00
      0010018d 66 c7 86      MOV       word ptr [ESI + 0x10a]=>DAT_0010514a,0x8   = ??
               0a 01 00 
               00 08 00
      00100196 c6 86 0d      MOV       byte ptr [ESI + 0x10d]=>DAT_0010514d,0x8e  = ??
               01 00 00 
               8e
...
```

As you can see, `DAT_00105148` is only loaded with the lower word `AX`. Taking a look at `LAB_0010036f`, I see

```asm
                         LAB_0010036f                              XREF[1]:   FUN_00100160:00100176(*)  
      0010036f e8 d5 fe      CALL      FUN_00100249                               undefined FUN_00100249()
               ff ff
      00100374 cf            IRETD

```

This appears to be the registered interrupt, as the `IRETD` instruction is used for interrupts. 



### Interrupt Handler Function

Taking a look at the interrupt handler function `FUN_00100249`, renamed to `InterruptHandlerFunction` shows:

```c
void InterruptHandlerFunction(void)

{
    char cVar1;
    uint uVar2;
    
    out_wrapper(0x20,0x20);
    uVar2 = FUN_0010044b(100);
    if ((uVar2 & 1) != 0) {
        cVar1 = FUN_0010044b(0x60);
        if (-1 < cVar1) {
            puts((int)(char)(&DAT_00101ba0)[cVar1]);
            FUN_00100086((int)(char)(&DAT_00101ba0)[cVar1]);
        }
    }
    return;
}
```

This function looks like its printing something to the screen each time an interrupt is called ... this could be the keyboard interrupt handler!



Decompiling `FUN_0010044b` reveals that it is a wrapper for the `in` assembly instruction, which reads from the I/O port.

```c
undefined FUN_0010044b(undefined2 param_1)
{
    undefined uVar1;
    
    uVar1 = in(param_1);
    return uVar1;
}
```

This means that `uVar2` could be whether there has been a keypress and `cVar1`, the key pressed. This is then printed to the screen - which we can successfully see happen. `DAT_00101ba0` is just an array of all the characters that can be pressed.

The interesting function is `FUN_00100086`, which takes the key pressed as input.

```c
void FUN_00100086(char param_1)
{
    int iVar1;
    undefined1 *puVar2;
    bool bVar3;
    
    iVar1 = strlen(&DAT_00105000);
    if (iVar1 < 0x1a) {
        (&DAT_00105000)[iVar1] = param_1 + -0x80;
    }
    else {
        puVar2 = &DAT_00105019;
        do {
            puVar2[1] = *puVar2;
            bVar3 = puVar2 != &DAT_00105000;
            puVar2 = puVar2 + -1;
        } while (bVar3);
        DAT_00105000 = param_1 + -0x80;
        DAT_0010501a = 0;
    }
    iVar1 = FUN_00100406(&DAT_0010100c,&DAT_00105000,0x1a);
    if (iVar1 != 0) {
        FUN_00100000();
    }
    return;
}
```

Here we see the `-0x80` operation - which means this might be encrypted similarly to the welcome message! Taking a look at `DAT_00105000` shows that this string is undefined at compile time. This must be written to during compilation time. This makes me think of a keyboard history buffer, which is further supported by the fact that `param_1 - 0x80` is written to the end (`iVar1`) of the buffer. You can draw an obvious conclusion that this is the encrypted keyboard buffer, as `param_1` is the last pressed key as seen earlier. 

After the buffer is full ` >= 0x1a`, the else condition is run. This takes the pointer to 0x20 (0x19 + 1) bytes into the keyboard history buffer and uses that as the counter. The while loop swaps `buf[i]` and `buf[i+1]  ` going backwards. This reverses the buffer. 

Finally, two different functions are run. `FUN_00100406` has 2 addresses passed in, one with our keyboard history buffer, an unknown data buffer and the size of our keyboard history buffer. This could be a string comparison or further encryption. This function returns a value and `FUN_00100000` is run if the value is not 0. Most likely this is a string comparison just from this information alone.

Taking a look at `DAT_0010100c` shows that it already has been initialised and is in `.rodata`.

```asm
      0010100c f7            ??        F7h
      0010100d e1            ??        E1h
      0010100e f2            ??        F2h
      0010100f f7            ??        F7h
      00101010 e9            ??        E9h
```

Decrypting this gives:

`warwick-cyber-security-123`

Taking a look at `FUN_0100000`, shows yet another encrypted string `DAT_00101028`

```c
void FUN_00100000(void)
{
    int iVar1;
    int iVar2;
    
    iVar1 = FUN_00100406(&DAT_0010100c,&DAT_00105000,0x1a);
    if (iVar1 == 0) {
        return;
    }
    FUN_00100693(10);
    do {
        iVar1 = 0;
        while( true ) {
            iVar2 = strlen(&DAT_00101028);
            if (iVar2 <= iVar1) break;
            FUN_00100693((int)(char)((&DAT_00101028)[iVar1] + -0x80));
            iVar1 = iVar1 + 1;
        }
        FUN_00100693(10);
    } while( true );
}
```

When decrypted, it becomes

`the key is [warwick-cyber-security-123] now decrypt the text\x80\x80\x80\x80`

Thinking back to the beginning, we can use the base64 string. Decoding that from base64 and then XOR'ing the string gives my answer to the cyber2 question!





## Solution / TL;DR

1. Realise that there is a keyboard history buffer that checks for `warwick-cyber-security-123` being typed without messing up - backspace is not a thing!

2. Decode the base64 string in .data and XOR it with the string `warwick-cyber-security-123` - gives my answer to cyber2