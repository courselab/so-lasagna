Makeshift Assembler

This folder contains some BIOS boot code, a makeshift assembler+linker combo,
and a Makefile that allows one to build the boot code using either the GNU
toolchain or the makeshift assembler.

Build using the GNU tools:
```
make eg-02-gnu.bin
```

Build using the makeshift assembler:
```
make eg-02-py.bin
```

By default, both versions are built when invoking `make`.

One can also compare the contents of both versions by running `make diff`.
