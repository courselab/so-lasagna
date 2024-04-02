AS=as
LD=ld
OC=objcopy

all: eg-02-gnu.bin eg-02-py.bin

diff: eg-02-gnu.bin eg-02-py.bin
	shasum $^

%-gnu.o: %.s
	$(AS) -o $@ $<

%-gnu.elf: %.ld %-gnu.o
	$(LD) -T $^ -o $@

%-gnu.bin: %-gnu.elf
	$(OC) -Obinary $< $@

%-py.bin: %.s linkmap.json
	./hwasm.py $^ $@

clean:
	rm -rf *.o *.bin *.elf

.PHONY: all diff clean

