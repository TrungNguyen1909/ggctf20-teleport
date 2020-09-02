.PHONY: all
all: leakptr memread portinit sendmsg
leakptr: leakptr.S
	nasm -o leakptr.bin leakptr.S

memread: memread.S
	nasm -o memread.bin memread.S

portinit: portinit.S
	nasm -o portinit.bin portinit.S

sendmsg: sendmsg.S
	nasm -o sendmsg.bin sendmsg.S

clean:
	rm leakptr.bin memread.bin portinit.bin sendmsg.bin