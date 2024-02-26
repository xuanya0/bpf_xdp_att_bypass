PROG_SRC=att_kern.c
PROG=att_prog.o
SKEL=att.skel.c
USER=att_user.c

att: $(USER) $(SKEL)
	clang -O2 -g -lbpf -Wall $< -o $@

$(SKEL): $(PROG)
	bpftool gen skeleton $(PROG) > $@

$(PROG): $(PROG_SRC)
	clang -O2 -g -Wall -target bpf -c $(PROG_SRC) -o $@
