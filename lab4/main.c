#include "xed/xed-address-width-enum.h"
#include "xed/xed-chip-enum.h"
#include "xed/xed-common-defs.h"
#include "xed/xed-decode.h"
#include "xed/xed-decoded-inst-api.h"
#include "xed/xed-error-enum.h"
#include "xed/xed-ild.h"
#include "xed/xed-init.h"
#include "xed/xed-machine-mode-enum.h"
#include "xed/xed-syntax-enum.h"
#include <antlr3defs.h>
#include <antlr3interfaces.h>
#include <libunwind-x86_64.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <xed/xed-decoded-inst.h>

#include <signal.h>
#include <antlr3collections.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <elf.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/personality.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/user.h>
#include <xed/xed-interface.h>
#include <unistd.h>

#ifdef USE_LIBUNWIND
#include <libunwind.h>
#include <libunwind-ptrace.h>
#endif

#include "lists.h"

typedef struct {
    pANTLR3_VECTOR funcs;
    pANTLR3_VECTOR files;
    pANTLR3_VECTOR lines;
} dbg_info_t;

typedef struct {
    size_t addr;
    long data;
} breakpoint_t;

void print_regs(struct user_regs_struct* regs, FILE* output);
long read_reg(pid_t child, char reg[4]);

bool parse_address(char* str, pid_t child, long* addr, dbg_info_t* info) {
    if (str[0] == '[') {
        char reg[4];
        sscanf(str, "[%3s]", reg);
        *addr = read_reg(child, reg);
    }
    else {
        char *end;
        *addr = strtol(str, &end, 0);
        if (end == str) {
            for (int i = 0; i < info->funcs->count; i++) {
                func_t* f = info->funcs->get(info->funcs, i);
                if (strcmp(str, f->identifier) == 0) {
                    *addr = MAP_TEXT_START + f->instruction_address;
                    return true;
                }
            }
            char file[FILENAME_MAX];
            int line_number;
            sscanf(str, "%[^:]:%d", file, &line_number);
            for (int i = 0; i < info->files->count; i++) {
                source_file_t* f = info->files->get(info->files, i);
                if (strcmp(f->name, file) == 0) {
                    for (int j = 0; j < f->lines->count; j++) {
                        line_t* line = f->lines->get(f->lines, j);
                        if (line->line >= line_number) {
                            *addr = MAP_TEXT_START + line->instruction_address_start;
                            return true;
                        }
                    }
                }
            }
            printf("Wrong argument format, expected: addr in hex or [reg] or function or source:line\n");
            return false;
        }
    }
    return true;
}

bool parse_number(char* str, pid_t child, long* addr) {
    char *end;
    *addr = strtol(str, &end, 0);
    if (end == str) {
        char reg[4];
        sscanf(str, "%3s", reg);
        *addr = read_reg(child, reg);
    }
    return true;
}


xed_error_enum_t decode_inst_in_child(xed_decoded_inst_t* xedd, pid_t child, unsigned long addr) {
    unsigned char inst[XED_MAX_INSTRUCTION_BYTES];
    long word = ptrace(PTRACE_PEEKDATA, child, addr, NULL);
    memcpy(inst, &word, sizeof(word));
    word = ptrace(PTRACE_PEEKDATA, child, addr + sizeof(word), NULL);
    memcpy(inst + sizeof(word), &word, sizeof(word) - 1);
    xed_decoded_inst_zero_keep_mode(xedd);
    return xed_decode(xedd, inst, XED_MAX_INSTRUCTION_BYTES);
}

dbg_info_t read_symbols(char *filename) {
    FILE* f = fopen(filename, "r");
    Elf64_Ehdr hdr;
    fread(&hdr, sizeof(Elf64_Ehdr), 1, f);
    if (memcmp(hdr.e_ident, "\x7f" "ELF\x2\x1\x1", 7) != 0) {
        printf("Not an ELF file or has the unsupported format\n");
        return (dbg_info_t){NULL, NULL, NULL};
    }
    if (hdr.e_type != ET_EXEC && hdr.e_type != ET_DYN) {
        printf("Not an executable.\n");
        return (dbg_info_t){NULL, NULL, NULL};
    }
    fseek(f, hdr.e_shoff, SEEK_SET);
    Elf64_Shdr *shdr = calloc(hdr.e_shentsize, hdr.e_shnum), *symtabhdr;
    fread(shdr, hdr.e_shentsize, hdr.e_shnum, f);
    char *str = malloc(shdr[hdr.e_shstrndx].sh_size);
    fseek(f, shdr[hdr.e_shstrndx].sh_offset, SEEK_SET);
    fread(str, shdr[hdr.e_shstrndx].sh_size, 1, f);
    char *strtab;
    Elf64_Sym *symtab;
    for (int i = 0; i < hdr.e_shnum; i++) {
        if (shdr[i].sh_size == 0) {
            continue;
        }
        if (strncmp(&str[shdr[i].sh_name], ".strtab", 7) == 0) {
            strtab = malloc(shdr[i].sh_size);
            fseek(f, shdr[i].sh_offset, SEEK_SET);
            fread(strtab, shdr[i].sh_size, 1, f);
            continue;
        }
        if (strncmp(&str[shdr[i].sh_name], ".symtab", 7) == 0) {
            printf("Found section %s at %d\n", &str[shdr[i].sh_name], i);
            symtabhdr = &shdr[i];
            symtab = malloc(shdr[i].sh_size);
            fseek(f, shdr[i].sh_offset, SEEK_SET);
            fread(symtab, shdr[i].sh_size, 1, f);
            continue;
        }
    }

    pANTLR3_VECTOR funcs = antlr3VectorNew(ANTLR3_SIZE_HINT);
    pANTLR3_VECTOR files = antlr3VectorNew(ANTLR3_SIZE_HINT);
    pANTLR3_VECTOR lines = antlr3VectorNew(ANTLR3_SIZE_HINT);

    for (int i = 0; i < symtabhdr->sh_size / sizeof(Elf64_Sym); i++) {
        if (symtab[i].st_info & STT_FUNC) {
            func_t* f = NULL;
            for (int j = 0; j < funcs->count; j++) {
                func_t* fi = funcs->get(funcs, j);
                if (strcmp(fi->identifier, &strtab[symtab[i].st_name]) == 0) {
                    f = fi;
                    break;
                }
            }
            if (f == NULL) {
                f = malloc(sizeof(func_t));
                *f = (func_t){strdup(&strtab[symtab[i].st_name]), 0, antlr3VectorNew(ANTLR3_SIZE_HINT)};
                funcs->add(funcs, f, (void (*))free_func);
            }
            f->instruction_address = symtab[i].st_value;
        }

        if (strncmp(&strtab[symtab[i].st_name], "_LOCALOFF", 9) == 0) {
            char id[128], func[128], source_file[128];
            sscanf(&strtab[symtab[i].st_name], "_LOCALOFF$%127[^@]@%127[^@]@%127s", id, func, source_file);
            func_t* f = NULL;
            for (int j = 0; j < funcs->count; j++) {
                func_t* fi = funcs->get(funcs, j);
                if (strcmp(fi->identifier, func) == 0) {
                    f = fi;
                    break;
                }
            }
            if (f == NULL) {
                f = malloc(sizeof(func_t));
                *f = (func_t){strdup(func), -2, antlr3VectorNew(ANTLR3_SIZE_HINT)};
                funcs->add(funcs, f, (void (*))free_func);
            }
            pANTLR3_VECTOR locals = f->locals;
            local_t *new = malloc(sizeof(local_t));
            *new = (local_t){strdup(id), symtab[i].st_value, symtab[i + 1].st_value, symtab[i + 2].st_value};
            locals->add(locals, new, (void (*))free_local);
        }

        if (strncmp(&strtab[symtab[i].st_name], "..@LN", 5) == 0 || strncmp(&strtab[symtab[i].st_name], "..@LNEND", 8) == 0) {
            bool is_end = strncmp(&strtab[symtab[i].st_name], "..@LNEND", 8) == 0;
            char source_file[128], func_id[128];
            int line;
            sscanf(&strtab[symtab[i].st_name], is_end ?  "..@LNEND%d@%127[^@]@%127s" : "..@LN%d@%127[^@]@%127s", &line, func_id, source_file);
            func_t* func = find_func(funcs, func_id);
            if (func == NULL) {
                func = malloc(sizeof(func_t));
                *func = (func_t){strdup(func_id), 0, antlr3VectorNew(ANTLR3_SIZE_HINT)};
                funcs->add(funcs, func, (void (*))free_func);
            }
            source_file_t* file = find_file(files, source_file);
            if (file == NULL) {
                file = malloc(sizeof(func_t));
                *file = (source_file_t){strdup(source_file), fopen(source_file, "r"), antlr3VectorNew(ANTLR3_SIZE_HINT)};
                files->add(files, file, (void (*))free_source_file);
            }
            line_t* l = find_line(lines, source_file, line);
            if (l == NULL) {
                l = malloc(sizeof(line_t));
                *l = (line_t){line, 0, 0, func, file};
                lines->add(lines, l, free);
                file->lines->add(file->lines, l, NULL);
            }
            *(is_end ? &l->instruction_address_end : &l->instruction_address_start) = symtab[i].st_value;
        }
    }

    free(shdr);
    free(str);
    free(strtab);
    free(symtab);

    return (dbg_info_t){funcs, files, lines};
}

line_t* get_current_line(dbg_info_t* info, unsigned long long rip) {
    for (int i = 0; i < info->lines->count; i++) {
        line_t *line = info->lines->get(info->lines, i);
        if (MAP_TEXT_START + line->instruction_address_start <= rip && rip < MAP_TEXT_START + line->instruction_address_end) {
            return line;
        }
    }
    return NULL;
}

int set_line_pos(pANTLR3_VECTOR files) {
    int sum = 0;
    for (int i = 0; i < files->count; i++) {
        source_file_t *file = files->get(files, i);
        int lines = 0;
        while (!feof(file->file)) {
            if (fgetc(file->file) == '\n') {
                lines++;
            }
        }
        fpos_t *positions = calloc(lines, sizeof(fpos_t));
        rewind(file->file);
        lines = 0;
        fgetpos(file->file, &positions[0]);
        while (!feof(file->file)) {
            if (fgetc(file->file) == '\n') {
                lines++;
                printf("Newline on %ld, lines is %d\n", ftell(file->file), lines);
                fgetpos(file->file, &positions[lines]);
            }
        }
        for (int l = 0; l < file->lines->count; l++) {
            line_t* line = file->lines->get(file->lines, l);
            line->pos = positions[line->line - 1];
        }
        sum += lines;
    }
    return sum;
}

long set_breakpoint(pid_t child, long addr) {
    long data = ptrace(PTRACE_PEEKDATA, child, addr, NULL);
    ptrace(PTRACE_POKEDATA, child, addr, (data & ~0xfflu) | 0xcc);
    return data;
}

void init_line_breakpoints(breakpoint_t* breakpoints, pANTLR3_VECTOR lines, pid_t child) {
    for (int i = 0; i < lines->count; i++) {
        breakpoints[i].addr = ((line_t *)lines->get(lines, i))->instruction_address_start + MAP_TEXT_START;
        breakpoints[i].data = ptrace(PTRACE_PEEKDATA, child, breakpoints[i].addr, NULL);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s INPUT [ARGS...]\n", argv[0]);
        return 1;
    }
    pid_t child = fork();
    if (child == -1) {
        perror("fork failed");
        return 2;
    }
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) {
            perror("ptrace");
            return 1;
        }
        personality(ADDR_NO_RANDOMIZE);
        execv(argv[1], &argv[1]);
    }
#ifdef USE_LIBUNWIND
    unw_cursor_t cursor;
    int res;
    if ((res = unw_init_remote(&cursor, unw_create_addr_space(&_UPT_accessors, 0), _UPT_create(child))) < 0) {
        fprintf(stderr, "Error initializing libunwind. %d\n", res);
        switch (res) {
            case -UNW_EINVAL:
                printf("unw_init_remote() was called in a version of libunwind which supports local unwinding only\n");
                break;
            case -UNW_EUNSPEC:
                printf("Unspecified error\n");
                break;
            case -UNW_EBADREG:
                printf("A register needed by unw_init_remote() wasn't accessible.\n");
        }
        return 1;
    }
#endif
    dbg_info_t info = read_symbols(argv[1]);
    set_line_pos(info.files);
    xed_decoded_inst_t xedd;
    xed_tables_init();
    xed_decoded_inst_zero(&xedd);
    xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
    int status = 0;
    char buff[100];
    char input[3072];
    char cmd[1024] = {0};
    char arg1[1024] = {0};
    char arg2[1024] = {0};
    struct user_regs_struct regs;
    breakpoint_t *line_breakpoints = calloc(info.lines->count, sizeof(breakpoint_t));
    init_line_breakpoints(line_breakpoints, info.lines, child);
    line_t *current = NULL;
    wait(&status);
    while (!WIFEXITED(status)) {
        ptrace(PTRACE_GETREGS, child, NULL, &regs);
        current = get_current_line(&info, regs.rip);
        if (current != NULL) {
            char buff[128], *res;
            printf("On line %d\n", current->line);
            fsetpos(current->file->file, &current->pos);
            do {
                res = fgets(buff, sizeof(buff), current->file->file);
                fputs(buff, stdout);
            } while (res != NULL && strchr(buff, '\n') == NULL);
        }

        xed_error_enum_t err = decode_inst_in_child(&xedd, child, regs.rip);
        if (err != XED_ERROR_NONE) {
            printf("There was an error decoding instruction: %s\n", xed_error_enum_t2str(err));
        }
        if (!xed_format_context(XED_SYNTAX_INTEL, &xedd, buff, sizeof(buff), regs.rip, NULL, 0)) {
            printf("There was an error formatting Instruction\n");
        }
        printf("Instruction at 0x%llX: %s\n>> ", regs.rip, buff);

        fgets(input, sizeof(input), stdin);
        cmd[0] = '\0';
        arg1[0] = '\0';
        arg2[0] = '\0';
        sscanf(input, "%1023s %1023s %1023s", cmd, arg1, arg2);
        if (strncmp(cmd, "continue", sizeof(cmd)) == 0 || strncmp(cmd, "c", sizeof(cmd)) == 0) {
            printf("Continuing...\n");
            ptrace(PTRACE_CONT, child, NULL, NULL);
            wait(&status);
        }
        if (strncmp(cmd, "breakpoint", sizeof(cmd)) == 0 || strncmp(cmd, "b", sizeof(cmd)) == 0) {
            long addr;
            if (strlen(arg1) == 0 || !parse_address(arg1, child, &addr, &info)) {
                printf("Wrong argument format, expected: breakpoint address\n");
                continue;
            }
            long data = set_breakpoint(child, addr);
            ptrace(PTRACE_CONT, child, NULL, NULL);
            wait(&status);
            ptrace(PTRACE_POKEDATA, child, addr, data);
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            regs.rip--;
            ptrace(PTRACE_SETREGS, child, NULL, &regs);
        }

        if (strncmp(cmd, "registers", sizeof(cmd)) == 0 || strncmp(cmd, "regs", sizeof(cmd)) == 0) {
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            print_regs(&regs, stdout);
        }

        if (strncmp(cmd, "nexti", sizeof(cmd)) == 0 || strncmp(cmd, "ni", sizeof(cmd)) == 0) {
            printf("Stepping single instruction...\n");
            ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
            wait(&status);
        }

        if (strncmp(cmd, "next", sizeof(cmd)) == 0 || strncmp(cmd, "n", sizeof(cmd)) == 0) {
            printf("Stepping single line...\n");
            for (int i = 0; i < info.lines->count; i++) {
                line_t* line = info.lines->get(info.lines, i);
                if (current != NULL && current->line == line->line) {
                    continue;
                }
                set_breakpoint(child, line_breakpoints[i].addr);
            }
            ptrace(PTRACE_CONT, child, NULL, NULL);
            wait(&status);
            for (int i = 0; i < info.lines->count; i++) {
                ptrace(PTRACE_POKEDATA, child, line_breakpoints[i].addr, line_breakpoints[i].data);
            }
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            regs.rip--;
            ptrace(PTRACE_SETREGS, child, NULL, &regs);
        }

        if (strncmp(cmd, "read", sizeof(cmd)) == 0 || strncmp(cmd, "r", sizeof(cmd)) == 0) {
            long addr;
            long bytes;
            if (strlen(arg1) == 0 || strlen(arg2) == 0) {
                printf("Expected two arguments\n");
                continue;
            }
            if (!parse_address(arg1, child, &addr, &info)) {
                printf("Wrong address format.\n");
                continue;
            }
            parse_number(arg2, child, &bytes);
            printf("Data at 0x%lX: ", addr);
            while (bytes >= sizeof(long)) {
                long data = ptrace(PTRACE_PEEKDATA, child, addr, NULL);
                for (int i = 0; i < sizeof(long); i++) {
                    printf("%02X ", ((uint8_t *)&data)[i]);
                }
                bytes -= sizeof(long);
                addr += sizeof(long);
            }
            if (bytes > 0) {
                long data = ptrace(PTRACE_PEEKDATA, child, addr, NULL);
                for (int i = 0; i < bytes; i++) {
                    printf("%02X ", ((uint8_t *)&data)[i]);
                }
            }
            putchar('\n');
        }

        if (strncmp(cmd, "disassemble", sizeof(cmd)) == 0 || strncmp(cmd, "disas", sizeof(cmd)) == 0) {
            long addr;
            long bytes;
            if (strlen(arg1) == 0 || strlen(arg2) == 0) {
                printf("Expected two arguments\n");
                continue;
            }
            if (!parse_address(arg1, child, &addr, &info)) {
                printf("Wrong address format.\n");
                continue;
            }
            parse_number(arg2, child, &bytes);
            xed_error_enum_t error = XED_ERROR_NONE;
            while (bytes > 0) {
                error = decode_inst_in_child(&xedd, child, addr);
                if (error != XED_ERROR_NONE) {
                    printf("Error occured while disassembling: %s\n", xed_error_enum_t2str(error));
                    break;
                }
                int length = xed_decoded_inst_get_length(&xedd);
                if (!xed_format_context(XED_SYNTAX_INTEL, &xedd, buff, sizeof(buff), addr, NULL, NULL)) {
                    printf("There was an error formatting Instruction\n");
                    break;
                }
                printf("0x%lX: %s\n", addr, buff);
                if (length == 0) {
                    printf("wait what.\n");
                    break;
                }
                bytes -= length;
                addr += length;
            }
        }

        if (strncmp(cmd, "locals", sizeof(cmd)) == 0 || strncmp(cmd, "l", sizeof(cmd)) == 0) {
            if (current == NULL) {
                printf("No locals at this position.\n");
                continue;
            }
            for (int i = 0; i < current->func->locals->count; i++) {
                local_t* local = current->func->locals->get(current->func->locals, i);
                ptrace(PTRACE_GETREGS, child, NULL, &regs);
                if (local->flags & ARRAY_FLAG) {
                    printf("%s is array of ", local->identifier);
                    switch (local->size) {
                        case sizeof(long): printf("longs"); break;
                        case sizeof(int): printf("ints"); break;
                        case sizeof(short): printf("shorts"); break;
                        case sizeof(char): printf("bytes"); break;
                    }
                    printf(" at 0x%lX\n", ptrace(PTRACE_PEEKDATA, child, regs.rbp + local->rbp_offset, NULL));
                    continue;
                }
                
                long value;
                switch (local->size) {
                    case sizeof(long): value = ptrace(PTRACE_PEEKDATA, child, regs.rbp + local->rbp_offset, NULL);
                    case sizeof(int): value = (int)ptrace(PTRACE_PEEKDATA, child, regs.rbp + local->rbp_offset, NULL);
                    case sizeof(short): value = (short)ptrace(PTRACE_PEEKDATA, child, regs.rbp + local->rbp_offset, NULL);
                    case sizeof(char): value = (char)ptrace(PTRACE_PEEKDATA, child, regs.rbp + local->rbp_offset, NULL);

                }
                printf("%s = %ld\n", local->identifier, value);
            }
        }

#ifdef USE_LIBUNWIND
        if (strncmp(cmd, "backtrace", sizeof(cmd)) == 0 || strncmp(cmd, "bt", sizeof(cmd)) == 0) {
            unw_word_t rsp;
            while (unw_step(&cursor) > 0) {
                unw_get_reg(&cursor, UNW_REG_SP, &rsp);
                func_t* func = find_func_by_addr(info.funcs, rsp);
                if (func == NULL) {
                    printf("???\n");
                } else {
                    printf("%s\n", func->identifier);
                }
            }
        }
#endif

        if (strncmp(cmd, "quit", sizeof(cmd)) == 0 || strncmp(cmd, "q", sizeof(cmd)) == 0) {
            kill(child, SIGTERM);
            return 0;
        }
        if (WIFSIGNALED(status)) {
            printf("Child recieved a signal %s\n", strsignal(WTERMSIG(status)));
        }
    }
    kill(child, SIGTERM);
}

void print_regs(struct user_regs_struct* regs, FILE* output) {
    static const char *flags[] = {
        "CF", NULL, "PF", NULL, "AF", NULL, "ZF", "SF", "TF", "IF", "DF", "OF", "IOPL", "IOPL", "NT", NULL,
        "RF", "VM", "AC", "VIF", "VIP", "ID"
    };
    fprintf(output, "%-8s0x%-20llX%lld\n", "rax", regs->rax, regs->rax);
    fprintf(output, "%-8s0x%-20llX%lld\n", "rbx", regs->rbx, regs->rbx);
    fprintf(output, "%-8s0x%-20llX%lld\n", "rcx", regs->rcx, regs->rcx);
    fprintf(output, "%-8s0x%-20llX%lld\n", "rdx", regs->rdx, regs->rdx);
    fprintf(output, "%-8s0x%-20llX%lld\n", "rsi", regs->rsi, regs->rsi);
    fprintf(output, "%-8s0x%-20llX%lld\n", "rdi", regs->rdi, regs->rdi);
    fprintf(output, "%-8s0x%-20llX%lld\n", "rbp", regs->rbp, regs->rbp);
    fprintf(output, "%-8s0x%-20llX%lld\n", "rsp", regs->rsp, regs->rsp);
    fprintf(output, "%-8s0x%-20llX%lld\n", "r8", regs->r8, regs->r8);
    fprintf(output, "%-8s0x%-20llX%lld\n", "r9", regs->r9, regs->r9);
    fprintf(output, "%-8s0x%-20llX%lld\n", "r10", regs->r10, regs->r10);
    fprintf(output, "%-8s0x%-20llX%lld\n", "r11", regs->r11, regs->r11);
    fprintf(output, "%-8s0x%-20llX%lld\n", "r12", regs->r12, regs->r12);
    fprintf(output, "%-8s0x%-20llX%lld\n", "r13", regs->r13, regs->r13);
    fprintf(output, "%-8s0x%-20llX%lld\n", "r14", regs->r14, regs->r14);
    fprintf(output, "%-8s0x%-20llX%lld\n", "r15", regs->r15, regs->r15);
    fprintf(output, "%-8s0x%-20llX%lld\n", "rip", regs->rip, regs->rip);
    fprintf(output, "%-8s0x%-20llX", "eflags", regs->eflags);
    fputs("[ ", output);
    for (int i = 0; i < sizeof(flags)/sizeof(flags[0]); i++) {
        if ((regs->eflags & (1 << i)) && flags[i]) {
            fprintf(output, "%s ", flags[i]);
        }
    }
    fputs("]\n", output);

    fprintf(output, "%-8s%-20llX%lld\n", "cs", regs->cs, regs->cs);
    fprintf(output, "%-8s%-20llX%lld\n", "ss", regs->ss, regs->ss);
    fprintf(output, "%-8s%-20llX%lld\n", "ds", regs->ds, regs->ds);
    fprintf(output, "%-8s%-20llX%lld\n", "es", regs->es, regs->es);
    fprintf(output, "%-8s%-20llX%lld\n", "fs", regs->fs, regs->fs);
    fprintf(output, "%-8s%-20llX%lld\n", "gs", regs->gs, regs->gs);
}

long read_reg(pid_t child, char reg[4]) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child, NULL, &regs);
    if (strncmp(reg, "rip", 3) == 0) {
        return regs.rip;
    }
    if (strncmp(reg, "rax", 3) == 0) {
        return regs.rax;
    }
    if (strncmp(reg, "rbx", 3) == 0) {
        return regs.rbx;
    }
    if (strncmp(reg, "rcx", 3) == 0) {
        return regs.rcx;
    }
    if (strncmp(reg, "rdx", 3) == 0) {
        return regs.rdx;
    }
    if (strncmp(reg, "rdi", 3) == 0) {
        return regs.rdi;
    }
    if (strncmp(reg, "rsi", 3) == 0) {
        return regs.rsi;
    }
    if (strncmp(reg, "rbp", 3) == 0) {
        return regs.rbp;
    }
    if (strncmp(reg, "rsp", 3) == 0) {
        return regs.rsp;
    }
    if (strncmp(reg, "r8", 3) == 0) {
        return regs.r8;
    }
    if (strncmp(reg, "r9", 3) == 0) {
        return regs.r9;
    }
    if (strncmp(reg, "r10", 3) == 0) {
        return regs.r10;
    }
    if (strncmp(reg, "r11", 3) == 0) {
        return regs.r11;
    }
    if (strncmp(reg, "r12", 3) == 0) {
        return regs.r12;
    }
    if (strncmp(reg, "r13", 3) == 0) {
        return regs.r13;
    }
    if (strncmp(reg, "r14", 3) == 0) {
        return regs.r14;
    }
    if (strncmp(reg, "r15", 3) == 0) {
        return regs.r15;
    }
    return -1;
}

