#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>

void *mapFile(const char *path, long *filesize)
{
    FILE *file = fopen(path, "rb");
    int fd;
    void *content;

    if (!file)
    {
        perror("fopen error:");
        exit(EXIT_FAILURE);
    }

    if (fseek(file, 0, SEEK_END) == -1)
    {
        fclose(file);
        perror("fseek error:");
        exit(EXIT_FAILURE);
    }

    fd = fileno(file);

    if (fd == -1)
    {
        fclose(file);
        perror("fileno error:");
        exit(EXIT_FAILURE);
    }

    *filesize = ftell(file);
    rewind(file);

    if (content = mmap(NULL, *filesize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0), content == MAP_FAILED)
    {
        fclose(file);
        perror("mmap error:");
        exit(EXIT_FAILURE);
    }

    fclose(file);
    printf("[+] %s was mapped into memory.\n", path);
    return content;
}

void freeContent(void *content, long filesize)
{
    if (munmap(content, filesize) == 0)
        printf("[+] The block memory of size %ld bytes was deallocated from the memory.\n", filesize);
}

void writeNewFile(char *content, long filesize)
{
    FILE *file = fopen("elf-obfuscated", "wb");

    if (!file)
    {
        freeContent(content, filesize);
        perror("fopen error:");
        exit(EXIT_FAILURE);
    }

    fwrite(content, filesize, 1, file);
    puts("[+] The new file was created.");
    fclose(file);

    if (chmod("elf-obfuscated", S_IRWXU) != -1)
        puts("[+] Run it");
}

bool isElf(char *content)
{
    if (content[0] == 0x7f && strncmp(&content[1], "ELF", 3) == 0)
        return true;
    return false;
}

void parseElf(char *content, long filesize)
{
    if (!isElf(content))
    {
        fprintf(stderr, "[-] Not an Elf file\n");
        freeContent(content, filesize);
        exit(EXIT_FAILURE);
    }

    Elf64_Ehdr *elf_headers = (Elf64_Ehdr *)content;
    Elf64_Shdr *sec_headers = (Elf64_Shdr *)((unsigned char *)elf_headers + elf_headers->e_shoff);
    Elf64_Phdr *prog_headers = (Elf64_Phdr *)((unsigned char *)elf_headers + elf_headers->e_phoff);

    memset(&content[sec_headers[elf_headers->e_shstrndx].sh_offset], 0, sec_headers[elf_headers->e_shstrndx].sh_size);
    memset(&content[elf_headers->e_shoff], 0, filesize - elf_headers->e_shoff);

    elf_headers->e_shstrndx = 0;
    elf_headers->e_shoff = 0;
    elf_headers->e_shnum = 0;
    elf_headers->e_shentsize = 0;

    for (int i = 0; i < elf_headers->e_phnum; ++i, prog_headers = (Elf64_Phdr *)((unsigned char *)prog_headers + elf_headers->e_phentsize))
    {
        if (prog_headers->p_type == PT_DYNAMIC)
        {
            prog_headers->p_flags = PF_R;
            prog_headers->p_offset = 0;
            prog_headers->p_align = 0;
            prog_headers->p_filesz = 0;
            prog_headers->p_paddr = 0;
            prog_headers->p_memsz = 0;
        }

        if (prog_headers->p_type == PT_GNU_STACK || prog_headers->p_type == PT_GNU_RELRO || prog_headers->p_type == PT_GNU_EH_FRAME || prog_headers->p_type == PT_NOTE)
        {
            prog_headers->p_type = PT_NULL;
            prog_headers->p_flags = PF_R;
            prog_headers->p_offset = 0;
            prog_headers->p_align = 0;
            prog_headers->p_filesz = 0;
            prog_headers->p_paddr = 0;
            prog_headers->p_vaddr = 0;
            prog_headers->p_memsz = 0;
        }

        if (prog_headers->p_type == PT_INTERP)
        {
            prog_headers->p_align = 0;
            prog_headers->p_paddr = 0;
            prog_headers->p_vaddr = 0;
            prog_headers->p_memsz = 0;
        }

        if (prog_headers->p_type == PT_PHDR)
        {
            prog_headers->p_align = 0;
            prog_headers->p_paddr = 0;
            prog_headers->p_memsz = 0;
            prog_headers->p_offset = 0;
            prog_headers->p_filesz = 0;
        }

        if (prog_headers->p_type == PT_LOAD && prog_headers->p_flags == (PF_R | PF_X))
        {
            prog_headers->p_offset = 0;
            prog_headers->p_align = 0;
            prog_headers->p_paddr = 0;
            prog_headers->p_vaddr = 0;
        }

        if (prog_headers->p_type == PT_LOAD && prog_headers->p_flags == (PF_R | PF_W))
        {
            prog_headers->p_align = 0;
            prog_headers->p_paddr = 0;
            prog_headers->p_memsz = prog_headers->p_offset;
            prog_headers->p_filesz = prog_headers->p_offset;
        }
    }

    elf_headers->e_phnum -= 4;
    memset(&content[0x38], 20, 1);
    elf_headers->e_ehsize = -1;
    elf_headers->e_ident[EI_CLASS] = ELFCLASSNONE;
    elf_headers->e_ident[EI_DATA] = ELFDATANONE;
    elf_headers->e_ident[EI_VERSION] = EV_NONE;
    elf_headers->e_version = 0;
    elf_headers->e_ident[EI_OSABI] = ELFOSABI_NONE;
    writeNewFile(content, filesize);
    freeContent(content, filesize);
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage %s <elf file>\n", *argv);
        return 1;
    }

    const char *path = argv[1];
    long filesize = 0;
    char *content = mapFile(path, &filesize);
    parseElf(content, filesize);
    return 0;
}