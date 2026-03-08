/*
 * $Id$
 * Created: 05/21/2004
 *
 * xvr (c) 2004
 * xvr@xvr.net
 */

#include "hdn_exe.h"

/*
 * checks wether a section is code or not
 */
inline char hdn_exe_section_is_code (hdn_sections_t *hs)
{
#if (defined(__CYGWIN32__) || defined(_Windows) || defined(_WIN32))

    return (hs->flags & IMAGE_SCN_CNT_CODE &&
            hs->flags & IMAGE_SCN_MEM_EXECUTE);

#else //ELF

    return (hs->type  == SHT_PROGBITS &&
            hs->flags == (SHF_ALLOC | SHF_EXECINSTR));

#endif
}

/*
 * returns true if we're dealing with an ELF file.
 */
#if (defined(__CYGWIN32__) || defined(_Windows) || defined(_WIN32))
static char _is_valid_exe (uint8_t *bin)
{
    size_t pos = 0;
    IMAGE_DOS_HEADER      dos_hdr;
    DWORD                 nt_sig;

    /* read and validate the dos header signature */
    memcpy (&dos_hdr, bin, sizeof (IMAGE_DOS_HEADER));
    if (dos_hdr.e_magic != IMAGE_DOS_SIGNATURE)
    {
        HDN_WARN ("Host file is not in PE format: DOS sig mismatch");
        return 0;
    }

    /* get NT header */
    pos = dos_hdr.e_lfanew;
    memcpy (&nt_sig, bin + pos, sizeof (IMAGE_NT_SIGNATURE));
    pos += sizeof (IMAGE_NT_SIGNATURE);

    if (nt_sig != IMAGE_NT_SIGNATURE)
    {
        HDN_WARN ("Host file is not in PE format: NT sig mismatch");
        return 0;
    }

    return 1;
}
#else //ELF
static int _is_valid_exe (uint8_t *bin)
{
    char magic[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3};
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)bin;

    /* make sure this is in elf format */
    if (memcmp (ehdr->e_ident, magic, sizeof magic))
    {
        HDN_WARN ("Host file is not in ELF format");
        return 0;
    }

    /* we only support elf32 lsb */
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS32 ||
        ehdr->e_ident[EI_DATA ] != ELFDATA2LSB)
    {
        HDN_WARN ("Host file is not in elf32 lsb format");
        return 0;
    }

    /* make sure this is indeed an executable */
    if (ehdr->e_type != ET_EXEC)
    {
        HDN_WARN ("Host file is not an executable");
        return 0;
    }

    if (!ehdr->e_phoff)
    {
        HDN_WARN ("Host file has no ELF program header");
        return 0;
    }

    if (!ehdr->e_shoff)
    {
        HDN_WARN ("Host file has no ELF section header");
        return 0;
    }

    if (ehdr->e_shstrndx == SHN_UNDEF)
    {
        HDN_WARN ("Host file has no section name string table");
        return 0;
    }

    //valid
    return 1;
}
#endif

/*
 * Adds a section to the end of the embeddable sections linked list.
 */
static void _insert_section (hdn_sections_t **base,
                             hdn_sections_t *new)
{
    hdn_sections_t *tmp;

    if (!new || !base) return;

    if (!(*base))
    {
        (*base) = new;
        return;
    }

    tmp = (*base);
    while (tmp->next)
        tmp = tmp->next;

    tmp->next = new;
}

/*
 * Returns the code locations in the exe file as a linked list.  These
 * sections are those that we want to look into for embeddable data.
 */
#if (defined(__CYGWIN32__) || defined(_Windows) || defined(_WIN32))
hdn_sections_t *hdn_exe_get_sections (uint8_t *file_start)
{
    uint32_t i;
    hdn_sections_t *sections  = NULL;
    hdn_sections_t *newsectn  = NULL;
    //XXX replace w/ sections header thing
    size_t pos = 0;
    IMAGE_DOS_HEADER      dos_hdr;
    IMAGE_FILE_HEADER     file_hdr;
    IMAGE_SECTION_HEADER  sect_hdr;

    /*
     * make sure we're dealing w/ an exe and not some random crap
     */
    if (!_is_valid_exe (host_data->content))
        return NULL;

    /* read the dos header */
    memcpy (&dos_hdr, file_start, sizeof (IMAGE_DOS_HEADER));
    pos = dos_hdr.e_lfanew;

    /* bypass NT header */
    pos += sizeof (IMAGE_NT_SIGNATURE);

    /* get file and bypass optional header */
    memcpy (&file_hdr, file_start + pos, sizeof (IMAGE_FILE_HEADER));
    pos += sizeof (IMAGE_FILE_HEADER);
    pos += sizeof (IMAGE_OPTIONAL_HEADER);

    /*
     * find code sections
     */
    for (i = 0; i < file_hdr.NumberOfSections; i++)
    {
        memcpy (&sect_hdr, file_start + pos, sizeof (IMAGE_SECTION_HEADER));
        pos += sizeof (IMAGE_SECTION_HEADER);

        /*
         * allocate an extra element in the array
         */
        newsectn = malloc (sizeof (hdn_sections_t) + sect_hdr.SizeOfRawData);
        bzero (newsectn,   sizeof (hdn_sections_t) + sect_hdr.SizeOfRawData);

        /*
         * copy in the section info and data
         */
        newsectn->next    = NULL;
        newsectn->offset  = sect_hdr.VirtualAddress;
#error  newsectn->address = shdr[i].sh_address; XXX
        newsectn->data.sz = sect_hdr.SizeOfRawData;
        newsectn->type    = 0; //type only exists in ELF
        newsectn->flags   = sect_hdr.Characteristics;

        memcpy (newsectn->data.content,
                file_start + newsectn->offset,
                newsectn->data.sz);

        _insert_section (&sections, newsectn);

#ifdef _DEBUG
        fprintf (stderr, "%s, %d bytes\n",
                 sect_hdr.Name,
                 sect_hdr.SizeOfRawData);
#endif
    }

    if (!sections)
        HDN_WARN ("couldn't find any sections in the PE file!");

    return sections;
}
#else //ELF
hdn_sections_header_t *hdn_exe_get_sections (uint8_t *file_start)
{
    uint32_t i;
    hdn_sections_t *sections  = NULL;
    hdn_sections_t *newsectn  = NULL;
    hdn_sections_header_t *sh = NULL;
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *) file_start;
    Elf32_Shdr *shdr = (Elf32_Shdr *)(file_start + ehdr->e_shoff);

    /*
     * make sure we're dealing w/ an exe and not some random crap
     */
    if (!_is_valid_exe (file_start))
        return NULL;

    /*
     * section header contains meta data about the sections -- right
     * now we only need the starting address, but maybe we'll add more
     * stuff later.
     */
    sh = malloc (sizeof (hdn_sections_header_t));
    bzero (sh,   sizeof (hdn_sections_header_t));

    sh->start_addr = (uint32_t)ehdr->e_entry;

    /*
     * find code sections
     */
    for (i=0; i < ehdr->e_shnum; i++)
    {
        /*
         * allocate an extra element in the array
         */
        newsectn = malloc (sizeof (hdn_sections_t) + shdr[i].sh_size);
        bzero (newsectn,   sizeof (hdn_sections_t) + shdr[i].sh_size);

        /*
         * copy in the section info and data
         */
        newsectn->next    = NULL;
        newsectn->offset  = shdr[i].sh_offset;
        newsectn->address = (uint8_t *)shdr[i].sh_addr;
        newsectn->data.sz = shdr[i].sh_size;
        newsectn->type    = shdr[i].sh_type;
        newsectn->flags   = shdr[i].sh_flags;

        memcpy (newsectn->data.content,
                file_start + newsectn->offset,
                newsectn->data.sz);

        _insert_section (&sections, newsectn);

#ifdef _DEBUG
        fprintf (stderr, "%s, %d bytes\n",
                 file_start +
                 shdr[ehdr->e_shstrndx].sh_offset + shdr[i].sh_name,
                 shdr[i].sh_size);
#endif
    }

    /*
     * make sh point to the newly allocated sections
     */
    sh->sections = sections;

    return sh;
}
#endif

