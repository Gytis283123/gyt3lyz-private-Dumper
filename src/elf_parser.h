#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <unordered_map>
#include <memory>

// ─── ELF Constants ───

constexpr uint32_t PT_LOAD    = 1;
constexpr uint32_t PT_DYNAMIC = 2;

constexpr uint64_t DT_NULL    = 0;
constexpr uint64_t DT_STRTAB  = 5;
constexpr uint64_t DT_SYMTAB  = 6;
constexpr uint64_t DT_STRSZ   = 10;
constexpr uint64_t DT_SYMENT  = 11;
constexpr uint64_t DT_HASH    = 4;
constexpr uint64_t DT_GNU_HASH = 0x6ffffef5;

constexpr uint32_t SHT_SYMTAB = 2;
constexpr uint32_t SHT_DYNSYM = 11;

// ─── ELF Structures ───

struct ElfSection {
    std::string name;
    uint32_t    name_offset;
    uint32_t    type;
    uint64_t    flags;
    uint64_t    addr;
    uint64_t    offset;
    uint64_t    size;
    uint32_t    link;
    uint32_t    info;
    uint64_t    addralign;
    uint64_t    entsize;
};

struct ElfSymbol {
    std::string name;
    uint32_t    name_offset = 0;
    uint64_t    value  = 0;
    uint64_t    size   = 0;
    uint8_t     info   = 0;
    uint8_t     other  = 0;
    uint16_t    shndx  = 0;

    uint8_t  type_val()  const { return info & 0xf; }
    uint8_t  bind_val()  const { return info >> 4; }

    const char* type_name() const;
    const char* bind_name() const;
};

struct ElfHeader {
    uint8_t  ei_class   = 0;  // 1=32bit, 2=64bit
    uint8_t  ei_data    = 0;  // 1=LE, 2=BE
    uint16_t e_type     = 0;
    uint16_t e_machine  = 0;
    uint64_t e_entry    = 0;
    uint64_t e_phoff    = 0;
    uint64_t e_shoff    = 0;
    uint16_t e_phnum    = 0;
    uint16_t e_shnum    = 0;
    uint32_t e_shstrndx = 0;
};

struct ElfProgramHeader {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t filesz;
    uint64_t memsz;
    uint64_t align;
};

struct ElfDynamicEntry {
    uint64_t tag;
    uint64_t val;
};

// ─── ELF Parser ───

class ElfParser {
public:
    explicit ElfParser(const std::string& filepath);
    ~ElfParser();

    bool parse();
    bool is_valid() const { return m_valid; }
    bool is_64bit()  const { return m_is64; }
    bool is_le()     const { return m_is_le; }

    const ElfHeader&                    header()          const { return m_header; }
    const std::vector<ElfSection>&      sections()        const { return m_sections; }
    const std::vector<ElfSymbol>&       symbols()         const { return m_symbols; }
    const std::vector<ElfSymbol>&       dynamic_symbols() const { return m_dynsyms; }
    const std::vector<std::pair<uint64_t,std::string>>& strings() const { return m_strings; }
    const std::vector<ElfProgramHeader>& program_headers() const { return m_phdrs; }
    const std::vector<ElfSymbol>&       code_functions()  const { return m_code_functions; }
    size_t                              hidden_functions_count() const { return m_hidden_functions_found; }
    uint64_t file_size() const { return m_filesize; }
    const std::string& filepath() const { return m_filepath; }
    
    // Get the base address (lowest PT_LOAD vaddr, aligned to page)
    uint64_t base_address() const { 
        uint64_t base = 0;
        for (const auto& ph : m_phdrs) {
            if (ph.type == PT_LOAD && ph.vaddr > 0) {
                if (base == 0 || ph.vaddr < base) {
                    base = ph.vaddr;
                }
            }
        }
        // Align down to 4KB page
        return base & ~0xFFF;
    }
    
    // Get the full memory address range (start to end)
    std::pair<uint64_t, uint64_t> address_range() const {
        uint64_t start = 0, end = 0;
        for (const auto& ph : m_phdrs) {
            if (ph.type == PT_LOAD && ph.vaddr > 0) {
                if (start == 0 || ph.vaddr < start) {
                    start = ph.vaddr;
                }
                uint64_t seg_end = ph.vaddr + ph.memsz;
                if (seg_end > end) {
                    end = seg_end;
                }
            }
        }
        // Align to 4KB page
        start = start & ~0xFFF;
        end = (end + 0xFFF) & ~0xFFF; // Align up
        return {start, end};
    }

    // String extraction with minimum length
    void extract_strings(size_t min_length = 4);

    // VTable structures discovered by deep scanning
    struct VTableInfo {
        uint64_t vtable_addr;           // Address of the vtable itself
        std::string class_name;         // From RTTI/typeinfo if available
        uint64_t typeinfo_addr;         // Address of typeinfo struct
        std::vector<uint64_t> func_addrs; // Virtual function addresses
    };

    const std::vector<VTableInfo>& vtables() const { return m_vtables; }

private:
    bool parse_header();
    bool parse_sections();
    bool parse_program_headers();
    bool parse_symbols();
    bool parse_symbol_table(const ElfSection& symtab, std::vector<ElfSymbol>& out);
    bool parse_dynamic_from_phdr();
    std::string read_strtab(uint32_t strtab_idx, uint32_t offset);
    std::string read_strtab_at(uint64_t strtab_file_offset, uint32_t name_offset);
    uint64_t va_to_offset(uint64_t vaddr) const;
    uint32_t get_dynsym_count_from_hash(uint64_t hash_offset);
    uint32_t get_dynsym_count_from_gnu_hash(uint64_t gnu_hash_offset, uint64_t symtab_offset, uint64_t syment);
    void scan_code_functions();
    void deobfuscate_functions(); // Rename obfuscated functions based on string refs
    void scan_vtables();         // Deep vtable scanning to find virtual functions
    void scan_hidden_functions(); // Find functions missed by other methods

    template<typename T>
    T read_val();

    template<typename T>
    T read_val_at(uint64_t file_offset);

    std::ifstream m_file;
    std::string   m_filepath;
    uint64_t      m_filesize = 0;
    bool          m_valid = false;
    bool          m_is64  = false;
    bool          m_is_le = true;

    ElfHeader                          m_header;
    std::vector<ElfSection>            m_sections;
    std::vector<ElfSymbol>             m_symbols;
    std::vector<ElfSymbol>             m_dynsyms;
    std::vector<std::pair<uint64_t,std::string>> m_strings;
    std::vector<ElfProgramHeader>     m_phdrs;
    std::vector<ElfDynamicEntry>      m_dynamic;
    std::vector<ElfSymbol>             m_code_functions; // Functions discovered by code scanning
    std::vector<VTableInfo>            m_vtables;        // VTables discovered by deep scanning
    size_t                             m_hidden_functions_found = 0; // Hidden functions found
};
