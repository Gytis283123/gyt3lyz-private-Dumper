#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <unordered_map>
#include <memory>

// ─── PE Constants ───

constexpr uint16_t PE_MACHINE_I386  = 0x014C;
constexpr uint16_t PE_MACHINE_AMD64 = 0x8664;
constexpr uint16_t PE_MACHINE_ARM64 = 0xAA64;

constexpr uint16_t PE_OPT_MAGIC_PE32   = 0x010B;
constexpr uint16_t PE_OPT_MAGIC_PE32PLUS = 0x020B;

constexpr uint32_t PE_SECTION_CODE   = 0x00000020; // IMAGE_SCN_CNT_CODE
constexpr uint32_t PE_SECTION_INIT   = 0x00000040; // IMAGE_SCN_CNT_INITIALIZED_DATA
constexpr uint32_t PE_SECTION_UNINIT = 0x00000080; // IMAGE_SCN_CNT_UNINITIALIZED_DATA
constexpr uint32_t PE_SECTION_EXEC   = 0x20000000; // IMAGE_SCN_MEM_EXECUTE
constexpr uint32_t PE_SECTION_READ   = 0x40000000; // IMAGE_SCN_MEM_READ
constexpr uint32_t PE_SECTION_WRITE  = 0x80000000; // IMAGE_SCN_MEM_WRITE

// ─── PE Structures ───

struct PeSection {
    std::string name;
    uint32_t    virtual_size;
    uint32_t    virtual_address;
    uint32_t    raw_size;
    uint32_t    raw_offset;
    uint32_t    characteristics;
    // Computed
    uint64_t    end_va;  // virtual_address + virtual_size
};

struct PeSymbol {
    std::string name;
    uint64_t    rva     = 0;   // Relative Virtual Address
    uint64_t    va      = 0;   // Absolute Virtual Address (rva + image_base)
    uint32_t    size    = 0;
    std::string type;          // "export", "import", "debug", "thunk", etc.
    std::string bind;          // "global", "local", "external"
    std::string dll_name;      // For imports: source DLL
    uint32_t    ordinal = 0;   // For imports/exports: ordinal number
};

struct PeImportDll {
    std::string name;
    uint32_t    first_thunk_rva;
    uint32_t    original_first_thunk_rva;
    std::vector<PeSymbol> functions;
};

struct PeExport {
    std::string dll_name;
    uint32_t    base;
    std::vector<PeSymbol> functions;
};

struct PeHeader {
    uint16_t machine;
    uint16_t num_sections;
    uint32_t timestamp;
    uint32_t characteristics;
    uint16_t opt_magic;     // PE32 or PE32+
    uint8_t  is_64bit;
    uint64_t image_base;
    uint32_t image_size;
    uint32_t header_size;
    uint32_t entry_point_rva;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint32_t number_of_rva_and_sizes;
};

// ─── PE Parser ───

class PeParser {
public:
    explicit PeParser(const std::string& filepath);
    ~PeParser();

    bool parse();
    bool is_valid() const { return m_valid; }
    bool is_64bit()  const { return m_header.is_64bit != 0; }

    const PeHeader&                        header()          const { return m_header; }
    const std::vector<PeSection>&          sections()        const { return m_sections; }
    const std::vector<PeSymbol>&           exports()         const { return m_exports; }
    const std::vector<PeImportDll>&        imports()         const { return m_imports; }
    const std::vector<PeSymbol>&           all_functions()   const { return m_all_functions; }
    const std::vector<PeSymbol>&           discovered_functions() const { return m_discovered; }
    size_t                                  discovered_count() const { return m_discovered.size(); }
    const std::vector<std::pair<uint64_t,std::string>>& strings() const { return m_strings; }
    uint64_t file_size() const { return m_filesize; }
    const std::string& filepath() const { return m_filepath; }
    uint64_t image_base() const { return m_header.image_base; }
    uint64_t entry_point() const { return m_header.image_base + m_header.entry_point_rva; }

    // Address range
    std::pair<uint64_t, uint64_t> address_range() const {
        uint64_t start = m_header.image_base;
        uint64_t end = m_header.image_base + m_header.image_size;
        return {start, end};
    }

    // String extraction
    void extract_strings(size_t min_length = 4);

    // RVA to file offset conversion
    uint64_t rva_to_offset(uint32_t rva) const;

private:
    bool parse_dos_header();
    bool parse_pe_header();
    bool parse_optional_header();
    bool parse_section_headers();
    bool parse_import_directory();
    bool parse_export_directory();
    void scan_exception_directory();   // .pdata runtime function table
    void scan_tls_callbacks();         // TLS callback functions
    void scan_code_prologues();        // Function prologue pattern scan
    void scan_relocations();            // Relocation-based function discovery
    void collect_all_functions();

    template<typename T>
    T read_val();

    template<typename T>
    T read_val_at(uint64_t file_offset);

    std::ifstream m_file;
    std::string   m_filepath;
    uint64_t      m_filesize = 0;
    bool          m_valid = false;

    // PE file offsets
    uint32_t      m_pe_offset = 0;     // Offset to PE signature
    uint32_t      m_coff_offset = 0;   // Offset to COFF header
    uint32_t      m_opt_offset = 0;    // Offset to Optional header
    uint32_t      m_sec_offset = 0;    // Offset to Section headers

    // Data directory info
    struct DataDir {
        uint32_t rva;
        uint32_t size;
    };
    DataDir m_data_dirs[16] = {};  // Up to 16 data directories

    PeHeader                      m_header;
    std::vector<PeSection>        m_sections;
    std::vector<PeSymbol>         m_exports;
    std::vector<PeImportDll>      m_imports;
    std::vector<PeSymbol>         m_all_functions;
    std::vector<PeSymbol>         m_discovered;  // Functions found by deep scanning
    std::vector<std::pair<uint64_t,std::string>> m_strings;
};
