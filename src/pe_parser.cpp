#include "pe_parser.h"
#include <cstring>
#include <algorithm>
#include <cctype>

// ─── PE Data Directory Indices ───
enum DataDirIndex {
    DD_EXPORT    = 0,
    DD_IMPORT    = 1,
    DD_RESOURCE  = 2,
    DD_EXCEPTION = 3,
    DD_SECURITY  = 4,
    DD_BASERELOC = 5,
    DD_DEBUG     = 6,
    DD_ARCH      = 7,
    DD_GLOBALPTR = 8,
    DD_TLS       = 9,
    DD_LOAD_CONFIG = 10,
    DD_BOUND_IMPORT = 11,
    DD_IAT       = 12,
    DD_DELAY_IMPORT = 13,
    DD_CLR       = 14,
};

// ─── Constructor / Destructor ───

PeParser::PeParser(const std::string& filepath)
    : m_filepath(filepath)
{
    m_file.open(filepath, std::ios::binary | std::ios::ate);
    if (m_file.is_open()) {
        m_filesize = static_cast<uint64_t>(m_file.tellg());
        m_file.seekg(0);
    }
}

PeParser::~PeParser() {
    if (m_file.is_open()) m_file.close();
}

// ─── Template readers ───

template<typename T>
T PeParser::read_val() {
    T val{};
    m_file.read(reinterpret_cast<char*>(&val), sizeof(T));
    return val;
}

template<typename T>
T PeParser::read_val_at(uint64_t file_offset) {
    T val{};
    auto pos = m_file.tellg();
    m_file.seekg(static_cast<std::streamoff>(file_offset));
    m_file.read(reinterpret_cast<char*>(&val), sizeof(T));
    m_file.seekg(pos);
    return val;
}

// ─── RVA to file offset ───

uint64_t PeParser::rva_to_offset(uint32_t rva) const {
    for (const auto& sec : m_sections) {
        uint32_t sec_end = sec.virtual_address + sec.virtual_size;
        if (rva >= sec.virtual_address && rva < sec_end) {
            return sec.raw_offset + (rva - sec.virtual_address);
        }
    }
    // Might be in the header area
    if (rva < m_header.header_size) {
        return rva;
    }
    return rva; // Fallback
}

// ─── Parse DOS Header ───

bool PeParser::parse_dos_header() {
    if (m_filesize < 64) return false;

    uint16_t e_magic = read_val_at<uint16_t>(0);
    if (e_magic != 0x5A4D) { // "MZ"
        return false;
    }

    // e_lfanew at offset 0x3C
    m_pe_offset = read_val_at<uint32_t>(0x3C);
    if (m_pe_offset == 0 || m_pe_offset + 4 > m_filesize) {
        return false;
    }

    // Verify PE signature "PE\0\0"
    uint32_t pe_sig = read_val_at<uint32_t>(m_pe_offset);
    if (pe_sig != 0x00004550) {
        return false;
    }

    m_coff_offset = m_pe_offset + 4;
    return true;
}

// ─── Parse PE Header ───

bool PeParser::parse_pe_header() {
    m_file.seekg(m_coff_offset);

    // COFF Header (20 bytes)
    m_header.machine        = read_val<uint16_t>();
    m_header.num_sections   = read_val<uint16_t>();
    m_header.timestamp      = read_val<uint32_t>();
    read_val<uint32_t>(); // PointerToSymbolTable (unused)
    read_val<uint32_t>(); // NumberOfSymbols (unused)
    uint16_t opt_header_size = read_val<uint16_t>();
    m_header.characteristics = read_val<uint16_t>();

    if (opt_header_size == 0) {
        // No optional header - not a valid PE for our purposes
        return false;
    }

    m_opt_offset = m_coff_offset + 20;
    m_sec_offset = m_opt_offset + opt_header_size;

    return parse_optional_header();
}

// ─── Parse Optional Header ───

bool PeParser::parse_optional_header() {
    m_file.seekg(m_opt_offset);

    uint16_t magic = read_val<uint16_t>();
    m_header.opt_magic = magic;

    if (magic == PE_OPT_MAGIC_PE32) {
        m_header.is_64bit = 0;
    } else if (magic == PE_OPT_MAGIC_PE32PLUS) {
        m_header.is_64bit = 1;
    } else {
        return false;
    }

    // Common fields for both PE32 and PE32+
    read_val<uint8_t>();  // MajorLinkerVersion
    read_val<uint8_t>();  // MinorLinkerVersion
    read_val<uint32_t>(); // SizeOfCode
    read_val<uint32_t>(); // SizeOfInitializedData
    read_val<uint32_t>(); // SizeOfUninitializedData
    m_header.entry_point_rva = read_val<uint32_t>(); // AddressOfEntryPoint

    read_val<uint32_t>(); // BaseOfCode

    if (magic == PE_OPT_MAGIC_PE32) {
        read_val<uint32_t>(); // BaseOfData (PE32 only)
        uint32_t image_base_32 = read_val<uint32_t>();
        m_header.image_base = image_base_32;
    } else {
        // PE32+
        uint64_t image_base_64 = read_val<uint64_t>();
        m_header.image_base = image_base_64;
    }

    uint32_t section_align = read_val<uint32_t>();
    m_header.section_alignment = section_align;
    uint32_t file_align = read_val<uint32_t>();
    m_header.file_alignment = file_align;

    // Skip OS version info (4 x uint16_t)
    read_val<uint16_t>(); read_val<uint16_t>();
    read_val<uint16_t>(); read_val<uint16_t>();

    // Win32 version, image size, header size
    read_val<uint32_t>(); // Win32VersionValue
    m_header.image_size = read_val<uint32_t>();
    m_header.header_size = read_val<uint32_t>();

    // Skip checksum
    read_val<uint32_t>();

    m_header.subsystem = read_val<uint16_t>();
    m_header.dll_characteristics = read_val<uint16_t>();

    // Skip stack/heap sizes
    if (magic == PE_OPT_MAGIC_PE32) {
        read_val<uint32_t>(); read_val<uint32_t>(); // Stack Rsv/Cmt
        read_val<uint32_t>(); read_val<uint32_t>(); // Heap  Rsv/Cmt
    } else {
        read_val<uint64_t>(); read_val<uint64_t>(); // Stack Rsv/Cmt
        read_val<uint64_t>(); read_val<uint64_t>(); // Heap  Rsv/Cmt
    }

    read_val<uint32_t>(); // LoaderFlags
    uint32_t num_dd = read_val<uint32_t>();
    m_header.number_of_rva_and_sizes = num_dd;

    // Read data directories
    uint32_t dd_count = (num_dd < 16) ? num_dd : 16;
    for (uint32_t i = 0; i < dd_count; ++i) {
        m_data_dirs[i].rva  = read_val<uint32_t>();
        m_data_dirs[i].size = read_val<uint32_t>();
    }

    return true;
}

// ─── Parse Section Headers ───

bool PeParser::parse_section_headers() {
    m_file.seekg(m_sec_offset);

    for (uint16_t i = 0; i < m_header.num_sections; ++i) {
        PeSection sec{};

        // Name is 8 bytes, not null-terminated
        char name_buf[9] = {};
        m_file.read(name_buf, 8);
        sec.name = name_buf;

        sec.virtual_size     = read_val<uint32_t>();
        sec.virtual_address  = read_val<uint32_t>();
        sec.raw_size         = read_val<uint32_t>();
        sec.raw_offset       = read_val<uint32_t>();
        read_val<uint32_t>(); // PointerToRelocations
        read_val<uint32_t>(); // PointerToLinenumbers
        read_val<uint16_t>(); // NumberOfRelocations
        read_val<uint16_t>(); // NumberOfLinenumbers
        sec.characteristics  = read_val<uint32_t>();

        sec.end_va = sec.virtual_address + sec.virtual_size;

        m_sections.push_back(sec);
    }

    return true;
}

// ─── Parse Import Directory ───

bool PeParser::parse_import_directory() {
    if (m_data_dirs[DD_IMPORT].rva == 0 || m_data_dirs[DD_IMPORT].size == 0) {
        return true; // No imports
    }

    uint32_t import_rva = m_data_dirs[DD_IMPORT].rva;
    uint64_t import_offset = rva_to_offset(import_rva);
    if (import_offset == 0 || import_offset >= m_filesize) return true;

    // Each import directory entry is 20 bytes
    // Terminated by an all-zero entry
    uint64_t entry_offset = import_offset;
    while (true) {
        if (entry_offset + 20 > m_filesize) break;

        uint32_t ilt_rva         = read_val_at<uint32_t>(entry_offset + 0);
        uint32_t timestamp       = read_val_at<uint32_t>(entry_offset + 4);
        uint32_t forwarder_chain = read_val_at<uint32_t>(entry_offset + 8);
        uint32_t name_rva        = read_val_at<uint32_t>(entry_offset + 12);
        uint32_t iat_rva         = read_val_at<uint32_t>(entry_offset + 16);

        // All zeros = end of import directory
        if (name_rva == 0 && ilt_rva == 0 && iat_rva == 0) break;

        PeImportDll dll{};
        dll.first_thunk_rva = iat_rva;
        dll.original_first_thunk_rva = ilt_rva;

        // Read DLL name
        if (name_rva != 0) {
            uint64_t name_offset = rva_to_offset(name_rva);
            if (name_offset < m_filesize) {
                auto pos = m_file.tellg();
                m_file.seekg(static_cast<std::streamoff>(name_offset));
                char c;
                while (m_file.get(c) && c != '\0' && c != '\n') {
                    dll.name += c;
                }
                m_file.seekg(pos);
            }
        }

        // Read import thunks (function names)
        // Use ILT if available, otherwise IAT
        uint32_t thunk_rva = ilt_rva ? ilt_rva : iat_rva;
        if (thunk_rva != 0) {
            uint64_t thunk_offset = rva_to_offset(thunk_rva);
            uint32_t entry_size = is_64bit() ? 8 : 4;

            for (uint32_t idx = 0; ; ++idx) {
                uint64_t thunk_entry_offset = thunk_offset + idx * entry_size;
                if (thunk_entry_offset + entry_size > m_filesize) break;

                uint64_t thunk_val = 0;
                if (is_64bit()) {
                    thunk_val = read_val_at<uint64_t>(thunk_entry_offset);
                } else {
                    thunk_val = read_val_at<uint32_t>(thunk_entry_offset);
                }

                if (thunk_val == 0) break; // End of thunk array

                PeSymbol sym{};
                sym.dll_name = dll.name;
                sym.type = "import";
                sym.bind = "external";

                // Check if import by ordinal (bit 31 set for PE32, bit 63 for PE32+)
                bool by_ordinal = is_64bit() ? (thunk_val & (1ULL << 63)) : (thunk_val & (1U << 31));

                if (by_ordinal) {
                    uint16_t ordinal_val = static_cast<uint16_t>(thunk_val & 0xFFFF);
                    sym.ordinal = ordinal_val;
                    sym.name = dll.name + "::ordinal_" + std::to_string(ordinal_val);
                    sym.rva = 0; // Will be filled at runtime
                    sym.va = 0;
                } else {
                    // Import by name - read hint/name
                    uint32_t hint_name_rva = static_cast<uint32_t>(thunk_val & 0x7FFFFFFF);
                    uint64_t hint_name_offset = rva_to_offset(hint_name_rva);
                    if (hint_name_offset + 2 < m_filesize) {
                        uint16_t hint = read_val_at<uint16_t>(hint_name_offset);
                        sym.ordinal = hint;

                        // Read function name after hint
                        auto pos = m_file.tellg();
                        m_file.seekg(static_cast<std::streamoff>(hint_name_offset + 2));
                        char c;
                        while (m_file.get(c) && c != '\0' && c != '\n') {
                            sym.name += c;
                        }
                        m_file.seekg(pos);
                    }

                    // IAT entry RVA will be resolved at runtime
                    uint64_t iat_entry_offset = rva_to_offset(iat_rva) + idx * entry_size;
                    sym.rva = iat_rva + idx * entry_size;
                    sym.va = m_header.image_base + sym.rva;
                }

                if (!sym.name.empty()) {
                    dll.functions.push_back(sym);
                }
            }
        }

        if (!dll.name.empty()) {
            m_imports.push_back(dll);
        }

        entry_offset += 20;
    }

    return true;
}

// ─── Parse Export Directory ───

bool PeParser::parse_export_directory() {
    if (m_data_dirs[DD_EXPORT].rva == 0 || m_data_dirs[DD_EXPORT].size == 0) {
        return true; // No exports
    }

    uint32_t export_rva = m_data_dirs[DD_EXPORT].rva;
    uint64_t export_offset = rva_to_offset(export_rva);
    if (export_offset == 0 || export_offset + 40 > m_filesize) return true;

    // Export directory table (skip unused header fields)
    (void)read_val_at<uint32_t>(export_offset + 0);  // Characteristics
    (void)read_val_at<uint32_t>(export_offset + 4);  // TimeDateStamp
    (void)read_val_at<uint16_t>(export_offset + 8);  // MajorVersion
    (void)read_val_at<uint16_t>(export_offset + 10); // MinorVersion
    uint32_t name_rva        = read_val_at<uint32_t>(export_offset + 12);
    uint32_t base            = read_val_at<uint32_t>(export_offset + 16);
    uint32_t num_functions   = read_val_at<uint32_t>(export_offset + 20);
    uint32_t num_names       = read_val_at<uint32_t>(export_offset + 24);
    uint32_t addr_table_rva  = read_val_at<uint32_t>(export_offset + 28);
    uint32_t name_table_rva  = read_val_at<uint32_t>(export_offset + 32);
    uint32_t ordinal_table_rva = read_val_at<uint32_t>(export_offset + 36);

    // Read DLL name
    std::string dll_name;
    if (name_rva != 0) {
        uint64_t name_offset = rva_to_offset(name_rva);
        if (name_offset < m_filesize) {
            auto pos = m_file.tellg();
            m_file.seekg(static_cast<std::streamoff>(name_offset));
            char c;
            while (m_file.get(c) && c != '\0' && c != '\n') {
                dll_name += c;
            }
            m_file.seekg(pos);
        }
    }

    // Read named exports
    if (name_table_rva != 0 && ordinal_table_rva != 0 && addr_table_rva != 0) {
        uint64_t name_table_offset = rva_to_offset(name_table_rva);
        uint64_t ordinal_table_offset = rva_to_offset(ordinal_table_rva);
        uint64_t addr_table_offset = rva_to_offset(addr_table_rva);

        uint32_t count = (num_names < num_functions) ? num_names : num_functions;
        if (count > 100000) count = 100000; // Safety limit

        for (uint32_t i = 0; i < count; ++i) {
            if (name_table_offset + (i + 1) * 4 > m_filesize) break;
            if (ordinal_table_offset + (i + 1) * 2 > m_filesize) break;

            uint32_t func_name_rva = read_val_at<uint32_t>(name_table_offset + i * 4);
            uint16_t ordinal_idx   = read_val_at<uint16_t>(ordinal_table_offset + i * 2);

            PeSymbol sym{};
            sym.type = "export";
            sym.bind = "global";
            sym.dll_name = dll_name;
            sym.ordinal = base + ordinal_idx;

            // Read function name
            if (func_name_rva != 0) {
                uint64_t fn_offset = rva_to_offset(func_name_rva);
                if (fn_offset < m_filesize) {
                    auto pos = m_file.tellg();
                    m_file.seekg(static_cast<std::streamoff>(fn_offset));
                    char c;
                    while (m_file.get(c) && c != '\0' && c != '\n') {
                        sym.name += c;
                    }
                    m_file.seekg(pos);
                }
            }

            // Read function RVA from address table
            if (addr_table_offset + (ordinal_idx + 1) * 4 <= m_filesize) {
                uint32_t func_rva = read_val_at<uint32_t>(addr_table_offset + ordinal_idx * 4);
                sym.rva = func_rva;
                sym.va = m_header.image_base + func_rva;
            }

            if (!sym.name.empty()) {
                m_exports.push_back(sym);
            }
        }
    }

    // Also collect unnamed exports (by ordinal only)
    if (addr_table_rva != 0 && num_functions > 0) {
        uint64_t addr_table_offset = rva_to_offset(addr_table_rva);
        uint32_t count = (num_functions > 100000) ? 100000 : num_functions;

        for (uint32_t i = 0; i < count; ++i) {
            if (addr_table_offset + (i + 1) * 4 > m_filesize) break;

            uint32_t func_rva = read_val_at<uint32_t>(addr_table_offset + i * 4);
            if (func_rva == 0) continue;

            // Check if this ordinal is already named
            bool already_named = false;
            for (const auto& exp : m_exports) {
                if (exp.ordinal == base + i) {
                    already_named = true;
                    break;
                }
            }

            if (!already_named) {
                PeSymbol sym{};
                sym.name = "ordinal_" + std::to_string(base + i);
                sym.rva = func_rva;
                sym.va = m_header.image_base + func_rva;
                sym.type = "export";
                sym.bind = "global";
                sym.ordinal = base + i;
                sym.dll_name = dll_name;
                m_exports.push_back(sym);
            }
        }
    }

    return true;
}

// ─── Collect All Functions ───

void PeParser::collect_all_functions() {
    // Exports
    for (const auto& exp : m_exports) {
        m_all_functions.push_back(exp);
    }

    // Import functions
    for (const auto& dll : m_imports) {
        for (const auto& fn : dll.functions) {
            m_all_functions.push_back(fn);
        }
    }

    // Entry point as a function
    if (m_header.entry_point_rva != 0) {
        PeSymbol ep{};
        ep.name = "EntryPoint";
        ep.rva = m_header.entry_point_rva;
        ep.va = m_header.image_base + m_header.entry_point_rva;
        ep.type = "entry";
        ep.bind = "global";
        m_all_functions.push_back(ep);
    }

    // Discovered functions from deep scanning
    for (const auto& df : m_discovered) {
        m_all_functions.push_back(df);
    }

    // Sort by VA
    std::sort(m_all_functions.begin(), m_all_functions.end(),
        [](const PeSymbol& a, const PeSymbol& b) {
            return a.va < b.va;
        });
}

// ─── Scan Exception Directory (.pdata / RUNTIME_FUNCTION) ───

void PeParser::scan_exception_directory() {
    // Data directory index 3 = Exception directory
    if (m_data_dirs[3].rva == 0 || m_data_dirs[3].size == 0) return;

    // Only valid for x64 (PE_MACHINE_AMD64)
    if (m_header.machine != PE_MACHINE_AMD64) return;

    uint32_t pdata_rva = m_data_dirs[3].rva;
    uint32_t pdata_size = m_data_dirs[3].size;
    uint64_t pdata_offset = rva_to_offset(pdata_rva);
    if (pdata_offset == 0 || pdata_offset + pdata_size > m_filesize) return;

    // Each RUNTIME_FUNCTION entry is 12 bytes: BeginOffset(4), EndOffset(4), UnwindInfoOffset(4)
    size_t entry_count = pdata_size / 12;
    if (entry_count > 1000000) entry_count = 1000000;

    for (size_t i = 0; i < entry_count; ++i) {
        uint64_t entry_off = pdata_offset + i * 12;
        if (entry_off + 12 > m_filesize) break;

        uint32_t begin_rva = read_val_at<uint32_t>(entry_off + 0);
        uint32_t end_rva   = read_val_at<uint32_t>(entry_off + 4);
        // uint32_t unwind_rva = read_val_at<uint32_t>(entry_off + 8); // not needed

        if (begin_rva == 0 || end_rva == 0 || end_rva <= begin_rva) continue;

        PeSymbol sym{};
        sym.rva = begin_rva;
        sym.va = m_header.image_base + begin_rva;
        sym.size = end_rva - begin_rva;
        sym.type = "exception";
        sym.bind = "local";
        sym.name = "func_" + std::to_string(begin_rva);
        m_discovered.push_back(sym);
    }
}

// ─── Scan TLS Callbacks ───

void PeParser::scan_tls_callbacks() {
    // Data directory index 9 = TLS directory
    if (m_data_dirs[9].rva == 0 || m_data_dirs[9].size == 0) return;

    uint32_t tls_rva = m_data_dirs[9].rva;
    uint64_t tls_offset = rva_to_offset(tls_rva);
    if (tls_offset == 0 || tls_offset + (is_64bit() ? 24 : 16) > m_filesize) return;

    // TLS directory structure varies between PE32 and PE32+
    uint32_t callbacks_rva = 0;
    if (is_64bit()) {
        // PE32+: StartDataOfRawData(8), EndDataOfRawData(8), AddressOfIndex(8), AddressOfCallBacks(8)
        callbacks_rva = read_val_at<uint32_t>(tls_offset + 24);
    } else {
        // PE32: StartDataOfRawData(4), EndDataOfRawData(4), AddressOfIndex(4), AddressOfCallBacks(4)
        callbacks_rva = read_val_at<uint32_t>(tls_offset + 12);
    }

    if (callbacks_rva == 0) return;

    uint64_t callbacks_offset = rva_to_offset(callbacks_rva);
    if (callbacks_offset == 0) return;

    size_t ptr_size = is_64bit() ? 8 : 4;
    for (size_t idx = 0; ; ++idx) {
        uint64_t cb_entry_off = callbacks_offset + idx * ptr_size;
        if (cb_entry_off + ptr_size > m_filesize) break;

        uint64_t callback_va = 0;
        if (is_64bit()) {
            callback_va = read_val_at<uint64_t>(cb_entry_off);
        } else {
            callback_va = read_val_at<uint32_t>(cb_entry_off);
        }

        if (callback_va == 0) break; // Null terminator

        PeSymbol sym{};
        sym.va = callback_va;
        sym.rva = static_cast<uint32_t>(callback_va - m_header.image_base);
        sym.type = "tls_callback";
        sym.bind = "global";
        sym.name = "TlsCallback_" + std::to_string(idx);
        m_discovered.push_back(sym);
    }
}

// ─── Scan Code Prologues ───

void PeParser::scan_code_prologues() {
    // Scan executable sections for common function prologue patterns
    for (const auto& sec : m_sections) {
        // Only scan sections with execute permission
        if (!(sec.characteristics & PE_SECTION_EXEC)) continue;
        if (sec.raw_size == 0 || sec.raw_offset == 0) continue;

        uint64_t sec_end = sec.raw_offset + sec.raw_size;
        if (sec_end > m_filesize) sec_end = m_filesize;

        // Read the section data
        std::ifstream f(m_filepath, std::ios::binary);
        if (!f.is_open()) continue;

        std::vector<uint8_t> data(sec.raw_size);
        f.seekg(static_cast<std::streamoff>(sec.raw_offset));
        f.read(reinterpret_cast<char*>(data.data()), sec.raw_size);
        f.close();

        if (m_header.machine == PE_MACHINE_AMD64) {
            // x64 prologues:
            // push rbp           : 55
            // mov rbp, rsp       : 48 8B EC  or  48 89 EC
            // sub rsp, imm8      : 48 83 EC XX
            // sub rsp, imm32     : 48 81 EC XX XX XX XX
            // push rbx           : 53
            // mov [rsp+X], rbx   : 48 89 5C 24 XX
            for (size_t i = 0; i + 1 < data.size(); ++i) {
                bool is_prologue = false;

                if (data[i] == 0x55) { // push rbp
                    is_prologue = true;
                } else if (i + 3 < data.size() && data[i] == 0x48 && data[i+1] == 0x89 && data[i+2] == 0xEC) {
                    // mov rbp, rsp (48 89 EC)
                    is_prologue = true;
                } else if (i + 3 < data.size() && data[i] == 0x48 && data[i+1] == 0x8B && data[i+2] == 0xEC) {
                    // mov rbp, rsp (48 8B EC)
                    is_prologue = true;
                } else if (i + 3 < data.size() && data[i] == 0x48 && data[i+1] == 0x83 && data[i+2] == 0xEC) {
                    // sub rsp, imm8
                    is_prologue = true;
                } else if (i + 5 < data.size() && data[i] == 0x48 && data[i+1] == 0x81 && data[i+2] == 0xEC) {
                    // sub rsp, imm32
                    is_prologue = true;
                } else if (i + 4 < data.size() && data[i] == 0x40 && data[i+1] == 0x53) {
                    // push rbx (REX prefix)
                    is_prologue = true;
                } else if (i + 3 < data.size() && data[i] == 0x48 && data[i+1] == 0x89 && data[i+2] == 0x5C) {
                    // mov [rsp+X], rbx
                    is_prologue = true;
                }

                if (is_prologue) {
                    uint32_t func_rva = sec.virtual_address + static_cast<uint32_t>(i);
                    // Check if already known
                    bool already_known = false;
                    for (const auto& existing : m_all_functions) {
                        if (existing.rva == func_rva) { already_known = true; break; }
                    }
                    for (const auto& existing : m_discovered) {
                        if (existing.rva == func_rva) { already_known = true; break; }
                    }
                    if (!already_known) {
                        PeSymbol sym{};
                        sym.rva = func_rva;
                        sym.va = m_header.image_base + func_rva;
                        sym.type = "prologue";
                        sym.bind = "local";
                        sym.name = "sub_" + std::to_string(func_rva);
                        m_discovered.push_back(sym);
                    }
                }
            }
        } else if (m_header.machine == PE_MACHINE_I386) {
            // x86 prologues:
            // push ebp           : 55
            // mov ebp, esp       : 8B EC  or  89 E5
            // sub esp, imm8      : 83 EC XX
            // sub esp, imm32     : 81 EC XX XX XX XX
            for (size_t i = 0; i + 1 < data.size(); ++i) {
                bool is_prologue = false;

                if (data[i] == 0x55) { // push ebp
                    is_prologue = true;
                } else if (i + 1 < data.size() && data[i] == 0x8B && data[i+1] == 0xEC) {
                    // mov ebp, esp
                    is_prologue = true;
                } else if (i + 1 < data.size() && data[i] == 0x89 && data[i+1] == 0xE5) {
                    // mov ebp, esp (alternate)
                    is_prologue = true;
                } else if (i + 2 < data.size() && data[i] == 0x83 && data[i+1] == 0xEC) {
                    // sub esp, imm8
                    is_prologue = true;
                } else if (i + 5 < data.size() && data[i] == 0x81 && data[i+1] == 0xEC) {
                    // sub esp, imm32
                    is_prologue = true;
                }

                if (is_prologue) {
                    uint32_t func_rva = sec.virtual_address + static_cast<uint32_t>(i);
                    bool already_known = false;
                    for (const auto& existing : m_all_functions) {
                        if (existing.rva == func_rva) { already_known = true; break; }
                    }
                    for (const auto& existing : m_discovered) {
                        if (existing.rva == func_rva) { already_known = true; break; }
                    }
                    if (!already_known) {
                        PeSymbol sym{};
                        sym.rva = func_rva;
                        sym.va = m_header.image_base + func_rva;
                        sym.type = "prologue";
                        sym.bind = "local";
                        sym.name = "sub_" + std::to_string(func_rva);
                        m_discovered.push_back(sym);
                    }
                }
            }
        }
    }
}

// ─── Scan Relocations ───

void PeParser::scan_relocations() {
    // Data directory index 5 = Base Relocation directory
    if (m_data_dirs[5].rva == 0 || m_data_dirs[5].size == 0) return;

    uint32_t reloc_rva = m_data_dirs[5].rva;
    uint32_t reloc_size = m_data_dirs[5].size;
    uint64_t reloc_offset = rva_to_offset(reloc_rva);
    if (reloc_offset == 0 || reloc_offset + reloc_size > m_filesize) return;

    uint64_t offset = reloc_offset;
    uint64_t end_offset = reloc_offset + reloc_size;

    while (offset + 8 <= end_offset) {
        uint32_t page_rva = read_val_at<uint32_t>(offset + 0);
        uint32_t block_size = read_val_at<uint32_t>(offset + 4);

        if (block_size == 0 || block_size < 8) break;
        if (offset + block_size > end_offset) break;

        // Number of entries in this block
        size_t entry_count = (block_size - 8) / 2;
        for (size_t i = 0; i < entry_count; ++i) {
            uint64_t entry_off = offset + 8 + i * 2;
            if (entry_off + 2 > m_filesize) break;

            uint16_t entry = read_val_at<uint16_t>(entry_off);
            uint16_t type = (entry >> 12) & 0xF;
            uint16_t offset_val = entry & 0xFFF;

            // Type 3 = IMAGE_REL_BASED_HIGHLOW (x86), Type 10 = IMAGE_REL_BASED_DIR64 (x64)
            if (type == 3 || type == 10) {
                uint32_t target_rva = page_rva + offset_val;

                // This is a relocation target - likely a code/data reference
                // Only add if it falls in an executable section
                for (const auto& sec : m_sections) {
                    if (target_rva >= sec.virtual_address && target_rva < sec.end_va) {
                        if (sec.characteristics & PE_SECTION_EXEC) {
                            // Check if already known
                            bool already_known = false;
                            for (const auto& existing : m_discovered) {
                                if (existing.rva == target_rva) { already_known = true; break; }
                            }
                            if (!already_known) {
                                PeSymbol sym{};
                                sym.rva = target_rva;
                                sym.va = m_header.image_base + target_rva;
                                sym.type = "reloc";
                                sym.bind = "local";
                                sym.name = "reloc_" + std::to_string(target_rva);
                                m_discovered.push_back(sym);
                            }
                        }
                        break;
                    }
                }
            }
        }

        offset += block_size;
    }
}

// ─── String Extraction ───

void PeParser::extract_strings(size_t min_length) {
    m_strings.clear();
    if (m_filesize == 0) return;

    // Re-read the file for string scanning
    std::ifstream f(m_filepath, std::ios::binary);
    if (!f.is_open()) return;

    std::string current;
    uint64_t start_offset = 0;

    for (uint64_t i = 0; i < m_filesize; ++i) {
        char c;
        f.read(&c, 1);
        if (c >= 0x20 && c <= 0x7E) {
            if (current.empty()) start_offset = i;
            current += c;
        } else {
            if (current.size() >= min_length) {
                m_strings.emplace_back(start_offset, current);
            }
            current.clear();
        }
    }
    if (current.size() >= min_length) {
        m_strings.emplace_back(start_offset, current);
    }
}

// ─── Main Parse ───

bool PeParser::parse() {
    if (!m_file.is_open()) return false;

    if (!parse_dos_header()) return false;
    if (!parse_pe_header()) return false;
    if (!parse_section_headers()) return false;
    if (!parse_import_directory()) return false;
    if (!parse_export_directory()) return false;

    // Deep scanning for additional functions
    scan_exception_directory();
    scan_tls_callbacks();

    collect_all_functions();
    extract_strings();

    m_valid = true;
    return true;
}
