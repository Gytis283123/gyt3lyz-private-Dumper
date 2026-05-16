#include "elf_parser.h"
#include "search_helper.h"
#include <cstring>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <iomanip>
#include <map>
#include <set>

// ELF program header flags
#ifndef PF_X
#define PF_X 0x1
#endif

// ─── ElfSymbol name helpers ───

const char* ElfSymbol::type_name() const {
    static const char* names[] = {
        "NOTYPE","OBJECT","FUNC","SECTION","FILE","COMMON","TLS",
        "","","","","LOOS","","HIOS","LOPROC","","HIPROC"
    };
    uint8_t t = type_val();
    return (t < 17) ? names[t] : "UNKNOWN";
}

const char* ElfSymbol::bind_name() const {
    static const char* names[] = {
        "LOCAL","GLOBAL","WEAK","","","","","","","","LOOS","","HIOS","LOPROC","","HIPROC"
    };
    uint8_t b = bind_val();
    return (b < 16) ? names[b] : "UNKNOWN";
}

// ─── ElfParser ───

ElfParser::ElfParser(const std::string& filepath)
    : m_filepath(filepath)
{
    m_file.open(filepath, std::ios::binary);
    if (m_file.is_open()) {
        m_file.seekg(0, std::ios::end);
        m_filesize = static_cast<uint64_t>(m_file.tellg());
        m_file.seekg(0, std::ios::beg);
    }
}

ElfParser::~ElfParser() {
    if (m_file.is_open()) m_file.close();
}

template<typename T>
T ElfParser::read_val() {
    T val{};
    m_file.read(reinterpret_cast<char*>(&val), sizeof(T));
    return val;
}

template<typename T>
T ElfParser::read_val_at(uint64_t file_offset) {
    m_file.seekg(static_cast<std::streamoff>(file_offset));
    return read_val<T>();
}

bool ElfParser::parse() {
    if (!m_file.is_open()) return false;

    if (!parse_header())       return false;
    if (!parse_program_headers()) return false;
    if (!parse_sections())     return false;
    if (!parse_symbols())      return false;

    extract_strings(); // Extract strings first
    scan_code_functions(); // Find internal game functions (uses strings for naming)
    deobfuscate_functions(); // Rename functions based on string references
    scan_vtables(); // Deep vtable scanning to find virtual functions
    deobfuscate_functions(); // Deobfuscate any new functions found by vtable scan
    scan_hidden_functions(); // Find hidden functions missed by other methods
    deobfuscate_functions(); // Deobfuscate any new functions found by hidden scan
    
    m_valid = true;
    return true;
}

bool ElfParser::parse_header() {
    m_file.seekg(0);
    uint8_t magic[16];
    m_file.read(reinterpret_cast<char*>(magic), 16);

    if (magic[0] != 0x7f || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F')
        return false;

    m_header.ei_class = magic[4];
    m_header.ei_data  = magic[5];
    m_is64  = (m_header.ei_class == 2);
    m_is_le = (m_header.ei_data == 1);

    if (m_is64) {
        m_header.e_type     = read_val<uint16_t>();
        m_header.e_machine  = read_val<uint16_t>();
        /*e_version*/         read_val<uint32_t>();
        m_header.e_entry    = read_val<uint64_t>();
        m_header.e_phoff    = read_val<uint64_t>();
        m_header.e_shoff    = read_val<uint64_t>();
        /*e_flags*/           read_val<uint32_t>();
        /*e_ehsize*/          read_val<uint16_t>();
        /*e_phentsize*/       read_val<uint16_t>();
        m_header.e_phnum    = read_val<uint16_t>();
        /*e_shentsize*/       read_val<uint16_t>();
        m_header.e_shnum    = read_val<uint16_t>();
        m_header.e_shstrndx = read_val<uint16_t>();
    } else {
        m_header.e_type     = read_val<uint16_t>();
        m_header.e_machine  = read_val<uint16_t>();
        /*e_version*/         read_val<uint32_t>();
        m_header.e_entry    = read_val<uint32_t>();
        m_header.e_phoff    = read_val<uint32_t>();
        m_header.e_shoff    = read_val<uint32_t>();
        /*e_flags*/           read_val<uint32_t>();
        /*e_ehsize*/          read_val<uint16_t>();
        /*e_phentsize*/       read_val<uint16_t>();
        m_header.e_phnum    = read_val<uint16_t>();
        /*e_shentsize*/       read_val<uint16_t>();
        m_header.e_shnum    = read_val<uint16_t>();
        m_header.e_shstrndx = read_val<uint16_t>();
    }
    return true;
}

bool ElfParser::parse_program_headers() {
    if (m_header.e_phoff == 0 || m_header.e_phnum == 0) return true;

    m_file.seekg(static_cast<std::streamoff>(m_header.e_phoff));
    m_phdrs.resize(m_header.e_phnum);

    for (auto& ph : m_phdrs) {
        if (m_is64) {
            ph.type   = read_val<uint32_t>();
            ph.flags  = read_val<uint32_t>();
            ph.offset = read_val<uint64_t>();
            ph.vaddr  = read_val<uint64_t>();
            ph.paddr  = read_val<uint64_t>();
            ph.filesz = read_val<uint64_t>();
            ph.memsz  = read_val<uint64_t>();
            ph.align  = read_val<uint64_t>();
        } else {
            ph.type   = read_val<uint32_t>();
            ph.offset = read_val<uint32_t>();
            ph.vaddr  = read_val<uint32_t>();
            ph.paddr  = read_val<uint32_t>();
            ph.filesz = read_val<uint32_t>();
            ph.memsz  = read_val<uint32_t>();
            ph.flags  = read_val<uint32_t>();
            ph.align  = read_val<uint32_t>();
        }
    }
    return true;
}

uint64_t ElfParser::va_to_offset(uint64_t vaddr) const {
    for (const auto& ph : m_phdrs) {
        if (ph.type == PT_LOAD && vaddr >= ph.vaddr && vaddr < ph.vaddr + ph.filesz) {
            return ph.offset + (vaddr - ph.vaddr);
        }
    }
    // Fallback: assume identity mapping
    return vaddr;
}

bool ElfParser::parse_sections() {
    if (m_header.e_shoff == 0 || m_header.e_shnum == 0) return true;

    m_file.seekg(static_cast<std::streamoff>(m_header.e_shoff));
    m_sections.resize(m_header.e_shnum);

    for (auto& sec : m_sections) {
        if (m_is64) {
            sec.name_offset = read_val<uint32_t>();
            sec.type        = read_val<uint32_t>();
            sec.flags       = read_val<uint64_t>();
            sec.addr        = read_val<uint64_t>();
            sec.offset      = read_val<uint64_t>();
            sec.size        = read_val<uint64_t>();
            sec.link        = read_val<uint32_t>();
            sec.info        = read_val<uint32_t>();
            sec.addralign   = read_val<uint64_t>();
            sec.entsize     = read_val<uint64_t>();
        } else {
            sec.name_offset = read_val<uint32_t>();
            sec.type        = read_val<uint32_t>();
            sec.flags       = read_val<uint32_t>();
            sec.addr        = read_val<uint32_t>();
            sec.offset      = read_val<uint32_t>();
            sec.size        = read_val<uint32_t>();
            sec.link        = read_val<uint32_t>();
            sec.info        = read_val<uint32_t>();
            sec.addralign   = read_val<uint32_t>();
            sec.entsize     = read_val<uint32_t>();
        }
    }

    // Resolve section names from shstrtab
    if (m_header.e_shstrndx < m_sections.size()) {
        for (auto& sec : m_sections) {
            sec.name = read_strtab(m_header.e_shstrndx, sec.name_offset);
        }
    }
    return true;
}

std::string ElfParser::read_strtab(uint32_t strtab_idx, uint32_t offset) {
    if (strtab_idx >= m_sections.size()) return "";
    auto& sec = m_sections[strtab_idx];
    if (sec.offset == 0 || sec.size == 0) return "";

    std::string result;
    m_file.seekg(static_cast<std::streamoff>(sec.offset + offset));
    char c;
    while (m_file.get(c) && c != '\0') {
        result += c;
    }
    return result;
}

std::string ElfParser::read_strtab_at(uint64_t strtab_file_offset, uint32_t name_offset) {
    std::string result;
    m_file.seekg(static_cast<std::streamoff>(strtab_file_offset + name_offset));
    char c;
    while (m_file.get(c) && c != '\0') {
        result += c;
    }
    return result;
}

bool ElfParser::parse_symbols() {
    for (const auto& sec : m_sections) {
        if (sec.type == SHT_SYMTAB) {
            parse_symbol_table(sec, m_symbols);
        } else if (sec.type == SHT_DYNSYM) {
            parse_symbol_table(sec, m_dynsyms);
        }
    }
    return true;
}

bool ElfParser::parse_symbol_table(const ElfSection& symtab, std::vector<ElfSymbol>& out) {
    if (symtab.entsize == 0 || symtab.size == 0) return false;

    uint64_t count = symtab.size / symtab.entsize;

    for (uint64_t i = 0; i < count; ++i) {
        ElfSymbol sym;
        auto pos = static_cast<std::streamoff>(symtab.offset + i * symtab.entsize);
        m_file.seekg(pos);

        if (m_is64) {
            sym.name_offset = read_val<uint32_t>();
            sym.info        = read_val<uint8_t>();
            sym.other       = read_val<uint8_t>();
            sym.shndx       = read_val<uint16_t>();
            sym.value       = read_val<uint64_t>();
            sym.size        = read_val<uint64_t>();
        } else {
            sym.name_offset = read_val<uint32_t>();
            sym.value       = read_val<uint32_t>();
            sym.size        = read_val<uint32_t>();
            sym.info        = read_val<uint8_t>();
            sym.other       = read_val<uint8_t>();
            sym.shndx       = read_val<uint16_t>();
        }

        sym.name = read_strtab(symtab.link, sym.name_offset);
        out.push_back(sym);
    }
    return true;
}

uint32_t ElfParser::get_dynsym_count_from_hash(uint64_t hash_offset) {
    // DT_HASH format: nbucket, nchain, bucket[], chain[]
    // nchain == number of symbols
    return read_val_at<uint32_t>(hash_offset + 4);
}

uint32_t ElfParser::get_dynsym_count_from_gnu_hash(uint64_t gnu_hash_offset, uint64_t symtab_offset, uint64_t syment) {
    // GNU hash format: nbuckets, symoffset, bloom_size, bloom_shift, bloom[], buckets[], chains[]
    uint32_t nbuckets = read_val_at<uint32_t>(gnu_hash_offset);
    uint32_t symoffset = read_val_at<uint32_t>(gnu_hash_offset + 4);
    uint32_t bloom_size = read_val_at<uint32_t>(gnu_hash_offset + 8);
    // bloom_shift at +12

    // Skip bloom filter
    uint64_t bloom_bytes = bloom_size * (m_is64 ? 8 : 4);
    uint64_t buckets_off = gnu_hash_offset + 16 + bloom_bytes;

    // Find max bucket value to determine start of chains
    uint32_t max_sym = 0;
    for (uint32_t b = 0; b < nbuckets; ++b) {
        uint32_t val = read_val_at<uint32_t>(buckets_off + b * 4);
        if (val > max_sym) max_sym = val;
    }

    if (max_sym == 0) return symoffset; // no symbols in buckets

    // Walk the chain from max_sym until terminating 0
    uint64_t chains_off = buckets_off + nbuckets * 4;
    uint32_t idx = max_sym - symoffset;
    uint32_t last = max_sym;
    while (true) {
        uint32_t chain_val = read_val_at<uint32_t>(chains_off + idx * 4);
        ++last;
        if ((chain_val & 1) != 0) break; // end of chain
        ++idx;
    }
    return last;
}

bool ElfParser::parse_dynamic_from_phdr() {
    // Find PT_DYNAMIC segment
    const ElfProgramHeader* dyn_phdr = nullptr;
    for (const auto& ph : m_phdrs) {
        if (ph.type == PT_DYNAMIC) {
            dyn_phdr = &ph;
            break;
        }
    }
    if (!dyn_phdr) return false;

    // Parse dynamic entries
    m_dynamic.clear();
    uint64_t dyn_offset = dyn_phdr->offset;
    uint64_t dyn_end = dyn_offset + dyn_phdr->filesz;

    m_file.seekg(static_cast<std::streamoff>(dyn_offset));
    while (static_cast<uint64_t>(m_file.tellg()) < dyn_end) {
        ElfDynamicEntry entry;
        if (m_is64) {
            entry.tag = read_val<uint64_t>();
            entry.val = read_val<uint64_t>();
        } else {
            entry.tag = read_val<uint32_t>();
            entry.val = read_val<uint32_t>();
        }
        if (entry.tag == DT_NULL) break;
        m_dynamic.push_back(entry);
    }

    // Extract key pointers from dynamic entries
    uint64_t dt_strtab = 0, dt_symtab = 0, dt_strsz = 0, dt_syment = 0;
    uint64_t dt_hash = 0, dt_gnu_hash = 0;

    for (const auto& e : m_dynamic) {
        switch (e.tag) {
            case DT_STRTAB:    dt_strtab = e.val; break;
            case DT_SYMTAB:    dt_symtab = e.val; break;
            case DT_STRSZ:     dt_strsz  = e.val; break;
            case DT_SYMENT:    dt_syment = e.val; break;
            case DT_HASH:      dt_hash   = e.val; break;
            case DT_GNU_HASH:  dt_gnu_hash = e.val; break;
        }
    }

    if (dt_strtab == 0 || dt_symtab == 0) return false;
    if (dt_syment == 0) dt_syment = m_is64 ? 24 : 16;

    // Convert VA to file offsets
    uint64_t strtab_foff = va_to_offset(dt_strtab);
    uint64_t symtab_foff = va_to_offset(dt_symtab);

    // Determine symbol count
    uint32_t sym_count = 0;
    if (dt_hash != 0) {
        sym_count = get_dynsym_count_from_hash(va_to_offset(dt_hash));
    } else if (dt_gnu_hash != 0) {
        sym_count = get_dynsym_count_from_gnu_hash(va_to_offset(dt_gnu_hash), symtab_foff, dt_syment);
    }

    if (sym_count == 0) return false;

    // Parse dynamic symbols
    m_dynsyms.clear();
    m_dynsyms.reserve(sym_count);

    for (uint32_t i = 0; i < sym_count; ++i) {
        ElfSymbol sym;
        uint64_t sym_off = symtab_foff + i * dt_syment;
        m_file.seekg(static_cast<std::streamoff>(sym_off));

        if (m_is64) {
            sym.name_offset = read_val<uint32_t>();
            sym.info        = read_val<uint8_t>();
            sym.other       = read_val<uint8_t>();
            sym.shndx       = read_val<uint16_t>();
            sym.value       = read_val<uint64_t>();
            sym.size        = read_val<uint64_t>();
        } else {
            sym.name_offset = read_val<uint32_t>();
            sym.value       = read_val<uint32_t>();
            sym.size        = read_val<uint32_t>();
            sym.info        = read_val<uint8_t>();
            sym.other       = read_val<uint8_t>();
            sym.shndx       = read_val<uint16_t>();
        }

        sym.name = read_strtab_at(strtab_foff, sym.name_offset);
        m_dynsyms.push_back(sym);
    }

    return true;
}

void ElfParser::extract_strings(size_t min_length) {
    m_file.seekg(0);
    std::vector<uint8_t> data(m_filesize);
    m_file.read(reinterpret_cast<char*>(data.data()), m_filesize);

    std::string current;
    uint64_t start = 0;

    for (uint64_t i = 0; i < m_filesize; ++i) {
        if (data[i] >= 32 && data[i] <= 126) {
            if (current.empty()) start = i;
            current += static_cast<char>(data[i]);
        } else {
            if (current.size() >= min_length) {
                m_strings.emplace_back(start, current);
            }
            current.clear();
        }
    }
    if (current.size() >= min_length) {
        m_strings.emplace_back(start, current);
    }
}

void ElfParser::scan_code_functions() {
    // Build a map of ALL existing symbols (from .symtab and .dynsym) for quick lookup
    std::map<uint64_t, std::string> existing_symbols;
    for (size_t i = 0; i < m_symbols.size(); i++) {
        const auto& sym = m_symbols[i];
        if (!sym.name.empty() && sym.value > 0) {
            existing_symbols[sym.value] = sym.name;
        }
    }
    for (size_t i = 0; i < m_dynsyms.size(); i++) {
        const auto& sym = m_dynsyms[i];
        if (!sym.name.empty() && sym.value > 0) {
            if (existing_symbols.find(sym.value) == existing_symbols.end()) {
                existing_symbols[sym.value] = sym.name;
            }
        }
    }
    
    // Build a map of string addresses to string values for quick lookup
    std::map<uint64_t, std::string> string_map;
    for (const auto& pair : m_strings) {
        string_map[pair.first] = pair.second;
    }
    
    // Scan executable segments for function prologues
    for (const auto& ph : m_phdrs) {
        if (!(ph.flags & PF_X)) continue; // Not executable
        if (ph.filesz == 0) continue;
        
        // Read segment data
        std::vector<uint8_t> code(ph.filesz);
        m_file.seekg(static_cast<std::streamoff>(ph.offset));
        m_file.read(reinterpret_cast<char*>(code.data()), ph.filesz);
        
        // Look for function prologues
        // x86-64: 0x55 (push rbp) or 0x48 0x89 0xE5 (mov rbp, rsp)
        // ARM64: 0xFD 0x7B 0xBF 0xA9 (stp x29, x30, [sp, #-16]!)
        
        for (uint64_t i = 0; i < code.size() - 32; i += 16) {
            bool found = false;
            uint64_t func_va = ph.vaddr + i;
            
            // Skip if we already have a symbol at this exact address
            auto sym_it = existing_symbols.find(func_va);
            if (sym_it != existing_symbols.end()) {
                // Add existing symbol to code functions if it's a function type
                ElfSymbol sym;
                sym.name = sym_it->second;
                sym.name_offset = 0;
                sym.value = func_va;
                sym.size = 100; // Unknown size
                sym.info = 0x12; // FUNC + GLOBAL
                sym.other = 0;
                sym.shndx = 0;
                m_code_functions.push_back(sym);
                continue; // Skip to next - we already have this one
            }
            
            if (m_header.e_machine == 62) { // x86-64
                // Check for push rbp
                if (code[i] == 0x55) found = true;
                // Check for mov rbp, rsp (0x48 0x89 0xE5)
                else if (i + 3 < code.size() && code[i] == 0x48 && code[i+1] == 0x89 && code[i+2] == 0xE5) found = true;
                // Check for endbr64 (0xF3 0x0F 0x1E 0xFA)
                else if (i + 4 < code.size() && code[i] == 0xF3 && code[i+1] == 0x0F && code[i+2] == 0x1E && code[i+3] == 0xFA) found = true;
            } else if (m_header.e_machine == 183) { // ARM64
                // stp x29, x30, [sp, #-16]!
                if (i + 4 <= code.size()) {
                    uint32_t inst = *reinterpret_cast<uint32_t*>(&code[i]);
                    if ((inst & 0xFFFC1FFF) == 0xA9BF7BFD) found = true;
                }
            }
            
            if (found) {
                // Estimate function size by looking for ret or next prologue
                uint64_t func_size = 0;
                for (uint64_t j = i + 1; j < code.size(); ++j) {
                    if (m_header.e_machine == 62) {
                        // Look for ret (0xC3) or next function prologue
                        if (code[j] == 0xC3 || code[j] == 0x55 || 
                            (j + 3 < code.size() && code[j] == 0x48 && code[j+1] == 0x89 && code[j+2] == 0xE5)) {
                            func_size = j - i;
                            break;
                        }
                    }
                }
                
                // Default size if we couldn't find end
                if (func_size == 0) func_size = 100;
                if (func_size > 0x10000) func_size = 0x10000; // Cap at 64KB
                
                // Look for string references in first 128 bytes for naming
                std::string best_hint;
                for (uint64_t j = i; j < i + 128 && j < code.size() - 6; ++j) {
                    // Check for RIP-relative lea (x86-64)
                    if (code[j] == 0x48 && code[j+1] == 0x8D && j + 6 < code.size()) {
                        int32_t rel = *reinterpret_cast<int32_t*>(&code[j+3]);
                        uint64_t str_addr = func_va + (j + 7) + rel;
                        auto it = string_map.find(str_addr);
                        if (it != string_map.end() && it->second.length() > 3) {
                            if (best_hint.empty() || it->second.length() < best_hint.length()) {
                                best_hint = it->second;
                            }
                        }
                    }
                    // Check for mov from memory (loading strings)
                    else if (code[j] == 0x48 && code[j+1] == 0x8B && j + 6 < code.size()) {
                        int32_t rel = *reinterpret_cast<int32_t*>(&code[j+3]);
                        uint64_t str_addr = func_va + (j + 7) + rel;
                        auto it = string_map.find(str_addr);
                        if (it != string_map.end() && it->second.length() > 3) {
                            if (best_hint.empty() || it->second.length() < best_hint.length()) {
                                best_hint = it->second;
                            }
                        }
                    }
                }
                
                // Only add if reasonable size and has evidence of being real code
                if (func_size >= 32 && func_size <= 0x2000) {
                    // Quick check: look for string references or call instructions
                    bool has_string_ref = false;
                    bool has_call = false;
                    
                    for (uint64_t j = i; j < i + 128 && j < code.size() - 6; ++j) {
                        // Check for RIP-relative lea (string loading)
                        if (code[j] == 0x48 && code[j+1] == 0x8D && j + 6 < code.size()) {
                            int32_t rel = *reinterpret_cast<int32_t*>(&code[j+3]);
                            uint64_t str_addr = func_va + (j + 7) + rel;
                            auto it = string_map.find(str_addr);
                            if (it != string_map.end() && it->second.length() > 3) {
                                has_string_ref = true;
                            }
                        }
                        // Check for RIP-relative mov (string loading)
                        else if (code[j] == 0x48 && code[j+1] == 0x8B && j + 6 < code.size()) {
                            int32_t rel = *reinterpret_cast<int32_t*>(&code[j+3]);
                            uint64_t str_addr = func_va + (j + 7) + rel;
                            if (string_map.find(str_addr) != string_map.end()) {
                                has_string_ref = true;
                            }
                        }
                        // Check for call instructions (E8 xx xx xx xx)
                        else if (code[j] == 0xE8) {
                            has_call = true;
                        }
                    }
                    
                    // Skip functions with no evidence of being real code
                    // Require at least string references, calls, or reasonable size with ret
                    bool has_ret = false;
                    for (uint64_t j = i; j < i + func_size && j < code.size(); ++j) {
                        if (code[j] == 0xC3 || code[j] == 0xC2) { // ret or ret imm16
                            has_ret = true;
                            break;
                        }
                    }
                    
                    // Only add if there's evidence this is real code
                    if (!has_string_ref && !has_call && !has_ret) {
                        continue; // Skip this function
                    }
                    
                    // Build function name - prioritize string hints that look like function names
                    std::ostringstream hex_ss;
                    hex_ss << std::hex << std::uppercase << func_va;
                    std::string func_name;
                    
                    if (!best_hint.empty()) {
                        // Check if the string hint looks like a function name
                        // Good hints: "Player::update", "getHealth", "OnDamageTaken"
                        // Bad hints: "Error: file not found", "Initializing..."
                        bool looks_like_function = false;
                        
                        // Check for C++ style names (::)
                        if (best_hint.find("::") != std::string::npos) {
                            looks_like_function = true;
                        }
                        // Check for camelCase or PascalCase
                        else if (best_hint.length() > 3 && best_hint.length() < 40) {
                            bool has_upper = false;
                            bool has_lower = false;
                            for (char c : best_hint) {
                                if (std::isupper(c)) has_upper = true;
                                if (std::islower(c)) has_lower = true;
                            }
                            if (has_upper && has_lower) looks_like_function = true;
                        }
                        
                        // Check for common function name patterns
                        if (best_hint.find("get") == 0 || best_hint.find("set") == 0 ||
                            best_hint.find("is") == 0 || best_hint.find("has") == 0 ||
                            best_hint.find("on") == 0 || best_hint.find("On") == 0 ||
                            best_hint.find("update") != std::string::npos ||
                            best_hint.find("Update") != std::string::npos ||
                            best_hint.find("init") == 0 || best_hint.find("Init") == 0) {
                            looks_like_function = true;
                        }
                        
                        if (looks_like_function) {
                            // Sanitize hint for function name
                            std::string sanitized;
                            for (char c : best_hint) {
                                if (std::isalnum(c) || c == '_') {
                                    sanitized += c;
                                } else if (c == ' ' || c == ':' || c == '-' || c == '.') {
                                    if (!sanitized.empty() && sanitized.back() != '_')
                                        sanitized += '_';
                                }
                            }
                            // Remove trailing underscores
                            while (!sanitized.empty() && sanitized.back() == '_')
                                sanitized.pop_back();
                            
                            if (sanitized.length() > 3) {
                                func_name = sanitized;
                            } else {
                                func_name = "func_" + hex_ss.str();
                            }
                        } else {
                            // String doesn't look like a function name, use generic
                            func_name = "func_" + hex_ss.str();
                        }
                    } else {
                        func_name = "func_" + hex_ss.str();
                    }

                    ElfSymbol sym;
                    sym.name = func_name;
                    sym.name_offset = 0;
                    sym.value = func_va;
                    sym.size = func_size;
                    sym.info = 0x12; // FUNC + GLOBAL
                    sym.other = 0;
                    sym.shndx = 0;
                    m_code_functions.push_back(sym);
                }
            }
        }
    }
    
    // After scanning, try to match discovered functions with nearby symbols
    // This helps when symbols exist but weren't matched initially
    for (auto& func : m_code_functions) {
        // If function already has a good name (not func_*), skip it
        if (func.name.rfind("func_", 0) != 0) {
            continue;
        }
        
        // Look for the closest symbol within a small range
        uint64_t best_distance = 0x1000; // Max 4KB distance
        std::string best_name;
        
        for (const auto& kv : existing_symbols) {
            uint64_t addr = kv.first;
            const std::string& name = kv.second;
            if (addr > func.value && (addr - func.value) < best_distance) {
                // Only use if it looks like a function name
                if (name.find("_Z") == 0 || // Mangled C++
                    name.find("Java_") == 0 || // JNI
                    name.find("_") != std::string::npos) {
                    best_distance = addr - func.value;
                    best_name = name;
                }
            }
        }
        
        if (!best_name.empty()) {
            // Found a nearby symbol - use it with offset
            std::ostringstream oss;
            oss << best_name << "+0x" << std::hex << best_distance;
            func.name = oss.str();
        }
    }
}

void ElfParser::deobfuscate_functions() {
    // Build a map of string addresses to string values
    std::map<uint64_t, std::string> string_map;
    for (const auto& pair : m_strings) {
        string_map[pair.first] = pair.second;
    }

    // Process each code function that has a generic name
    for (auto& sym : m_code_functions) {
        // Only process functions with generic names
        bool is_generic = (sym.name.rfind("sub_", 0) == 0) ||
                          (sym.name.rfind("func_", 0) == 0) ||
                          (sym.name.rfind("VClass_", 0) == 0) ||
                          (sym.name.rfind("hidden_", 0) == 0);
        if (!is_generic) continue;

        // Find the executable segment containing this function
        for (const auto& ph : m_phdrs) {
            if (ph.type == PT_LOAD && (ph.flags & 0x1) && 
                sym.value >= ph.vaddr && sym.value < ph.vaddr + ph.filesz) {
                
                // Calculate offset within the segment
                uint64_t seg_offset = sym.value - ph.vaddr;
                uint64_t file_offset = ph.offset + seg_offset;
                
                // Read the function code (up to 512 bytes)
                uint64_t read_size = std::min(sym.size, static_cast<uint64_t>(512));
                std::vector<uint8_t> code(read_size);
                m_file.seekg(static_cast<std::streamoff>(file_offset));
                m_file.read(reinterpret_cast<char*>(code.data()), read_size);
                
                // Look for string references in the function
                std::string best_name;
                int best_score = 0;
                
                for (uint64_t j = 0; j + 7 < code.size(); ++j) {
                    uint64_t str_addr = 0;
                    bool found_ref = false;
                    
                    if (m_header.e_machine == 62 || m_header.e_machine == 3) {
                        // x86/x64: RIP-relative lea (48 8D XX XX XX XX XX XX)
                        if (code[j] == 0x48 && code[j+1] == 0x8D) {
                            int32_t rel = *reinterpret_cast<int32_t*>(&code[j+3]);
                            str_addr = sym.value + (j + 7) + rel;
                            found_ref = true;
                        }
                        // x86/x64: RIP-relative mov (48 8B XX XX XX XX XX XX)
                        else if (code[j] == 0x48 && code[j+1] == 0x8B) {
                            int32_t rel = *reinterpret_cast<int32_t*>(&code[j+3]);
                            str_addr = sym.value + (j + 7) + rel;
                            found_ref = true;
                        }
                    } else if (m_header.e_machine == 183) {
                        // ARM64: ADRP/ADD pair for address loading
                        // ADRP: 10xx xxxx xxxx xxxx xxxx xxxx xxxx 1000
                        if (j + 8 < code.size() && (code[j+3] & 0x9F) == 0x90) {
                            // Decode ADRP (simplified)
                            uint32_t instr = *reinterpret_cast<uint32_t*>(&code[j]);
                            uint64_t page_addr = (sym.value + j) & ~0xFFF;
                            int64_t imm = ((instr >> 29) & 0x3) | (((instr >> 5) & 0x3FFFF) << 2);
                            imm = (imm << 43) >> 43; // Sign extend
                            str_addr = page_addr + (imm << 12);
                            
                            // Check for following ADD instruction
                            if (j + 4 < code.size() && ((code[j+3] & 0x9F) == 0x91)) {
                                uint32_t add_instr = *reinterpret_cast<uint32_t*>(&code[j+4]);
                                uint64_t add_imm = ((add_instr >> 10) & 0xFFF) << ((add_instr >> 22) & 0x3);
                                str_addr += add_imm;
                            }
                            found_ref = true;
                        }
                        // ARM64: LDR with literal (address loading)
                        else if (j + 4 < code.size() && ((code[j+3] & 0x7F) == 0x18)) {
                            uint32_t instr = *reinterpret_cast<uint32_t*>(&code[j]);
                            int32_t imm = ((instr >> 5) & 0x3FFF) << 2;
                            imm = (imm << 18) >> 18; // Sign extend
                            str_addr = (sym.value + j) + imm;
                            found_ref = true;
                        }
                    } else if (m_header.e_machine == 40) {
                        // ARM 32-bit: LDR Rd, [PC, #offset]
                        if (j + 4 < code.size() && (code[j+3] & 0x0F) == 0x04) {
                            uint32_t instr = *reinterpret_cast<uint32_t*>(&code[j]);
                            uint32_t imm = instr & 0xFFF;
                            // PC is always word-aligned (current + 8)
                            str_addr = ((sym.value + j + 8) & ~0x3) + imm;
                            found_ref = true;
                        }
                    }
                    
                    if (!found_ref || str_addr == 0) continue;
                    
                    auto it = string_map.find(str_addr);
                    if (it != string_map.end() && it->second.length() > 3) {
                        std::string str = it->second;
                        
                        // Score based on string quality
                        int score = 0;
                        // Prefer longer strings with meaningful content
                        if (str.length() > 10) score += 10;
                        if (str.length() > 20) score += 10;
                        // Prefer strings with letters
                        int alpha_count = 0;
                        for (char c : str) {
                            if (std::isalpha(c)) alpha_count++;
                        }
                        score += (alpha_count * 100) / str.length();
                        
                        // Prefer strings that look like identifiers
                        if (str.find("::") != std::string::npos) score += 20;
                        if (str.find("(") != std::string::npos) score += 10;
                        
                        // Common game-related keywords boost score
                        std::string lower;
                        for (char c : str) lower += std::tolower(c);
                        if (lower.find("coin") != std::string::npos) score += 50;
                        if (lower.find("gold") != std::string::npos) score += 50;
                        if (lower.find("gem") != std::string::npos) score += 50;
                        if (lower.find("player") != std::string::npos) score += 40;
                        if (lower.find("game") != std::string::npos) score += 40;
                        if (lower.find("level") != std::string::npos) score += 40;
                        if (lower.find("score") != std::string::npos) score += 40;
                        if (lower.find("health") != std::string::npos) score += 40;
                        if (lower.find("damage") != std::string::npos) score += 40;
                        if (lower.find("get") != std::string::npos) score += 20;
                        if (lower.find("set") != std::string::npos) score += 20;
                        if (lower.find("init") != std::string::npos) score += 20;
                        if (lower.find("load") != std::string::npos) score += 20;
                        if (lower.find("save") != std::string::npos) score += 20;
                        
                        if (score > best_score) {
                            best_score = score;
                            // Sanitize for use as function name
                            best_name.clear();
                            for (char c : str) {
                                if (std::isalnum(c) || c == '_') {
                                    best_name += c;
                                } else if (c == ' ' || c == ':' || c == '-') {
                                    if (!best_name.empty() && best_name.back() != '_')
                                        best_name += '_';
                                }
                            }
                            // Remove trailing underscores
                            while (!best_name.empty() && best_name.back() == '_')
                                best_name.pop_back();
                        }
                    }
                }
                
                // Rename if we found a good name
                if (!best_name.empty() && best_name.length() > 3) {
                    std::ostringstream hex_ss;
                    hex_ss << "0x" << std::hex << sym.value;
                    sym.name = best_name + "_" + hex_ss.str();
                }
                
                break;
            }
        }
    }
}

void ElfParser::scan_vtables() {
    // Build a set of known function addresses (from symbols + code_functions)
    std::set<uint64_t> known_funcs;
    std::map<uint64_t, std::string> func_names;
    for (const auto& s : m_dynsyms) {
        if (s.value > 0 && (s.type_val() == 2 || s.type_val() == 0)) { // STT_FUNC or NOTYPE
            known_funcs.insert(s.value);
            if (!s.name.empty()) func_names[s.value] = s.name;
        }
    }
    for (const auto& s : m_symbols) {
        if (s.value > 0 && (s.type_val() == 2 || s.type_val() == 0)) {
            known_funcs.insert(s.value);
            if (!s.name.empty()) func_names[s.value] = s.name;
        }
    }
    for (const auto& s : m_code_functions) {
        known_funcs.insert(s.value);
        if (!s.name.empty()) func_names[s.value] = s.name;
    }

    // Build a set of known vtable addresses from symbol names
    std::map<uint64_t, std::string> known_vtable_names;
    auto collect_vtable_syms = [&](const std::vector<ElfSymbol>& syms) {
        for (const auto& sym : syms) {
            if (sym.name.empty()) continue;
            if (sym.name.find("_ZTV") == 0) {
                // Demangle: _ZTV<className> -> extract class name
                std::string cls = SearchHelper::demangle(sym.name);
                if (cls.find("vtable for ") == 0) cls = cls.substr(11);
                known_vtable_names[sym.value] = cls;
            }
        }
    };
    collect_vtable_syms(m_dynsyms);
    collect_vtable_syms(m_symbols);

    // Build string map for RTTI name resolution
    std::map<uint64_t, std::string> string_map;
    for (const auto& pair : m_strings) {
        string_map[pair.first] = pair.second;
    }

    // Find the code range (executable segment) for pointer validation
    uint64_t code_start = 0, code_end = 0;
    uint64_t code_file_start = 0, code_file_end = 0;
    for (const auto& ph : m_phdrs) {
        if (ph.type == PT_LOAD && (ph.flags & 0x1) && ph.filesz > 0) {
            if (code_start == 0 || ph.vaddr < code_start) code_start = ph.vaddr;
            uint64_t seg_end = ph.vaddr + ph.memsz;
            if (seg_end > code_end) code_end = seg_end;
            if (code_file_start == 0 || ph.offset < code_file_start) code_file_start = ph.offset;
            uint64_t file_end = ph.offset + ph.filesz;
            if (file_end > code_file_end) code_file_end = file_end;
        }
    }

    // Scan ALL non-executable PT_LOAD segments for vtables
    // Vtables live in .data.rel.ro or .rodata sections
    for (const auto& ph : m_phdrs) {
        if (ph.type != PT_LOAD || ph.filesz == 0) continue;
        // Skip executable segments - vtables are in data segments
        if (ph.flags & 0x1) continue;

        uint64_t seg_size = std::min(ph.filesz, static_cast<uint64_t>(4 * 1024 * 1024));
        std::vector<uint8_t> data(seg_size);
        m_file.seekg(static_cast<std::streamoff>(ph.offset));
        m_file.read(reinterpret_cast<char*>(data.data()), seg_size);

        uint8_t ptr_size = m_is64 ? 8 : 4;

        // Scan for vtable-like structures: sequences of code pointers
        // A vtable typically looks like:
        //   [0] = offset-to-top (0 or small negative)
        //   [1] = typeinfo pointer (points to data segment)
        //   [2..N] = virtual function pointers (point to code segment)
        for (uint64_t i = 0; i + ptr_size * 3 < data.size(); i += ptr_size) {
            auto read_ptr = [&](uint64_t off) -> uint64_t {
                if (off + ptr_size > data.size()) return 0;
                if (m_is64) {
                    return *reinterpret_cast<uint64_t*>(&data[off]);
                } else {
                    uint32_t v = *reinterpret_cast<uint32_t*>(&data[off]);
                    return static_cast<uint64_t>(v);
                }
            };

            uint64_t slot0 = read_ptr(i);      // offset-to-top
            uint64_t slot1 = read_ptr(i + ptr_size);  // typeinfo ptr

            // Heuristic: offset-to-top is usually 0 or a small negative value
            // For 64-bit, 0xFFFFFFFFFFFFFFFF is -1, for 32-bit 0xFFFFFFFF
            bool valid_offset_to_top = (slot0 == 0);
            if (m_is64) {
                // Also allow small negative values (sign extended)
                if (slot0 >= 0xFFFFFFFFFFFFFF00ULL) valid_offset_to_top = true;
            } else {
                if (slot0 >= 0xFFFFFF00ULL && slot0 <= 0xFFFFFFFFULL) valid_offset_to_top = true;
            }

            if (!valid_offset_to_top) continue;

            // Heuristic: typeinfo pointer should point to a data segment (not code)
            // and should not be null, and should not look like a small integer
            if (slot1 == 0) continue;
            if (slot1 < 0x1000) continue; // Too small to be a valid address

            // Check if typeinfo pointer is within any PT_LOAD segment (non-executable)
            bool typeinfo_valid = false;
            for (const auto& ph2 : m_phdrs) {
                if (ph2.type == PT_LOAD && slot1 >= ph2.vaddr && slot1 < ph2.vaddr + ph2.memsz) {
                    // Prefer typeinfo in non-executable segments
                    typeinfo_valid = true;
                    break;
                }
            }
            if (!typeinfo_valid) continue;

            // Now check slots 2+ for virtual function pointers
            // They should point into the code segment and be properly aligned
            int vfunc_count = 0;
            uint64_t scan_pos = i + ptr_size * 2;
            std::vector<uint64_t> vfunc_addrs;

            for (uint64_t j = scan_pos; j + ptr_size <= data.size(); j += ptr_size) {
                uint64_t ptr = read_ptr(j);

                // Check if this looks like a valid code pointer
                bool is_code_ptr = false;
                // Must be within code segment VA range
                if (ptr >= code_start && ptr < code_end) {
                    // Must be properly aligned
                    if (m_header.e_machine == 183 || m_header.e_machine == 40) {
                        if ((ptr & 0x1) == 0 || (ptr & 0x2) != 0) is_code_ptr = true;
                    } else {
                        if ((ptr & 0x3) == 0) is_code_ptr = true;
                    }
                }
                // Also check if it's a file offset pointing into code
                if (!is_code_ptr && ptr >= code_file_start && ptr < code_file_end) {
                    is_code_ptr = true;
                }
                // Also accept known function addresses
                if (known_funcs.count(ptr)) {
                    is_code_ptr = true;
                }
                // Try resolving through va_to_offset as a fallback
                if (!is_code_ptr && ptr > 0) {
                    uint64_t foff = va_to_offset(ptr);
                    if (foff > 0 && foff >= code_file_start && foff < code_file_end) {
                        is_code_ptr = true;
                    }
                }

                // Reject obviously bad pointers
                if (ptr < 0x1000) is_code_ptr = false;

                if (is_code_ptr) {
                    vfunc_count++;
                    vfunc_addrs.push_back(ptr);
                } else {
                    break;
                }
            }

            // A valid vtable should have at least 3 virtual functions
            // (most C++ classes have several virtual methods)
            // But cap at 100 to avoid false positives from GOT/PLT tables
            if (vfunc_count < 3 || vfunc_count > 100) continue;

            uint64_t vtable_va = ph.vaddr + i;

            // Try to get class name from known vtable symbols
            std::string class_name;
            auto vtit = known_vtable_names.find(vtable_va);
            if (vtit != known_vtable_names.end()) {
                class_name = vtit->second;
            }

            // Try to resolve class name from RTTI/typeinfo
            if (class_name.empty() && slot1 != 0) {
                // typeinfo structure: name pointer is at offset ptr_size*2
                // typeinfo: [vtable_ptr, name_ptr, ...]
                uint64_t ti_offset = va_to_offset(slot1);
                if (ti_offset > 0 && ti_offset + ptr_size * 2 < m_filesize) {
                    m_file.seekg(static_cast<std::streamoff>(ti_offset + ptr_size));
                    uint64_t name_ptr = 0;
                    if (m_is64) {
                        m_file.read(reinterpret_cast<char*>(&name_ptr), 8);
                    } else {
                        uint32_t np32 = 0;
                        m_file.read(reinterpret_cast<char*>(&np32), 4);
                        name_ptr = static_cast<uint64_t>(np32);
                    }
                    // name_ptr is a VA pointing to the mangled name string
                    auto sit = string_map.find(name_ptr);
                    if (sit != string_map.end()) {
                        std::string mangled = sit->second;
                        // Try to demangle _ZTS prefix (typeinfo name)
                        if (mangled.find("_ZTS") == 0) {
                            class_name = SearchHelper::demangle(mangled);
                            if (class_name.find("typeinfo-name for ") == 0)
                                class_name = class_name.substr(18);
                        } else if (mangled.length() > 2 && mangled[0] != '_') {
                            class_name = mangled;
                        } else {
                            // Try to extract from _ZTS manually
                            if (mangled.length() > 4) {
                                size_t pos = 4;
                                // Skip digits (length prefix)
                                while (pos < mangled.size() && std::isdigit(mangled[pos])) pos++;
                                class_name = mangled.substr(4, pos - 4);
                                // Actually extract the name after length prefix
                                if (pos < mangled.size()) {
                                    size_t name_start = pos;
                                    while (pos < mangled.size() && (std::isalnum(mangled[pos]) || mangled[pos] == '_')) pos++;
                                    class_name = mangled.substr(name_start, pos - name_start);
                                }
                            }
                        }
                    }
                }
            }

            // Fallback: generate class name from vtable address
            if (class_name.empty()) {
                std::ostringstream cls_ss;
                cls_ss << "VClass_" << std::hex << std::uppercase << vtable_va;
                class_name = cls_ss.str();
            }

            // Store the vtable info
            VTableInfo vti;
            vti.vtable_addr = vtable_va;
            vti.class_name = class_name;
            vti.typeinfo_addr = slot1;
            vti.func_addrs = vfunc_addrs;
            m_vtables.push_back(vti);

            // Add any new virtual functions that aren't already known
            int vfunc_idx = 0;
            for (uint64_t faddr : vfunc_addrs) {
                if (known_funcs.find(faddr) == known_funcs.end()) {
                    // New function discovered via vtable!
                    std::ostringstream fname_ss;
                    fname_ss << class_name << "_vf" << std::dec << vfunc_idx
                             << "_0x" << std::hex << std::uppercase << faddr;

                    ElfSymbol sym;
                    sym.name = fname_ss.str();
                    sym.name_offset = 0;
                    sym.value = faddr;
                    sym.size = 0x100; // Estimated
                    sym.info = 0x12; // FUNC + GLOBAL
                    sym.other = 0;
                    sym.shndx = 0;
                    m_code_functions.push_back(sym);

                    known_funcs.insert(faddr);
                    func_names[faddr] = fname_ss.str();
                }
                vfunc_idx++;
            }

            // Skip past this vtable
            i += ptr_size * (2 + vfunc_count) - ptr_size;
        }
    }
}

void ElfParser::scan_hidden_functions() {
    // Build set of already known function addresses
    std::set<uint64_t> known_funcs;
    for (const auto& sym : m_code_functions) {
        known_funcs.insert(sym.value);
    }
    for (const auto& sym : m_symbols) {
        if (sym.type_val() == 2) known_funcs.insert(sym.value); // FUNC type
    }
    for (const auto& sym : m_dynsyms) {
        if (sym.type_val() == 2) known_funcs.insert(sym.value);
    }

    // Find executable segments (skip first segment if it's the ELF header)
    struct CodeSegment {
        uint64_t vaddr_start, vaddr_end;
        uint64_t file_offset;
        uint64_t file_size;
    };
    std::vector<CodeSegment> code_segs;
    bool first_seg = true;
    for (const auto& ph : m_phdrs) {
        if (ph.type == PT_LOAD && (ph.flags & 0x1) && ph.filesz > 0) {
            // Skip the first executable segment if it's at address 0 (ELF header segment)
            if (first_seg && ph.vaddr < 0x1000) {
                first_seg = false;
                continue;
            }
            code_segs.push_back({ph.vaddr, ph.vaddr + ph.memsz, ph.offset, ph.filesz});
        }
    }
    if (code_segs.empty()) return;

    size_t hidden_found = 0;

    // Method 1: Scan for function pointers in data segments
    // Many C++ binaries have function pointer tables, callbacks, etc.
    for (const auto& ph : m_phdrs) {
        if (ph.type != PT_LOAD || ph.filesz == 0) continue;
        if (ph.flags & 0x1) continue; // Skip executable segments

        uint8_t ptr_size = m_is64 ? 8 : 4;
        uint64_t scan_size = std::min(ph.filesz, static_cast<uint64_t>(2 * 1024 * 1024));

        std::vector<uint8_t> data(scan_size);
        m_file.seekg(static_cast<std::streamoff>(ph.offset));
        m_file.read(reinterpret_cast<char*>(data.data()), scan_size);

        for (uint64_t i = 0; i + ptr_size <= data.size(); i += ptr_size) {
            uint64_t ptr = 0;
            if (m_is64) {
                ptr = *reinterpret_cast<uint64_t*>(&data[i]);
            } else {
                ptr = *reinterpret_cast<uint32_t*>(&data[i]);
            }

            // Check if pointer points to executable code
            bool in_code = false;
            for (const auto& seg : code_segs) {
                if (ptr >= seg.vaddr_start && ptr < seg.vaddr_end) {
                    in_code = true;
                    break;
                }
            }

            // Stricter filtering for function pointers
            if (in_code && known_funcs.find(ptr) == known_funcs.end()) {
                // Must be reasonably large address (not NULL, not tiny)
                if (ptr < 0x10000) continue;
                
                // Must have reasonable alignment (at least 4-byte, typically 16)
                if ((ptr & 0x3) != 0) continue;
                
                // Must be within actual code segment (not ELF headers, etc.)
                bool in_real_code = false;
                for (const auto& seg : code_segs) {
                    if (ptr >= seg.vaddr_start && ptr < seg.vaddr_end) {
                        in_real_code = true;
                        break;
                    }
                }
                if (!in_real_code) continue;
                
                // Potential hidden function found - use generic name so deobfuscate can improve it
                std::ostringstream fname;
                fname << "func_0x" << std::hex << std::uppercase << ptr;

                ElfSymbol sym;
                sym.name = fname.str();
                sym.value = ptr;
                sym.size = 0x100;
                sym.info = 0x12;
                sym.other = 0;
                sym.shndx = 0;
                m_code_functions.push_back(sym);
                known_funcs.insert(ptr);
                hidden_found++;
            }
        }
    }

    // Method 2: Scan code for indirect call/jump targets
    // x86-64: look for patterns like FF 15 (call [rip+offset]) or FF 25 (jmp [rip+offset])
    // This finds functions called through the PLT/GOT or function pointers
    for (const auto& seg : code_segs) {
        uint64_t scan_size = std::min(seg.file_size, static_cast<uint64_t>(4 * 1024 * 1024));
        std::vector<uint8_t> code(scan_size);
        m_file.seekg(static_cast<std::streamoff>(seg.file_offset));
        m_file.read(reinterpret_cast<char*>(code.data()), scan_size);

        // Scan for call/jump instructions with RIP-relative addressing
        for (uint64_t i = 0; i + 6 < code.size(); i++) {
            // x86-64: FF 15 xx xx xx xx = call [rip+offset]
            // x86-64: FF 25 xx xx xx xx = jmp [rip+offset]
            if ((code[i] == 0xFF && code[i+1] == 0x15) ||
                (code[i] == 0xFF && code[i+1] == 0x25)) {
                // 32-bit relative offset
                int32_t offset = *reinterpret_cast<int32_t*>(&code[i+2]);
                uint64_t next_insn = seg.vaddr_start + i + 6;
                uint64_t target_ptr = next_insn + offset; // Address of the pointer

                // Resolve the pointer to get the actual function address
                uint64_t foff = va_to_offset(target_ptr);
                if (foff > 0 && foff + 8 <= m_filesize) {
                    uint64_t func_addr = read_val_at<uint64_t>(foff);
                    
                    // Check if it's a valid code address we don't know
                    bool in_code = false;
                    for (const auto& cs : code_segs) {
                        if (func_addr >= cs.vaddr_start && func_addr < cs.vaddr_end) {
                            in_code = true;
                            break;
                        }
                    }

                    if (in_code && known_funcs.find(func_addr) == known_funcs.end()) {
                        // Must be reasonably large and aligned
                        if (func_addr < 0x10000) continue;
                        if ((func_addr & 0x3) != 0) continue;
                        
                        std::ostringstream fname;
                        fname << "hidden_call_0x" << std::hex << std::uppercase << func_addr;

                        ElfSymbol sym;
                        sym.name = fname.str();
                        sym.value = func_addr;
                        sym.size = 0x100;
                        sym.info = 0x12;
                        sym.other = 0;
                        sym.shndx = 0;
                        m_code_functions.push_back(sym);
                        known_funcs.insert(func_addr);
                        hidden_found++;
                    }
                }
            }
        }
    }

    // Method 3: Alignment-based scan
    // Functions are typically aligned to 4 or 16 bytes
    // Look for aligned addresses that aren't already known
    for (const auto& seg : code_segs) {
        // Scan at 16-byte alignment
        uint64_t aligned_start = (seg.vaddr_start + 15) & ~15;
        for (uint64_t addr = aligned_start; addr < seg.vaddr_end; addr += 16) {
            if (known_funcs.find(addr) != known_funcs.end()) continue;
            
            // Skip if address is too small (likely not a real function)
            if (addr < 0x10000) continue;

            uint64_t foff = va_to_offset(addr);
            if (foff == 0 || foff + 4 > m_filesize) continue;

            // Read first few bytes
            m_file.seekg(static_cast<std::streamoff>(foff));
            uint8_t bytes[4];
            m_file.read(reinterpret_cast<char*>(bytes), 4);

            // Check for common function start patterns
            bool looks_like_function = false;

            // x86-64 common prologue patterns:
            // 55 = push rbp
            // 53 = push rbx
            // 48 89 E5 = mov rbp, rsp (first byte 48, second 89, third E5)
            // 48 81 EC = sub rsp, imm32
            // 48 83 EC = sub rsp, imm8
            // 41 5x = push r12/r13/r14/r15
            if (bytes[0] == 0x55 || // push rbp
                bytes[0] == 0x53 || // push rbx
                (bytes[0] == 0x48 && bytes[1] == 0x89 && bytes[2] == 0xE5) || // mov rbp, rsp
                (bytes[0] == 0x48 && bytes[1] == 0x81 && bytes[2] == 0xEC) || // sub rsp, imm32
                (bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xEC) || // sub rsp, imm8
                (bytes[0] == 0x41 && (bytes[1] == 0x54 || bytes[1] == 0x55 || // push r12/r13
                                      bytes[1] == 0x56 || bytes[1] == 0x57))) { // push r14/r15
                looks_like_function = true;
            }

            if (looks_like_function) {
                std::ostringstream fname;
                fname << "hidden_align_0x" << std::hex << std::uppercase << addr;

                ElfSymbol sym;
                sym.name = fname.str();
                sym.value = addr;
                sym.size = 0x100;
                sym.info = 0x12;
                sym.other = 0;
                sym.shndx = 0;
                m_code_functions.push_back(sym);
                known_funcs.insert(addr);
                hidden_found++;
            }
        }
    }

    // Method 4: Gap Analysis - find spaces between known functions
    // Functions are often contiguous; gaps may indicate missed functions
    std::vector<uint64_t> sorted_funcs;
    for (const auto& sym : m_code_functions) {
        sorted_funcs.push_back(sym.value);
    }
    for (const auto& sym : m_symbols) {
        if (sym.type_val() == 2) sorted_funcs.push_back(sym.value);
    }
    std::sort(sorted_funcs.begin(), sorted_funcs.end());
    
    for (size_t i = 0; i + 1 < sorted_funcs.size(); i++) {
        uint64_t curr_end = sorted_funcs[i] + 0x100; // Assume minimum function size
        uint64_t next_start = sorted_funcs[i + 1];
        
        // If there's a reasonable gap, check for function prologue
        if (next_start > curr_end && (next_start - curr_end) < 0x500) {
            // Check addresses at 16-byte alignment within the gap
            for (uint64_t addr = (curr_end + 15) & ~15; addr < next_start; addr += 16) {
                if (known_funcs.find(addr) != known_funcs.end()) continue;
                
                uint64_t foff = va_to_offset(addr);
                if (foff == 0 || foff + 4 > m_filesize) continue;
                
                m_file.seekg(static_cast<std::streamoff>(foff));
                uint8_t bytes[4];
                m_file.read(reinterpret_cast<char*>(bytes), 4);
                
                bool is_func_start = (bytes[0] == 0x55 || bytes[0] == 0x53 ||
                    (bytes[0] == 0x48 && bytes[1] == 0x89 && bytes[2] == 0xE5) ||
                    (bytes[0] == 0x48 && bytes[1] == 0x81 && bytes[2] == 0xEC) ||
                    (bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xEC) ||
                    (bytes[0] == 0x41 && (bytes[1] >= 0x54 && bytes[1] <= 0x57)));
                
                if (is_func_start) {
                    std::ostringstream fname;
                    fname << "hidden_gap_0x" << std::hex << std::uppercase << addr;
                    
                    ElfSymbol sym;
                    sym.name = fname.str();
                    sym.value = addr;
                    sym.size = static_cast<uint64_t>(next_start - addr);
                    sym.info = 0x12;
                    sym.other = 0;
                    sym.shndx = 0;
                    m_code_functions.push_back(sym);
                    known_funcs.insert(addr);
                    hidden_found++;
                    break; // Only find first function in gap
                }
            }
        }
    }

    // Method 5: Direct Call/Jump Target Analysis
    // Scan for E8 (call rel32) and E9 (jmp rel32) instructions
    // and check if targets are valid functions we don't know
    for (const auto& seg : code_segs) {
        uint64_t scan_size = std::min(seg.file_size, static_cast<uint64_t>(4 * 1024 * 1024));
        std::vector<uint8_t> code(scan_size);
        m_file.seekg(static_cast<std::streamoff>(seg.file_offset));
        m_file.read(reinterpret_cast<char*>(code.data()), scan_size);
        
        for (uint64_t i = 0; i + 5 < code.size(); i++) {
            uint8_t opcode = code[i];
            // E8 = call rel32, E9 = jmp rel32
            if (opcode == 0xE8 || opcode == 0xE9) {
                int32_t offset = *reinterpret_cast<int32_t*>(&code[i+1]);
                uint64_t next_insn = seg.vaddr_start + i + 5;
                uint64_t target = next_insn + offset;
                
                // Check if target is in code and not known
                bool in_code = false;
                for (const auto& cs : code_segs) {
                    if (target >= cs.vaddr_start && target < cs.vaddr_end) {
                        in_code = true;
                        break;
                    }
                }
                
                if (in_code && target >= 0x10000 && (target & 0x3) == 0 &&
                    known_funcs.find(target) == known_funcs.end()) {
                    // Verify it looks like a function start
                    uint64_t toff = va_to_offset(target);
                    if (toff > 0 && toff + 4 <= m_filesize) {
                        m_file.seekg(static_cast<std::streamoff>(toff));
                        uint8_t bytes[4];
                        m_file.read(reinterpret_cast<char*>(bytes), 4);
                        
                        bool valid_start = (bytes[0] == 0x55 || bytes[0] == 0x53 ||
                            (bytes[0] == 0x48 && bytes[1] == 0x89 && bytes[2] == 0xE5) ||
                            (bytes[0] == 0x48 && bytes[1] == 0x81 && bytes[2] == 0xEC) ||
                            (bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xEC) ||
                            (bytes[0] == 0x41 && (bytes[1] >= 0x54 && bytes[1] <= 0x57)));
                        
                        if (valid_start) {
                            std::ostringstream fname;
                            fname << "hidden_" << (opcode == 0xE8 ? "call_" : "jump_")
                                  << "0x" << std::hex << std::uppercase << target;
                            
                            ElfSymbol sym;
                            sym.name = fname.str();
                            sym.value = target;
                            sym.size = 0x100;
                            sym.info = 0x12;
                            sym.other = 0;
                            sym.shndx = 0;
                            m_code_functions.push_back(sym);
                            known_funcs.insert(target);
                            hidden_found++;
                        }
                    }
                }
            }
        }
    }

    m_hidden_functions_found = hidden_found;
}
