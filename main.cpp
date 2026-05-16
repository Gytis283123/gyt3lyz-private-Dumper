#include "elf_parser.h"
#include "pe_parser.h"
#include "search_helper.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <map>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#else
#include <sys/stat.h>
#endif

// ─── Color helpers (ANSI) ───

namespace Color {
    const char* Reset   = "\033[0m";
    const char* Red     = "\033[31m";
    const char* Green   = "\033[32m";
    const char* Yellow  = "\033[33m";
    const char* Blue    = "\033[34m";
    const char* Magenta = "\033[35m";
    const char* Cyan    = "\033[36m";
    const char* Bold    = "\033[1m";
    const char* Dim     = "\033[2m";

    bool enabled = true;

    std::string wrap(const char* c, const std::string& s) {
        if (!enabled) return s;
        return std::string(c) + s + Reset;
    }

    std::string wrap2(const char* c1, const char* c2, const std::string& s) {
        if (!enabled) return s;
        return std::string(c1) + std::string(c2) + s + Reset;
    }
}

// ─── Utility ───

static std::string hex_val(uint64_t v) {
    std::ostringstream ss;
    ss << std::uppercase << std::hex << v;
    return ss.str();
}

static std::string dec_val(uint64_t v) {
    std::ostringstream ss;
    ss << std::dec << v;
    return ss.str();
}

static std::string truncate(const std::string& s, size_t max_len = 80) {
    if (s.size() <= max_len) return s;
    return s.substr(0, max_len - 3) + "...";
}

static std::string to_lower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), [](unsigned char c){ return std::tolower(c); });
    return r;
}

// ─── Progress Bar ───

class ProgressBar {
public:
    ProgressBar(const std::string& label, size_t total, size_t width = 30)
        : m_label(label), m_total(total), m_width(width), m_current(0)
    {}

    void update(size_t current) {
        m_current = current;
        draw();
    }

    void advance(size_t step = 1) {
        m_current += step;
        if (m_current > m_total) m_current = m_total;
        draw();
    }

    void finish() {
        m_current = m_total;
        draw();
        if (Color::enabled) std::cout << "\n";
        else std::cout << "\n";
    }

    void clear() const {
        std::cout << "\r" << std::string(80, ' ') << "\r" << std::flush;
    }

private:
    std::string m_label;
    size_t      m_total;
    size_t      m_width;
    size_t      m_current;

    void draw() const {
        float pct = (m_total == 0) ? 1.0f : static_cast<float>(m_current) / static_cast<float>(m_total);
        if (pct > 1.0f) pct = 1.0f;
        size_t filled = static_cast<size_t>(pct * m_width);

        std::cout << "\r  " << Color::wrap(Color::Cyan, m_label) << " [";
        for (size_t i = 0; i < m_width; ++i) {
            if (i < filled) std::cout << Color::wrap(Color::Green, "#");
            else std::cout << Color::wrap(Color::Dim, "-");
        }
        std::cout << "] " << m_current << "/" << m_total
                  << std::flush;
    }
};

// ─── Output file writer ───

class OutputWriter {
public:
    OutputWriter(const std::string& output_dir) : m_dir(output_dir) {
    #ifdef _WIN32
        _mkdir(m_dir.c_str());
    #else
        mkdir(m_dir.c_str(), 0755);
    #endif
    }

    void write(const std::string& filename, const std::string& content) {
        std::string path = m_dir + "/" + filename;
        std::ofstream f(path);
        if (f.is_open()) {
            f << content;
            f.close();
            std::cout << Color::wrap(Color::Green, "[+] Saved: " + path) << "\n";
        } else {
            std::cout << Color::wrap(Color::Red, "[!] Failed to write: " + path) << "\n";
        }
    }

    const std::string& dir() const { return m_dir; }

private:
    std::string m_dir;
};

// ─── PE/EXE Dumper Application ───

class PeDumperApp {
public:
    PeDumperApp(const std::string& filepath, const std::string& output_dir)
        : m_parser(filepath), m_output(output_dir)
    {}

    bool run() {
        {
            ProgressBar pb("Parsing PE/EXE", 6);
            pb.advance(); // 1 - DOS header
            if (!m_parser.parse()) {
                pb.clear();
                std::cout << Color::wrap(Color::Red, "[!] Failed to parse PE/EXE file") << "\n";
                return false;
            }
            pb.advance(5); // skip to end
            pb.finish();
        }

        print_banner();
        print_info();

        {
            ProgressBar pb("Dumping Lua", 1);
            dump_lua();
            pb.finish();
        }
        {
            ProgressBar pb("Dumping HPP", 1);
            dump_hpp();
            pb.finish();
        }
        {
            ProgressBar pb("Dumping CPP", 1);
            dump_cpp();
            pb.finish();
        }

        std::cout << "\n" << Color::wrap2(Color::Green, Color::Bold,
            "[+] Dump complete! Output saved to: " + m_output.dir()) << "\n";
        return true;
    }

    void interactive() {
        if (!m_parser.parse()) {
            std::cout << Color::wrap(Color::Red, "[!] Failed to parse PE/EXE file") << "\n";
            return;
        }

        print_banner();
        print_info();

        std::cout << "\n" << Color::wrap(Color::Cyan,
            "Interactive PE/EXE Dumper - type 'help' for commands") << "\n\n";

        std::string line;
        while (true) {
            std::cout << Color::wrap(Color::Green, "pe> ");
            if (!std::getline(std::cin, line)) break;

            line.erase(0, line.find_first_not_of(" \t"));
            line.erase(line.find_last_not_of(" \t") + 1);

            if (line.empty()) continue;
            if (line == "quit" || line == "exit" || line == "q") break;

            process_command(line);
        }

        std::cout << Color::wrap(Color::Yellow, "Bye!") << "\n";
    }

    // ─── Public search methods ───

    void do_search(const std::string& query) {
        if (query.empty()) {
            std::cout << Color::wrap(Color::Red, "  Usage: search <query>") << "\n";
            return;
        }
        std::string lq = to_lower(query);
        int found = 0;

        // Search exports
        for (const auto& sym : m_parser.exports()) {
            if (to_lower(sym.name).find(lq) != std::string::npos) {
                print_pe_symbol(sym);
                found++;
            }
        }
        // Search imports
        for (const auto& dll : m_parser.imports()) {
            for (const auto& fn : dll.functions) {
                if (to_lower(fn.name).find(lq) != std::string::npos) {
                    print_pe_symbol(fn);
                    found++;
                }
            }
        }
        if (found == 0) {
            std::cout << Color::wrap(Color::Yellow, "  No symbols found matching: " + query) << "\n";
        } else {
            std::cout << Color::wrap(Color::Green, "  Found " + std::to_string(found) + " symbols") << "\n";
        }
    }

    void do_list_functions() {
        const auto& funcs = m_parser.all_functions();
        std::cout << Color::wrap(Color::Green, "  Total functions: " + std::to_string(funcs.size())) << "\n\n";
        std::cout << "  " << std::setw(18) << std::left << "VA"
                  << std::setw(18) << std::left << "RVA"
                  << std::setw(10) << std::left << "Type"
                  << std::setw(8)  << std::left << "Bind"
                  << std::setw(20) << std::left << "DLL"
                  << "Name\n";
        std::cout << "  " << std::string(120, '-') << "\n";
        for (size_t i = 0; i < funcs.size() && i < 100; ++i) {
            const auto& f = funcs[i];
            std::cout << "  " << std::setw(18) << std::left << hex_val(f.va)
                      << std::setw(18) << std::left << hex_val(f.rva)
                      << std::setw(10) << std::left << f.type
                      << std::setw(8)  << std::left << f.bind
                      << std::setw(20) << std::left << truncate(f.dll_name, 20)
                      << truncate(f.name, 60) << "\n";
        }
        if (funcs.size() > 100) {
            std::cout << Color::wrap(Color::Dim, "  ... and " + std::to_string(funcs.size() - 100) + " more") << "\n";
        }
        std::cout << "\n";
    }

    void do_list_imports() {
        const auto& imports = m_parser.imports();
        std::cout << Color::wrap(Color::Green, "  Imported DLLs: " + std::to_string(imports.size())) << "\n\n";
        for (const auto& dll : imports) {
            std::cout << "  " << Color::wrap(Color::Cyan, dll.name) << " (" << dll.functions.size() << " functions)\n";
            for (size_t i = 0; i < dll.functions.size() && i < 20; ++i) {
                const auto& fn = dll.functions[i];
                std::cout << "    " << hex_val(fn.va) << "  " << truncate(fn.name, 60) << "\n";
            }
            if (dll.functions.size() > 20) {
                std::cout << "    ... and " << (dll.functions.size() - 20) << " more\n";
            }
            std::cout << "\n";
        }
    }

    void do_list_exports() {
        const auto& exports = m_parser.exports();
        std::cout << Color::wrap(Color::Green, "  Exported functions: " + std::to_string(exports.size())) << "\n\n";
        std::cout << "  " << std::setw(18) << std::left << "VA"
                  << std::setw(18) << std::left << "RVA"
                  << std::setw(8)  << std::left << "Ord"
                  << "Name\n";
        std::cout << "  " << std::string(90, '-') << "\n";
        for (size_t i = 0; i < exports.size() && i < 100; ++i) {
            const auto& exp = exports[i];
            std::cout << "  " << std::setw(18) << std::left << hex_val(exp.va)
                      << std::setw(18) << std::left << hex_val(exp.rva)
                      << std::setw(8)  << std::left << exp.ordinal
                      << truncate(exp.name, 60) << "\n";
        }
        if (exports.size() > 100) {
            std::cout << Color::wrap(Color::Dim, "  ... and " + std::to_string(exports.size() - 100) + " more") << "\n";
        }
        std::cout << "\n";
    }

    void do_string_search(const std::string& query) {
        if (query.empty()) {
            std::cout << Color::wrap(Color::Red, "  Usage: string <query>") << "\n";
            return;
        }
        std::string lq = to_lower(query);
        int found = 0;
        for (const auto& [offset, str] : m_parser.strings()) {
            if (to_lower(str).find(lq) != std::string::npos) {
                std::cout << "  " << hex_val(offset) << "  " << truncate(str, 80) << "\n";
                found++;
                if (found >= 50) break;
            }
        }
        if (found == 0) {
            std::cout << Color::wrap(Color::Yellow, "  No strings found matching: " + query) << "\n";
        }
        std::cout << "\n";
    }

private:
    PeParser    m_parser;
    OutputWriter m_output;

    void print_banner() {
        std::cout << Color::wrap2(Color::Cyan, Color::Bold,
            std::string("\n")
            + "  +===================================================+\n"
            + "  |     PE/EXE Dumper v1.0                            |\n"
            + "  |     PE Binary Analyzer for .exe/.dll Files        |\n"
            + "  +===================================================+\n");
        std::cout << "  " << Color::wrap(Color::Dim, "Coded by gyt3lyz (aka Gytis)")
                  << "\n\n";
    }

    void print_info() {
        auto& hdr = m_parser.header();
        const char* arch = "Unknown";
        switch (hdr.machine) {
            case PE_MACHINE_I386:  arch = "x86 (IA-32)"; break;
            case PE_MACHINE_AMD64: arch = "x86-64"; break;
            case PE_MACHINE_ARM64: arch = "AArch64 (ARM64)"; break;
        }

        const char* subsys = "Unknown";
        switch (hdr.subsystem) {
            case 1: subsys = "Native"; break;
            case 2: subsys = "Windows GUI"; break;
            case 3: subsys = "Windows Console"; break;
            case 9: subsys = "WinCE"; break;
        }

        auto [start, end] = m_parser.address_range();

        std::cout << "\n"
                  << Color::wrap(Color::Yellow, "  File:      ") << m_parser.filepath() << "\n"
                  << Color::wrap(Color::Yellow, "  Class:     ") << (m_parser.is_64bit() ? "64-bit (PE32+)" : "32-bit (PE32)") << "\n"
                  << Color::wrap(Color::Yellow, "  Arch:      ") << arch << "\n"
                  << Color::wrap(Color::Yellow, "  Subsystem: ") << subsys << "\n"
                  << Color::wrap(Color::Yellow, "  ImageBase: ") << hex_val(m_parser.image_base()) << "\n"
                  << Color::wrap(Color::Yellow, "  Entry:     ") << hex_val(m_parser.entry_point()) << "\n"
                  << Color::wrap(Color::Yellow, "  Range:     ") << hex_val(start) << " - " << hex_val(end) << "\n"
                  << Color::wrap(Color::Yellow, "  ImageSize: ") << hdr.image_size << " bytes ("
                  << std::fixed << std::setprecision(2) << (hdr.image_size / 1024.0 / 1024.0) << " MB)\n"
                  << Color::wrap(Color::Yellow, "  Sections:  ") << m_parser.sections().size() << "\n"
                  << Color::wrap(Color::Yellow, "  Exports:   ") << m_parser.exports().size() << "\n"
                  << Color::wrap(Color::Yellow, "  Imports:   ") << m_parser.imports().size() << " DLLs\n"
                  << Color::wrap(Color::Yellow, "  Functions: ") << m_parser.all_functions().size() << "\n"
                  << Color::wrap(Color::Yellow, "  Strings:   ") << m_parser.strings().size() << "\n\n";
    }

    void print_pe_symbol(const PeSymbol& sym) {
        std::cout << "  " << std::setw(18) << std::left << hex_val(sym.va)
                  << std::setw(10) << std::left << sym.type
                  << std::setw(8)  << std::left << sym.bind
                  << truncate(sym.name, 60) << "\n";
    }

    static std::string base_filename(const std::string& path) {
        size_t slash = path.find_last_of("/\\\\");
        std::string name = (slash != std::string::npos) ? path.substr(slash + 1) : path;
        size_t dot = name.find_last_of('.');
        if (dot != std::string::npos) name = name.substr(0, dot);
        return name;
    }

    static std::string lua_escape(const std::string& s) {
        std::string out;
        for (char c : s) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        char buf[8];
                        snprintf(buf, sizeof(buf), "\\x%02x", (unsigned char)c);
                        out += buf;
                    } else {
                        out += c;
                    }
            }
        }
        return out;
    }

public:
    // ─── Dump Lua ───

    void dump_lua() {
        auto& hdr = m_parser.header();
        std::ostringstream ss;

        const char* arch = "Unknown";
        switch (hdr.machine) {
            case PE_MACHINE_I386:  arch = "x86 (IA-32)"; break;
            case PE_MACHINE_AMD64: arch = "x86-64"; break;
            case PE_MACHINE_ARM64: arch = "AArch64 (ARM64)"; break;
        }

        ss << "-- ============================================================\n";
        ss << "-- " << base_filename(m_parser.filepath()) << "_Dump.lua\n";
        ss << "-- Auto-generated by PE/EXE Dumper v1.0\n";
        ss << "-- ============================================================\n\n";

        ss << "local M = {}\n\n";
        ss << "-- File Info\n";
        auto [range_start, range_end] = m_parser.address_range();

        ss << "M.header = {\n";
        ss << "    file       = \"" << lua_escape(m_parser.filepath()) << "\",\n";
        ss << "    class      = " << (m_parser.is_64bit() ? 64 : 32) << ",\n";
        ss << "    arch       = \"" << lua_escape(arch) << "\",\n";
        ss << "    machine    = " << hdr.machine << ",\n";
        ss << "    image_base = " << hex_val(m_parser.image_base()) << ",\n";
        ss << "    entry      = " << hex_val(m_parser.entry_point()) << ",\n";
        ss << "    range_start = " << hex_val(range_start) << ",\n";
        ss << "    range_end   = " << hex_val(range_end) << ",\n";
        ss << "    image_size = " << hdr.image_size << ",\n";
        ss << "    subsystem  = " << hdr.subsystem << ",\n";
        ss << "}\n\n";

        // ── Sections ──
        const auto& secs = m_parser.sections();
        if (!secs.empty()) {
            ss << "-- Sections (" << secs.size() << ")\n";
            ss << "M.sections = {\n";
            for (size_t i = 0; i < secs.size(); ++i) {
                const auto& s = secs[i];
                ss << "    { name = \"" << lua_escape(s.name)
                   << "\", va = " << hex_val(s.virtual_address)
                   << ", vsize = " << s.virtual_size
                   << ", raw_size = " << s.raw_size
                   << ", raw_offset = " << hex_val(s.raw_offset)
                   << ", chars = " << hex_val(s.characteristics) << " }";
                if (i + 1 < secs.size()) ss << ",";
                ss << "\n";
            }
            ss << "}\n\n";
        }

        // ── Exports ──
        const auto& exports = m_parser.exports();
        if (!exports.empty()) {
            ss << "-- ============================================================\n";
            ss << "-- Exported Functions (" << exports.size() << ")\n";
            ss << "-- ============================================================\n\n";
            ss << "M.exports = {\n";
            for (const auto& exp : exports) {
                ss << "    [" << hex_val(exp.va) << "] = {\n";
                ss << "        name    = \"" << lua_escape(exp.name) << "\",\n";
                ss << "        rva     = " << hex_val(exp.rva) << ",\n";
                ss << "        ordinal = " << exp.ordinal << ",\n";
                ss << "    },\n";
            }
            ss << "}\n\n";
        }

        // ── Imports ──
        const auto& imports = m_parser.imports();
        if (!imports.empty()) {
            ss << "-- ============================================================\n";
            ss << "-- Imported DLLs (" << imports.size() << ")\n";
            ss << "-- ============================================================\n\n";
            ss << "M.imports = {\n";
            for (const auto& dll : imports) {
                ss << "    [\"" << lua_escape(dll.name) << "\"] = {\n";
                for (const auto& fn : dll.functions) {
                    ss << "        { name = \"" << lua_escape(fn.name)
                       << "\", va = " << hex_val(fn.va)
                       << ", ordinal = " << fn.ordinal << " },\n";
                }
                ss << "    },\n";
            }
            ss << "}\n\n";
        }

        // ── All Functions ──
        const auto& funcs = m_parser.all_functions();
        if (!funcs.empty()) {
            ss << "-- ============================================================\n";
            ss << "-- All Functions (" << funcs.size() << ")\n";
            ss << "-- ============================================================\n\n";
            ss << "M.functions = {\n";
            for (const auto& f : funcs) {
                ss << "    [" << hex_val(f.va) << "] = {\n";
                ss << "        name     = \"" << lua_escape(f.name) << "\",\n";
                ss << "        rva      = " << hex_val(f.rva) << ",\n";
                ss << "        type     = \"" << lua_escape(f.type) << "\",\n";
                ss << "        bind     = \"" << lua_escape(f.bind) << "\",\n";
                ss << "        dll_name = \"" << lua_escape(f.dll_name) << "\",\n";
                ss << "        ordinal  = " << f.ordinal << ",\n";
                ss << "    },\n";
            }
            ss << "}\n\n";
        }

        // ── Strings ──
        const auto& strings = m_parser.strings();
        if (!strings.empty()) {
            ss << "-- ============================================================\n";
            ss << "-- Strings (" << strings.size() << ")\n";
            ss << "-- ============================================================\n\n";
            ss << "M.strings = {\n";
            for (size_t i = 0; i < strings.size(); ++i) {
                ss << "    [" << hex_val(strings[i].first)
                   << "] = \"" << lua_escape(strings[i].second) << "\",\n";
            }
            ss << "}\n\n";
        }

        ss << "return M\n";
        std::string lua_filename = base_filename(m_parser.filepath()) + "_Dump.lua";
        m_output.write(lua_filename, ss.str());
    }

    // ─── Dump HPP ───

    void dump_hpp() {
        std::ostringstream ss;
        std::string fname = base_filename(m_parser.filepath());
        auto [range_start, range_end] = m_parser.address_range();

        std::string guard = fname + "_PE_HPP";
        for (char& c : guard) {
            if (!std::isalnum(c)) c = '_';
            c = std::toupper(c);
        }

        ss << "// ============================================================\n";
        ss << "// " << fname << ".hpp (PE/EXE)\n";
        ss << "// Auto-generated by PE/EXE Dumper v1.0\n";
        ss << "// ============================================================\n";
        ss << "// Architecture: " << (m_parser.is_64bit() ? "x86-64" : "x86") << "\n";
        ss << "// Image Base:   " << hex_val(m_parser.image_base()) << "\n";
        ss << "// Entry Point:  " << hex_val(m_parser.entry_point()) << "\n";
        ss << "// Range:        " << hex_val(range_start) << " - " << hex_val(range_end) << "\n";
        ss << "// ============================================================\n\n";
        ss << "#ifndef " << guard << "\n";
        ss << "#define " << guard << "\n\n";
        ss << "#include <cstdint>\n\n";

        // ── Sections ──
        const auto& secs = m_parser.sections();
        ss << "// ============================================================\n";
        ss << "// Sections (" << secs.size() << ")\n";
        ss << "// ============================================================\n\n";
        for (const auto& s : secs) {
            std::string sec_name = s.name;
            for (char& c : sec_name) if (!std::isalnum(c)) c = '_';
            ss << "// " << s.name << " @ " << hex_val(s.virtual_address)
               << " size=" << hex_val(s.virtual_size) << "\n";
            ss << "constexpr uintptr_t SEC_" << sec_name << "_START = 0x"
               << std::hex << std::uppercase << s.virtual_address << std::dec << ";\n";
            ss << "constexpr uintptr_t SEC_" << sec_name << "_END   = 0x"
               << std::hex << std::uppercase << s.end_va << std::dec << ";\n\n";
        }

        // ── Export function declarations ──
        const auto& exports = m_parser.exports();
        if (!exports.empty()) {
            ss << "// ============================================================\n";
            ss << "// Exported Functions (" << exports.size() << ")\n";
            ss << "// ============================================================\n\n";
            for (const auto& exp : exports) {
                std::string safe_name = exp.name;
                for (char& c : safe_name) if (!std::isalnum(c) && c != '_') c = '_';
                ss << "// " << exp.name << " @ " << hex_val(exp.va)
                   << " (ordinal: " << exp.ordinal << ")\n";
                ss << "using ptr_" << safe_name << " = void (*)(void);  // "
                   << hex_val(exp.va) << "\n\n";
            }
        }

        // ── Import function declarations ──
        const auto& imports = m_parser.imports();
        if (!imports.empty()) {
            ss << "// ============================================================\n";
            ss << "// Imported Functions (" << imports.size() << " DLLs)\n";
            ss << "// ============================================================\n\n";
            for (const auto& dll : imports) {
                std::string dll_safe = dll.name;
                for (char& c : dll_safe) if (!std::isalnum(c) && c != '_') c = '_';
                ss << "// --- " << dll.name << " (" << dll.functions.size() << " functions) ---\n";
                for (const auto& fn : dll.functions) {
                    std::string safe_name = fn.name;
                    for (char& c : safe_name) if (!std::isalnum(c) && c != '_') c = '_';
                    ss << "// " << fn.name << " (from " << dll.name << ")\n";
                    ss << "using ptr_" << dll_safe << "_" << safe_name
                       << " = void (*)(void);  // import\n\n";
                }
            }
        }

        ss << "#endif // " << guard << "\n";
        std::string hpp_filename = fname + ".hpp";
        m_output.write(hpp_filename, ss.str());
    }

    // ─── Dump CPP ───

    void dump_cpp() {
        std::ostringstream ss;
        std::string fname = base_filename(m_parser.filepath());
        auto [range_start, range_end] = m_parser.address_range();

        std::string guard = fname + "_PE_CPP";
        for (char& c : guard) {
            if (!std::isalnum(c)) c = '_';
            c = std::toupper(c);
        }

        ss << "// ============================================================\n";
        ss << "// " << fname << ".cpp (PE/EXE)\n";
        ss << "// Auto-generated by PE/EXE Dumper v1.0\n";
        ss << "// ============================================================\n";
        ss << "// Architecture: " << (m_parser.is_64bit() ? "x86-64" : "x86") << "\n";
        ss << "// Image Base:   " << hex_val(m_parser.image_base()) << "\n";
        ss << "// Range:        " << hex_val(range_start) << " - " << hex_val(range_end) << "\n";
        ss << "// ============================================================\n\n";

        ss << "#include \"" << fname << ".hpp\"\n";
        ss << "#include <windows.h>\n";
        ss << "#include <cstdio>\n";
        ss << "#include <cstring>\n\n";

        // ── Base address constant ──
        ss << "// ============================================================\n";
        ss << "// Base Address & Module Info\n";
        ss << "// ============================================================\n\n";
        ss << "constexpr uintptr_t IMAGE_BASE = 0x" << std::hex << std::uppercase
           << m_parser.image_base() << std::dec << ";\n";
        ss << "constexpr uintptr_t RANGE_START = 0x" << std::hex << std::uppercase
           << range_start << std::dec << ";\n";
        ss << "constexpr uintptr_t RANGE_END   = 0x" << std::hex << std::uppercase
           << range_end << std::dec << ";\n\n";

        // ── Module handle ──
        ss << "static HMODULE g_module = nullptr;\n\n";
        ss << "bool load_module(const char* path) {\n";
        ss << "    g_module = LoadLibraryA(path);\n";
        ss << "    if (!g_module) {\n";
        ss << "        fprintf(stderr, \"[PE Dumper] Failed to load: %s (error: %lu)\\n\", path, GetLastError());\n";
        ss << "        return false;\n";
        ss << "    }\n";
        ss << "    return true;\n";
        ss << "}\n\n";
        ss << "void* get_proc(const char* name) {\n";
        ss << "    if (!g_module) return nullptr;\n";
        ss << "    return (void*)GetProcAddress(g_module, name);\n";
        ss << "}\n\n";
        ss << "void unload_module() {\n";
        ss << "    if (g_module) {\n";
        ss << "        FreeLibrary(g_module);\n";
        ss << "        g_module = nullptr;\n";
        ss << "    }\n";
        ss << "}\n\n";

        // ── Export function pointers ──
        const auto& exports = m_parser.exports();
        if (!exports.empty()) {
            ss << "// ============================================================\n";
            ss << "// Export Function Pointers (" << exports.size() << ")\n";
            ss << "// ============================================================\n\n";
            for (const auto& exp : exports) {
                std::string safe_name = exp.name;
                for (char& c : safe_name) if (!std::isalnum(c) && c != '_') c = '_';
                ss << "ptr_" << safe_name << " g_" << safe_name << " = nullptr;  // @"
                   << hex_val(exp.va) << "\n";
            }
            ss << "\n";

            // Resolver
            ss << "bool resolve_exports() {\n";
            ss << "    if (!g_module) return false;\n";
            ss << "    bool all_ok = true;\n\n";
            for (const auto& exp : exports) {
                std::string safe_name = exp.name;
                for (char& c : safe_name) if (!std::isalnum(c) && c != '_') c = '_';
                ss << "    g_" << safe_name << " = (ptr_" << safe_name
                   << ")GetProcAddress(g_module, \"" << exp.name << "\");\n";
                ss << "    if (!g_" << safe_name << ") {\n";
                ss << "        fprintf(stderr, \"[!] Failed to resolve: " << exp.name << "\\n\");\n";
                ss << "        all_ok = false;\n";
                ss << "    }\n\n";
            }
            ss << "    return all_ok;\n";
            ss << "}\n\n";
        }

        // ── Import function pointers ──
        const auto& imports = m_parser.imports();
        if (!imports.empty()) {
            ss << "// ============================================================\n";
            ss << "// Import Function Pointers (" << imports.size() << " DLLs)\n";
            ss << "// ============================================================\n\n";
            for (const auto& dll : imports) {
                std::string dll_safe = dll.name;
                for (char& c : dll_safe) if (!std::isalnum(c) && c != '_') c = '_';
                ss << "// --- " << dll.name << " ---\n";
                for (const auto& fn : dll.functions) {
                    std::string safe_name = fn.name;
                    for (char& c : safe_name) if (!std::isalnum(c) && c != '_') c = '_';
                    ss << "ptr_" << dll_safe << "_" << safe_name
                       << " g_imp_" << dll_safe << "_" << safe_name
                       << " = nullptr;  // import from " << dll.name << "\n";
                }
                ss << "\n";
            }

            // Import resolver
            ss << "bool resolve_imports() {\n";
            ss << "    bool all_ok = true;\n\n";
            for (const auto& dll : imports) {
                std::string dll_safe = dll.name;
                for (char& c : dll_safe) if (!std::isalnum(c) && c != '_') c = '_';
                ss << "    // " << dll.name << "\n";
                ss << "    HMODULE h_" << dll_safe << " = GetModuleHandleA(\"" << dll.name << "\");\n";
                ss << "    if (!h_" << dll_safe << ") h_" << dll_safe
                   << " = LoadLibraryA(\"" << dll.name << "\");\n";
                ss << "    if (!h_" << dll_safe << ") {\n";
                ss << "        fprintf(stderr, \"[!] Failed to load: " << dll.name << "\\n\");\n";
                ss << "        all_ok = false;\n";
                ss << "    } else {\n";
                for (const auto& fn : dll.functions) {
                    std::string safe_name = fn.name;
                    for (char& c : safe_name) if (!std::isalnum(c) && c != '_') c = '_';
                    ss << "        g_imp_" << dll_safe << "_" << safe_name
                       << " = (ptr_" << dll_safe << "_" << safe_name
                       << ")GetProcAddress(h_" << dll_safe << ", \"" << fn.name << "\");\n";
                }
                ss << "    }\n\n";
            }
            ss << "    return all_ok;\n";
            ss << "}\n\n";
        }

        // ── String references ──
        const auto& strings = m_parser.strings();
        if (!strings.empty()) {
            ss << "// ============================================================\n";
            ss << "// String References (" << strings.size() << " extracted)\n";
            ss << "// ============================================================\n\n";
            ss << "struct StringRef { uintptr_t addr; const char* str; };\n\n";
            ss << "static StringRef g_strings[] = {\n";
            size_t str_count = 0;
            for (const auto& [addr, str] : strings) {
                if (str_count >= 500) {
                    ss << "    // ... and " << (strings.size() - 500) << " more strings\n";
                    break;
                }
                std::string escaped;
                for (char c : str) {
                    if (c == '"') escaped += "\\\"";
                    else if (c == '\\') escaped += "\\\\";
                    else if (c == '\n') escaped += "\\n";
                    else if (c == '\r') escaped += "\\r";
                    else if (c == '\t') escaped += "\\t";
                    else if (static_cast<unsigned char>(c) < 0x20) {
                        char buf[8];
                        snprintf(buf, sizeof(buf), "\\x%02x", (unsigned char)c);
                        escaped += buf;
                    } else {
                        escaped += c;
                    }
                }
                ss << "    {0x" << std::hex << std::uppercase << addr << std::dec
                   << ", \"" << escaped << "\"},\n";
                str_count++;
            }
            ss << "};\n\n";
            ss << "constexpr size_t g_string_count = " << str_count << ";\n\n";
        }

        // ── Hook framework ──
        ss << "// ============================================================\n";
        ss << "// Hook Framework\n";
        ss << "// ============================================================\n\n";
        ss << "template<typename T>\n";
        ss << "struct Hook {\n";
        ss << "    T original = nullptr;\n";
        ss << "    T hooked = nullptr;\n";
        ss << "    bool active = false;\n";
        ss << "};\n\n";

        // ── Initialization ──
        ss << "// ============================================================\n";
        ss << "// Initialization\n";
        ss << "// ============================================================\n\n";
        ss << "bool initialize(const char* module_path) {\n";
        ss << "    if (!load_module(module_path)) {\n";
        ss << "        return false;\n";
        ss << "    }\n\n";
        if (!exports.empty()) {
            ss << "    if (!resolve_exports()) {\n";
            ss << "        fprintf(stderr, \"[!] Some exports failed to resolve\\n\");\n";
            ss << "    }\n\n";
        }
        if (!imports.empty()) {
            ss << "    if (!resolve_imports()) {\n";
            ss << "        fprintf(stderr, \"[!] Some imports failed to resolve\\n\");\n";
            ss << "    }\n\n";
        }
        ss << "    printf(\"[+] Module initialized: %s\\n\", module_path);\n";
        ss << "    printf(\"    ImageBase: 0x%lx\\n\", (unsigned long)IMAGE_BASE);\n";
        ss << "    printf(\"    Range: 0x%lx - 0x%lx\\n\",\n";
        ss << "           (unsigned long)RANGE_START, (unsigned long)RANGE_END);\n";
        ss << "    return true;\n";
        ss << "}\n\n";
        ss << "void cleanup() {\n";
        ss << "    unload_module();\n";
        ss << "}\n";

        std::string cpp_filename = fname + ".cpp";
        m_output.write(cpp_filename, ss.str());
    }

private:
    // ─── Interactive Commands ───

    void process_command(const std::string& line) {
        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;
        auto lcmd = to_lower(cmd);

        if (lcmd == "help" || lcmd == "?") {
            print_help();
        } else if (lcmd == "info") {
            print_info();
        } else if (lcmd == "sections") {
            print_sections_interactive();
        } else if (lcmd == "search" || lcmd == "s") {
            std::string query;
            std::getline(iss, query);
            auto pos = query.find_first_not_of(" \t");
            if (pos != std::string::npos) query = query.substr(pos); else query.clear();
            do_search(query);
        } else if (lcmd == "funcs" || lcmd == "functions") {
            do_list_functions();
        } else if (lcmd == "imports" || lcmd == "imp") {
            do_list_imports();
        } else if (lcmd == "exports" || lcmd == "exp") {
            do_list_exports();
        } else if (lcmd == "string" || lcmd == "str") {
            std::string query;
            std::getline(iss, query);
            auto pos = query.find_first_not_of(" \t");
            if (pos != std::string::npos) query = query.substr(pos); else query.clear();
            do_string_search(query);
        } else if (lcmd == "dump") {
            run();
        } else if (lcmd == "dump_lua" || lcmd == "lua") {
            dump_lua();
        } else {
            std::cout << Color::wrap(Color::Red, "  Unknown command: " + cmd) << " (type 'help')\n";
        }
    }

    void print_help() {
        std::cout << Color::wrap2(Color::Cyan, Color::Bold, "  Commands:\n")
                  << "    help / ?              Show this help\n"
                  << "    info                  Show PE header info\n"
                  << "    sections              List section headers\n"
                  << "    search <query>        Search symbols by name\n"
                  << "    funcs                 List all functions (exports+imports)\n"
                  << "    imports / imp         List imported DLLs and functions\n"
                  << "    exports / exp         List exported functions\n"
                  << "    string <query>        Search strings by content\n"
                  << "    dump                  Run full dump to output directory\n"
                  << "    dump_lua / lua        Dump as Lua table\n"
                  << "    quit / exit / q       Exit\n\n";
    }

    void print_sections_interactive() {
        const auto& secs = m_parser.sections();
        std::cout << Color::wrap2(Color::Magenta, Color::Bold,
            "  Idx  Name       VA           VSize        RawSize      Characteristics\n");
        std::cout << "  " << std::string(100, '-') << "\n";
        for (size_t i = 0; i < secs.size(); ++i) {
            const auto& s = secs[i];
            std::cout << "  " << std::setw(3) << i << "  "
                      << std::setw(10) << std::left << truncate(s.name, 10) << " "
                      << std::setw(12) << std::left << hex_val(s.virtual_address) << " "
                      << std::setw(12) << std::left << dec_val(s.virtual_size) << " "
                      << std::setw(12) << std::left << dec_val(s.raw_size) << " "
                      << hex_val(s.characteristics) << "\n";
        }
        std::cout << "\n";
    }
};

// ─── Dumper Application ───

class DumperApp {
public:
    DumperApp(const std::string& filepath, const std::string& output_dir)
        : m_parser(filepath), m_output(output_dir), m_search(m_parser)
    {}

    bool run() {
        {
            ProgressBar pb("Parsing ELF", 1);
            if (!m_parser.parse()) {
                pb.clear();
                std::cout << Color::wrap(Color::Red, "[!] Failed to parse ELF file") << "\n";
                return false;
            }
            pb.finish();
        }

        print_banner();
        print_info();

        {
            ProgressBar pb("Dumping Lua", 1);
            dump_lua();
            pb.finish();
        }
        {
            ProgressBar pb("Dumping HPP", 1);
            dump_hpp();
            pb.finish();
        }
        {
            ProgressBar pb("Dumping CPP", 1);
            dump_cpp();
            pb.finish();
        }

        std::cout << "\n" << Color::wrap2(Color::Green, Color::Bold,
            "[+] Dump complete! Output saved to: " + m_output.dir()) << "\n";
        return true;
    }

    void interactive() {
        if (!m_parser.parse()) {
            std::cout << Color::wrap(Color::Red, "[!] Failed to parse ELF file") << "\n";
            return;
        }

        print_banner();
        print_info();

        std::cout << "\n" << Color::wrap(Color::Cyan,
            "Interactive Search Helper - type 'help' for commands") << "\n\n";

        std::string line;
        while (true) {
            std::cout << Color::wrap(Color::Green, "elf> ");
            if (!std::getline(std::cin, line)) break;

            line.erase(0, line.find_first_not_of(" \t"));
            line.erase(line.find_last_not_of(" \t") + 1);

            if (line.empty()) continue;
            if (line == "quit" || line == "exit" || line == "q") break;

            process_command(line);
        }

        std::cout << Color::wrap(Color::Yellow, "Bye!") << "\n";
    }

    // ─── Public search methods (used by CLI mode) ───

    void do_search(const std::string& query) {
        if (query.empty()) {
            std::cout << Color::wrap(Color::Red, "  Usage: search <query>") << "\n";
            return;
        }
        auto results = m_search.search_symbol(query);
        if (results.empty()) {
            std::cout << Color::wrap(Color::Yellow, "  No symbols found matching: " + query) << "\n";
            return;
        }
        std::cout << Color::wrap(Color::Green, "  Found " + std::to_string(results.size()) + " symbols:") << "\n\n";
        print_results(results, 50);
    }

    void do_offset_search(const std::string& offset_str) {
        if (offset_str.empty()) {
            std::cout << Color::wrap(Color::Red, "  Usage: offset <hex_value>") << "\n";
            return;
        }
        uint64_t offset = std::stoull(offset_str, nullptr, 0);
        auto results = m_search.search_by_offset(offset);
        if (results.empty()) {
            std::cout << Color::wrap(Color::Yellow, "  No symbol found at offset " + hex_val(offset)) << "\n";
            return;
        }
        print_results(results);
    }

    void do_range_search(const std::string& lo_str, const std::string& hi_str) {
        if (lo_str.empty() || hi_str.empty()) {
            std::cout << Color::wrap(Color::Red, "  Usage: range <lo_hex> <hi_hex>") << "\n";
            return;
        }
        uint64_t lo = std::stoull(lo_str, nullptr, 0);
        uint64_t hi = std::stoull(hi_str, nullptr, 0);
        auto results = m_search.search_by_offset_range(lo, hi);
        if (results.empty()) {
            std::cout << Color::wrap(Color::Yellow, "  No symbols in range " + hex_val(lo) + " - " + hex_val(hi)) << "\n";
            return;
        }
        std::cout << Color::wrap(Color::Green, "  Found " + std::to_string(results.size()) + " symbols in range:") << "\n\n";
        print_results(results, 100);
    }

    void do_string_search(const std::string& query) {
        if (query.empty()) {
            std::cout << Color::wrap(Color::Red, "  Usage: string <query>") << "\n";
            return;
        }
        auto results = m_search.search_string(query);
        if (results.empty()) {
            std::cout << Color::wrap(Color::Yellow, "  No strings found matching: " + query) << "\n";
            return;
        }
        std::cout << Color::wrap(Color::Green, "  Found " + std::to_string(results.size()) + " strings:") << "\n\n";
        print_results(results, 30);
    }

    void do_vtable_search() {
        // Show deep-scanned vtables
        const auto& deep_vtables = m_parser.vtables();
        if (!deep_vtables.empty()) {
            std::cout << Color::wrap(Color::Green, "  Found " + std::to_string(deep_vtables.size()) + " vtables (deep scanned):") << "\n\n";
            for (const auto& vt : deep_vtables) {
                std::cout << "  " << Color::wrap(Color::Cyan, vt.class_name) 
                          << " @ " << hex_val(vt.vtable_addr) 
                          << " (" << vt.func_addrs.size() << " virtual functions)\n";
                for (size_t j = 0; j < vt.func_addrs.size() && j < 10; ++j) {
                    std::cout << "    vf" << j << " = " << hex_val(vt.func_addrs[j]) << "\n";
                }
                if (vt.func_addrs.size() > 10) {
                    std::cout << "    ... and " << (vt.func_addrs.size() - 10) << " more\n";
                }
                std::cout << "\n";
            }
        }
        // Also show symbol-based vtables
        auto vtables = m_search.find_vtables();
        if (!vtables.empty()) {
            std::cout << Color::wrap(Color::Green, "  Found " + std::to_string(vtables.size()) + " vtable symbols:") << "\n\n";
            print_results(vtables, 50);
        }
        if (deep_vtables.empty() && vtables.empty()) {
            std::cout << Color::wrap(Color::Yellow, "  No vtables found") << "\n";
        }
    }

    void do_category_search(const std::string& name) {
        auto cats = m_search.categorize_symbols();

        if (!name.empty()) {
            auto it = cats.find(name);
            if (it == cats.end()) {
                for (auto& kv : cats) {
                    if (to_lower(kv.first) == to_lower(name)) {
                        it = cats.find(kv.first);
                        break;
                    }
                }
            }
            if (it != cats.end()) {
                std::cout << Color::wrap(Color::Green, "  " + it->first + " (" + std::to_string(it->second.size()) + " symbols):") << "\n\n";
                print_results(it->second, 50);
            } else {
                std::cout << Color::wrap(Color::Yellow, "  Category not found: " + name) << "\n";
                std::cout << "  Available: ";
                for (const auto& kv : cats) std::cout << kv.first << " ";
                std::cout << "\n";
            }
        } else {
            std::cout << Color::wrap2(Color::Cyan, Color::Bold, "  Symbol Categories:\n\n");
            for (const auto& kv : cats) {
                std::cout << "    " << Color::wrap(Color::Yellow, kv.first)
                          << " (" << kv.second.size() << " symbols)\n";
            }
            std::cout << "\n  Use: category <name> to list symbols\n\n";
        }
    }

    void do_pattern_scan(const std::string& hex_pattern) {
        if (hex_pattern.empty()) {
            std::cout << Color::wrap(Color::Red, "  Usage: pattern <hex_pattern>  (e.g. 7F??45??89)") << "\n";
            return;
        }
        std::cout << Color::wrap(Color::Dim, "  Scanning...") << "\n";
        auto matches = m_search.pattern_scan(hex_pattern);
        if (matches.empty()) {
            std::cout << Color::wrap(Color::Yellow, "  No matches for pattern: " + hex_pattern) << "\n";
            return;
        }
        std::cout << Color::wrap(Color::Green, "  Found " + std::to_string(matches.size()) + " matches:") << "\n\n";
        size_t show_count = (matches.size() > 50) ? 50 : matches.size();
        for (size_t i = 0; i < show_count; ++i) {
            const auto& m = matches[i];
            std::cout << "  " << hex_val(m.offset) << "  ";
            for (uint8_t b : m.bytes) {
                std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(b) << " ";
            }
            std::cout << std::dec << "\n";
        }
        if (matches.size() > 50) {
            std::cout << Color::wrap(Color::Dim, "  ... and " + std::to_string(matches.size() - 50) + " more") << "\n";
        }
        std::cout << "\n";
    }

    void do_list_functions() {
        auto funcs = m_search.get_all_functions();
        std::cout << Color::wrap(Color::Green, "  Total functions: " + std::to_string(funcs.size())) << "\n\n";
        print_results(funcs, 50);
    }

    private:
    ElfParser    m_parser;
    OutputWriter m_output;
    SearchHelper m_search;

    void print_banner() {
        std::cout << Color::wrap2(Color::Cyan, Color::Bold,
            std::string("\n")
            + "  +===================================================+\n"
            + "  |     ELF Dumper v1.0                              |\n"
            + "  |     ELF Binary Analyzer for .so Libraries         |\n"
            + "  +===================================================+\n");
        std::cout << "  " << Color::wrap(Color::Dim, "Coded by gyt3lyz (aka Gytis)")
                  << "\n\n";
    }

    void print_info() {
        auto& hdr = m_parser.header();
        const char* arch = "Unknown";
        switch (hdr.e_machine) {
            case 3:   arch = "x86 (IA-32)"; break;
            case 40:  arch = "ARM"; break;
            case 62:  arch = "x86-64"; break;
            case 183: arch = "AArch64 (ARM64)"; break;
            case 8:   arch = "MIPS"; break;
        }

        auto [start, end] = m_parser.address_range();
        
        std::cout << "\n"
                  << Color::wrap(Color::Yellow, "  File:      ") << m_parser.filepath() << "\n"
                  << Color::wrap(Color::Yellow, "  Class:     ") << (m_parser.is_64bit() ? "64-bit" : "32-bit") << "\n"
                  << Color::wrap(Color::Yellow, "  Arch:      ") << arch << "\n"
                  << Color::wrap(Color::Yellow, "  Endian:    ") << (m_parser.is_le() ? "Little" : "Big") << "\n"
                  << Color::wrap(Color::Yellow, "  Range:     ") << hex_val(start) << " - " << hex_val(end) << "\n"
                  << Color::wrap(Color::Yellow, "  Size:      ") << m_parser.file_size() << " bytes ("
                  << std::fixed << std::setprecision(2) << (m_parser.file_size() / 1024.0 / 1024.0) << " MB)\n"
                  << Color::wrap(Color::Yellow, "  Sections:  ") << m_parser.sections().size() << "\n"
                  << Color::wrap(Color::Yellow, "  Symbols:   ") << m_parser.symbols().size() << "\n"
                  << Color::wrap(Color::Yellow, "  DynSyms:   ") << m_parser.dynamic_symbols().size() << "\n"
                  << Color::wrap(Color::Yellow, "  Strings:   ") << m_parser.strings().size() << "\n"
                  << Color::wrap(Color::Yellow, "  VTables:   ") << m_parser.vtables().size() << "\n"
                  << Color::wrap(Color::Yellow, "  Hidden:    ") << m_parser.hidden_functions_count() << " found\n\n";
    }

    // ─── Dump Methods ───

    void dump_sections() {
        std::ostringstream ss;
        ss << "Index  Name                                      Type         Address          Offset           Size\n";
        ss << std::string(110, '-') << "\n";
        const auto& secs = m_parser.sections();
        for (size_t i = 0; i < secs.size(); ++i) {
            const auto& s = secs[i];
            ss << std::setw(5) << i << "  "
               << std::setw(42) << std::left << truncate(s.name, 42) << " "
               << std::setw(12) << std::left << s.type << " "
               << std::setw(16) << std::left << hex_val(s.addr) << " "
               << std::setw(16) << std::left << hex_val(s.offset) << " "
               << std::setw(12) << std::left << dec_val(s.size) << "\n";
        }
        m_output.write("sections.txt", ss.str());
    }

    void dump_symbols() {
        dump_symbol_list("symbols.txt", m_parser.symbols(), "Static Symbols");
    }

    void dump_dynamic_symbols() {
        dump_symbol_list("dynamic_symbols.txt", m_parser.dynamic_symbols(), "Dynamic Symbols");
    }

    void dump_symbol_list(const std::string& filename, const std::vector<ElfSymbol>& syms, const std::string& title) {
        std::ostringstream ss;
        ss << title << " (count: " << syms.size() << ")\n";
        ss << std::string(120, '=') << "\n";
        ss << std::setw(18) << std::left << "Offset"
           << std::setw(10) << std::left << "Size"
           << std::setw(8)  << std::left << "Bind"
           << std::setw(10) << std::left << "Type"
           << "Name\n";
        ss << std::string(120, '-') << "\n";
        for (const auto& sym : syms) {
            if (sym.name.empty()) continue;
            ss << std::setw(18) << std::left << hex_val(sym.value)
               << std::setw(10) << std::left << dec_val(sym.size)
               << std::setw(8)  << std::left << sym.bind_name()
               << std::setw(10) << std::left << sym.type_name()
               << sym.name << "\n";
        }
        m_output.write(filename, ss.str());
    }

    void dump_vtables() {
        auto vtables = m_search.find_vtables();
        std::ostringstream ss;
        ss << "VTable Symbols (count: " << vtables.size() << ")\n";
        ss << std::string(120, '=') << "\n";
        ss << std::setw(18) << std::left << "Offset"
           << std::setw(10) << std::left << "Size"
           << std::setw(8)  << std::left << "Kind"
           << "Name\n";
        ss << std::string(120, '-') << "\n";
        for (const auto& v : vtables) {
            ss << std::setw(18) << std::left << hex_val(v.offset)
               << std::setw(10) << std::left << dec_val(v.size)
               << std::setw(8)  << std::left << v.context
               << v.name << "\n";
        }
        m_output.write("vtables.txt", ss.str());
    }

    void dump_categories() {
        auto cats = m_search.categorize_symbols();
        std::ostringstream ss;
        ss << "Categorized Symbols\n";
        ss << std::string(120, '=') << "\n\n";
        for (const auto& kv : cats) {
            ss << "-- " << kv.first << " (" << kv.second.size() << " symbols) --\n";
            ss << std::setw(18) << std::left << "Offset"
               << std::setw(10) << std::left << "Size"
               << std::setw(10) << std::left << "Type"
               << "Name\n";
            ss << std::string(100, '-') << "\n";
            for (const auto& s : kv.second) {
                ss << std::setw(18) << std::left << hex_val(s.offset)
                   << std::setw(10) << std::left << dec_val(s.size)
                   << std::setw(10) << std::left << s.type
                   << s.name << "\n";
            }
            ss << "\n";
        }
        m_output.write("categories.txt", ss.str());
    }

    void dump_strings() {
        std::ostringstream ss;
        ss << "Extracted Strings (count: " << m_parser.strings().size() << ")\n";
        ss << std::string(120, '=') << "\n";
        ss << std::setw(18) << std::left << "Offset" << "String\n";
        ss << std::string(120, '-') << "\n";
        for (const auto& p : m_parser.strings()) {
            ss << std::setw(18) << std::left << hex_val(p.first)
               << truncate(p.second, 100) << "\n";
        }
        m_output.write("strings.txt", ss.str());
    }

    void dump_offsets() {
        auto funcs = m_search.get_all_functions();
        std::ostringstream ss;
        ss << "Function Offsets (count: " << funcs.size() << ")\n";
        ss << std::string(120, '=') << "\n";
        ss << std::setw(18) << std::left << "Offset"
           << std::setw(10) << std::left << "Size"
           << std::setw(8)  << std::left << "Bind"
           << "Demangled Name\n";
        ss << std::string(120, '-') << "\n";
        for (const auto& f : funcs) {
            std::string demangled = SearchHelper::demangle(f.name);
            ss << std::setw(18) << std::left << hex_val(f.offset)
               << std::setw(10) << std::left << dec_val(f.size)
               << std::setw(8)  << std::left << f.bind
               << demangled << "\n";
        }
        m_output.write("offsets.txt", ss.str());
    }

public:
    // ─── Lua Dump ───

    static std::string lua_escape(const std::string& s) {
        std::string out;
        for (char c : s) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        char buf[8];
                        snprintf(buf, sizeof(buf), "\\x%02x", (unsigned char)c);
                        out += buf;
                    } else {
                        out += c;
                    }
            }
        }
        return out;
    }

    static std::string base_filename(const std::string& path) {
        size_t slash = path.find_last_of("/\\\\");
        std::string name = (slash != std::string::npos) ? path.substr(slash + 1) : path;
        size_t dot = name.find_last_of('.');
        if (dot != std::string::npos) name = name.substr(0, dot);
        return name;
    }

    void dump_lua() {
        auto& hdr = m_parser.header();
        std::ostringstream ss;
        
        // Determine architecture name
        const char* arch = "Unknown";
        switch (hdr.e_machine) {
            case 3:   arch = "x86 (IA-32)"; break;
            case 40:  arch = "ARM"; break;
            case 62:  arch = "x86-64"; break;
            case 183: arch = "AArch64 (ARM64)"; break;
            case 8:   arch = "MIPS"; break;
        }

        ss << "-- ============================================================\n";
        ss << "-- " << base_filename(m_parser.filepath()) << "_Dump.lua\n";
        ss << "-- Auto-generated by ELF Dumper v1.0\n";
        ss << "-- ============================================================\n\n";

        // ── Header ──
        ss << "local M = {}\n\n";
        ss << "-- File Info\n";
        auto [range_start, range_end] = m_parser.address_range();
        
        ss << "M.header = {\n";
        ss << "    file      = \"" << lua_escape(m_parser.filepath()) << "\",\n";
        ss << "    class     = " << (m_parser.is_64bit() ? 64 : 32) << ",\n";
        ss << "    endian    = \"" << (m_parser.is_le() ? "little" : "big") << "\",\n";
        ss << "    arch      = \"" << lua_escape(arch) << "\",\n";
        ss << "    machine   = " << hdr.e_machine << ",\n";
        ss << "    base      = " << hex_val(m_parser.base_address()) << ",\n";
        ss << "    range_start = " << hex_val(range_start) << ",\n";
        ss << "    range_end   = " << hex_val(range_end) << ",\n";
        ss << "    entry     = " << hex_val(hdr.e_entry) << ",\n";
        ss << "    filesize  = " << m_parser.file_size() << ",\n";
        ss << "}\n\n";

        // ── Sections ──
        const auto& secs = m_parser.sections();
        if (!secs.empty()) {
            ss << "-- Sections (" << secs.size() << ")\n";
            ss << "M.sections = {\n";
            for (size_t i = 0; i < secs.size(); ++i) {
                const auto& s = secs[i];
                ss << "    { name = \"" << lua_escape(s.name) << "\", type = " << s.type
                   << ", addr = " << hex_val(s.addr)
                   << ", offset = " << hex_val(s.offset)
                   << ", size = " << s.size << " }";
                if (i + 1 < secs.size()) ss << ",";
                ss << "\n";
            }
            ss << "}\n\n";
        }

        // ── Functions (organized by class) ──
        auto funcs = m_search.get_all_functions();
        const auto& code_funcs = m_parser.code_functions();
        if (!funcs.empty() || !code_funcs.empty()) {
            ss << "-- ============================================================\n";
            ss << "-- Functions (" << funcs.size() << " symbols + " << code_funcs.size() << " discovered)\n";
            ss << "-- ============================================================\n\n";

            // Separate discovered code functions - organized by category
            if (!code_funcs.empty()) {
                // Categorize functions by name prefix
                std::unordered_map<std::string, std::vector<const ElfSymbol*>> named_funcs;
                std::vector<const ElfSymbol*> unnamed_funcs;
                
                for (const auto& f : code_funcs) {
                    if (f.name.rfind("func_", 0) == 0) {
                        unnamed_funcs.push_back(&f);
                    } else if (f.name.find('_') != std::string::npos) {
                        // Extract category from name (e.g., "SetHealth_648000" -> "SetHealth")
                        std::string cat = f.name.substr(0, f.name.find_last_of('_'));
                        // Truncate if too long
                        if (cat.length() > 40) cat = cat.substr(0, 40);
                        named_funcs[cat].push_back(&f);
                    } else {
                        named_funcs[f.name].push_back(&f);
                    }
                }
                
                ss << "-- Functions discovered by code scanning (" << code_funcs.size() << " total)\n";
                ss << "-- Named: " << (code_funcs.size() - unnamed_funcs.size()) << ", Unnamed: " << unnamed_funcs.size() << "\n\n";
                
                ss << "M.code_functions = {\n";
                
                // First output named functions grouped by category
                std::vector<std::string> categories;
                for (const auto& kv : named_funcs) categories.push_back(kv.first);
                std::sort(categories.begin(), categories.end());
                
                for (const auto& cat : categories) {
                    const auto& funcs = named_funcs[cat];
                    ss << "    -- [" << cat << "] (" << funcs.size() << " functions)\n";
                    for (const auto* f : funcs) {
                        ss << "    [" << hex_val(f->value) << "] = {\n";
                        ss << "        name   = \"" << lua_escape(f->name) << "\",\n";
                        ss << "        size   = " << f->size << ",\n";
                        ss << "    },\n";
                    }
                    ss << "\n";
                }
                
                // Then output unnamed functions (just addresses)
                if (!unnamed_funcs.empty()) {
                    ss << "    -- [Unnamed/Generic Functions] (" << unnamed_funcs.size() << " functions)\n";
                    for (const auto* f : unnamed_funcs) {
                        ss << "    [" << hex_val(f->value) << "] = {\n";
                        ss << "        name   = \"" << lua_escape(f->name) << "\",\n";
                        ss << "        size   = " << f->size << ",\n";
                        ss << "    },\n";
                    }
                }
                
                ss << "}\n\n";
            }

            // Group functions by class from demangled name
            std::unordered_map<std::string, std::vector<std::pair<SearchResult, std::string>>> class_funcs;
            for (const auto& f : funcs) {
                std::string demangled = SearchHelper::demangle(f.name);
                // Extract class name: "ClassName::methodName"
                std::string cls = "Global";
                auto pos = demangled.find("::");
                if (pos != std::string::npos) {
                    // Walk back to find the class start (after space, return type)
                    std::string before = demangled.substr(0, pos);
                    auto last_space = before.find_last_of(" \t");
                    if (last_space != std::string::npos) {
                        cls = before.substr(last_space + 1);
                    } else {
                        cls = before;
                    }
                }
                class_funcs[cls].push_back({f, demangled});
            }

            // Flat function list with hex offsets
            ss << "M.functions = {\n";
            for (size_t i = 0; i < funcs.size(); ++i) {
                const auto& f = funcs[i];
                std::string demangled = SearchHelper::demangle(f.name);
                ss << "    [" << hex_val(f.offset) << "] = {\n";
                ss << "        name       = \"" << lua_escape(f.name) << "\",\n";
                ss << "        demangled  = \"" << lua_escape(demangled) << "\",\n";
                ss << "        offset     = " << hex_val(f.offset) << ",\n";
                ss << "        size       = " << f.size << ",\n";
                ss << "        bind       = \"" << lua_escape(f.bind) << "\",\n";
                ss << "    },\n";
            }
            ss << "}\n\n";

            // Grouped by class
            ss << "-- ============================================================\n";
            ss << "-- Functions by Class (" << class_funcs.size() << " classes)\n";
            ss << "-- ============================================================\n\n";
            ss << "M.functions_by_class = {\n";
            for (auto it = class_funcs.begin(); it != class_funcs.end(); ++it) {
                ss << "    [\"" << lua_escape(it->first) << "\"] = {\n";
                for (size_t j = 0; j < it->second.size(); ++j) {
                    const auto& pair = it->second[j];
                    ss << "        { offset = " << hex_val(pair.first.offset)
                       << ", size = " << pair.first.size
                       << ", name = \"" << lua_escape(pair.second) << "\" },\n";
                }
                ss << "    },\n";
            }
            ss << "}\n\n";
        }

        // ── Class Hierarchy in Lua ──
        if (!code_funcs.empty()) {
            ss << "-- ============================================================\n";
            ss << "-- Class Hierarchy (grouped by class names)\n";
            ss << "-- ============================================================\n\n";
            ss << "M.classes = {\n";
            
            // Group functions by class
            std::map<std::string, std::vector<const ElfSymbol*>> class_groups;
            for (const auto& f : code_funcs) {
                std::string class_name = extract_class_name(f.name);
                class_groups[class_name].push_back(&f);
            }
            
            // Sort classes by number of functions (descending)
            std::vector<std::pair<std::string, std::vector<const ElfSymbol*>>> sorted_classes;
            for (auto& kv : class_groups) {
                sorted_classes.push_back({kv.first, kv.second});
            }
            std::sort(sorted_classes.begin(), sorted_classes.end(),
                [](const auto& a, const auto& b) {
                    return a.second.size() > b.second.size();
                });
            
            for (const auto& [class_name, funcs] : sorted_classes) {
                ss << "    [\"" << lua_escape(class_name) << "\"] = {\n";
                ss << "        count = " << funcs.size() << ",\n";
                ss << "        functions = {\n";
                
                // Sort functions by offset
                std::vector<const ElfSymbol*> sorted_funcs = funcs;
                std::sort(sorted_funcs.begin(), sorted_funcs.end(),
                    [](const ElfSymbol* a, const ElfSymbol* b) {
                        return a->value < b->value;
                    });
                
                for (const auto* f : sorted_funcs) {
                    ss << "            [" << hex_val(f->value) << "] = {\n";
                    ss << "                name = \"" << lua_escape(f->name) << "\",\n";
                    ss << "                size = " << f->size << ",\n";
                    ss << "            },\n";
                }
                ss << "        },\n";
                ss << "    },\n";
            }
            ss << "}\n\n";
        }
        
        const auto& deep_vtables = m_parser.vtables();
        if (!deep_vtables.empty()) {
            ss << "-- ============================================================\n";
            ss << "-- VTables (" << deep_vtables.size() << " classes, deep scanned)\n";
            ss << "-- ============================================================\n\n";
            ss << "M.vtables = {\n";
            for (size_t i = 0; i < deep_vtables.size(); ++i) {
                const auto& vt = deep_vtables[i];
                ss << "    [" << hex_val(vt.vtable_addr) << "] = {\n";
                ss << "        class = \"" << lua_escape(vt.class_name) << "\",\n";
                ss << "        typeinfo = " << hex_val(vt.typeinfo_addr) << ",\n";
                ss << "        vfuncs = {\n";
                for (size_t j = 0; j < vt.func_addrs.size(); ++j) {
                    ss << "            [" << j << "] = " << hex_val(vt.func_addrs[j]);
                    if (j + 1 < vt.func_addrs.size()) ss << ",";
                    ss << "\n";
                }
                ss << "        },\n";
                ss << "    },\n";
            }
            ss << "}\n\n";
        }

        // ── Symbol Categories ──
        auto cats = m_search.categorize_symbols();
        if (!cats.empty()) {
            ss << "-- ============================================================\n";
            ss << "-- Symbol Categories (" << cats.size() << ")\n";
            ss << "-- ============================================================\n\n";
            ss << "M.categories = {\n";
            for (auto it = cats.begin(); it != cats.end(); ++it) {
                ss << "    -- " << it->first << " (" << it->second.size() << " symbols)\n";
                ss << "    [\"" << lua_escape(it->first) << "\"] = {\n";
                for (size_t j = 0; j < it->second.size(); ++j) {
                    const auto& s = it->second[j];
                    ss << "        { offset = " << hex_val(s.offset)
                       << ", size = " << s.size
                       << ", type = \"" << lua_escape(s.type)
                       << "\", name = \"" << lua_escape(s.name) << "\" },\n";
                }
                ss << "    },\n\n";
            }
            ss << "}\n\n";
        }

        // ── Dynamic Symbols (keyed by offset for lookup) ──
        const auto& dynsyms = m_parser.dynamic_symbols();
        if (!dynsyms.empty()) {
            ss << "-- ============================================================\n";
            ss << "-- Dynamic Symbols (" << dynsyms.size() << ")\n";
            ss << "-- ============================================================\n\n";
            ss << "M.dynamic_symbols = {\n";
            for (size_t i = 0; i < dynsyms.size(); ++i) {
                const auto& sym = dynsyms[i];
                if (sym.name.empty()) continue;
                ss << "    [" << hex_val(sym.value) << "] = {\n";
                ss << "        name  = \"" << lua_escape(sym.name) << "\",\n";
                ss << "        type  = \"" << sym.type_name() << "\",\n";
                ss << "        bind  = \"" << sym.bind_name() << "\",\n";
                ss << "        size  = " << sym.size << ",\n";
                ss << "    },\n";
            }
            ss << "}\n\n";
        }

        // ── Static Symbols ──
        const auto& syms = m_parser.symbols();
        if (!syms.empty()) {
            ss << "-- Static Symbols (" << syms.size() << ")\n";
            ss << "M.symbols = {\n";
            for (size_t i = 0; i < syms.size(); ++i) {
                const auto& sym = syms[i];
                if (sym.name.empty()) continue;
                ss << "    [" << hex_val(sym.value) << "] = {\n";
                ss << "        name  = \"" << lua_escape(sym.name) << "\",\n";
                ss << "        type  = \"" << sym.type_name() << "\",\n";
                ss << "        bind  = \"" << sym.bind_name() << "\",\n";
                ss << "        size  = " << sym.size << ",\n";
                ss << "    },\n";
            }
            ss << "}\n\n";
        }

        // ── Strings ──
        const auto& strings = m_parser.strings();
        if (!strings.empty()) {
            ss << "-- ============================================================\n";
            ss << "-- Strings (" << strings.size() << ")\n";
            ss << "-- ============================================================\n\n";
            ss << "M.strings = {\n";
            for (size_t i = 0; i < strings.size(); ++i) {
                ss << "    [" << hex_val(strings[i].first)
                   << "] = \"" << lua_escape(strings[i].second) << "\",\n";
            }
            ss << "}\n\n";
        }

        ss << "return M\n";

        std::string lua_filename = base_filename(m_parser.filepath()) + "_Dump.lua";
        m_output.write(lua_filename, ss.str());
    }

    // ─── Helper: Extract class/namespace from function name ───
    std::string extract_class_name(const std::string& func_name) {
        // Try to find class name from patterns like:
        // - ClassName::functionName
        // - Namespace::ClassName::functionName
        // - _ZN9Namespace5ClassName8funcNameEv (mangled)
        
        // First check for :: in demangled names
        size_t last_colon = func_name.rfind("::");
        if (last_colon != std::string::npos && last_colon > 0) {
            // Found ::, extract class/namespace prefix
            std::string prefix = func_name.substr(0, last_colon);
            
            // If there's another ::, take the last part (class name)
            size_t prev_colon = prefix.rfind("::");
            if (prev_colon != std::string::npos) {
                return prefix.substr(prev_colon + 2);
            }
            return prefix;
        }
        
        // Check for mangled name pattern _ZN...E
        if (func_name.find("_ZN") == 0) {
            // Parse mangled name: _ZN<len>name<len>name...E
            size_t i = 3; // skip _ZN
            std::vector<std::string> parts;
            
            while (i < func_name.size()) {
                if (func_name[i] == 'E' || func_name[i] == 'I') break; // end of name or template
                
                // Read length
                int len = 0;
                while (i < func_name.size() && std::isdigit(func_name[i])) {
                    len = len * 10 + (func_name[i] - '0');
                    i++;
                }
                
                if (len > 0 && i + len <= func_name.size()) {
                    parts.push_back(func_name.substr(i, len));
                    i += len;
                } else {
                    break;
                }
            }
            
            // Return first non-numeric part (usually the class name)
            for (const auto& part : parts) {
                if (part.length() > 1 && !std::isdigit(part[0])) {
                    return part;
                }
            }
        }
        
        // Check for VClass patterns (vtable functions)
        if (func_name.find("VClass_") == 0) {
            size_t end = func_name.find("_vf");
            if (end != std::string::npos) {
                return func_name.substr(0, end);
            }
            return "VTableClasses";
        }
        
        // Check for func_ patterns - group by hex prefix
        if (func_name.find("func_") == 0) {
            return "GenericFunctions";
        }
        
        return "Global";
    }

    void dump_hpp() {
        auto& hdr = m_parser.header();
        std::ostringstream ss;
        std::string fname = base_filename(m_parser.filepath());
        
        // Header guard
        std::string guard = fname + "_HPP";
        for (char& c : guard) {
            if (!std::isalnum(c)) c = '_';
            c = std::toupper(c);
        }
        
        ss << "// ============================================================\n";
        ss << "// " << fname << ".hpp\n";
        ss << "// Auto-generated by ELF Dumper v1.0\n";
        ss << "// ============================================================\n";
        ss << "// Architecture: " << (m_parser.is_64bit() ? "x86-64" : "x86") << "\n";
        ss << "// Base Address: " << hex_val(m_parser.base_address()) << "\n";
        ss << "// Range: " << hex_val(m_parser.address_range().first) << " - " 
           << hex_val(m_parser.address_range().second) << "\n";
        ss << "// ============================================================\n\n";
        ss << "#ifndef " << guard << "\n";
        ss << "#define " << guard << "\n\n";
        ss << "#include <cstdint>\n\n";
        
        // Address range table (0-F style)
        ss << "// ============================================================\n";
        ss << "// Address Range Table (0-F)\n";
        ss << "// ============================================================\n\n";
        
        auto [range_start, range_end] = m_parser.address_range();
        uint64_t range_size = range_end - range_start;
        
        ss << "// Memory Layout:\n";
        ss << "// Start:  " << hex_val(range_start) << "\n";
        ss << "// End:    " << hex_val(range_end) << "\n";
        ss << "// Size:   0x" << std::hex << range_size << std::dec << " bytes\n\n";
        
        // Show address ranges in 0-F blocks
        ss << "// Address Blocks:\n";
        for (int block = 0; block < 16 && range_start + (block * 0x10000) < range_end; ++block) {
            uint64_t block_start = range_start + (block * 0x10000);
            uint64_t block_end = block_start + 0xFFFF;
            if (block_end > range_end) block_end = range_end;
            ss << "//   [" << std::hex << std::uppercase << block << std::dec << "] " 
               << hex_val(block_start) << " - " << hex_val(block_end) << "\n";
        }
        ss << "\n";
        
        // Function declarations
        const auto& code_funcs = m_parser.code_functions();
        if (!code_funcs.empty()) {
            ss << "// ============================================================\n";
            ss << "// Discovered Functions (" << code_funcs.size() << ")\n";
            ss << "// ============================================================\n\n";
            
            // Group functions by first hex digit
            std::map<char, std::vector<const ElfSymbol*>> func_by_digit;
            for (const auto& f : code_funcs) {
                char digit = '0';
                uint64_t rel_addr = f.value - range_start;
                if (rel_addr > 0) {
                    digit = hex_val(rel_addr)[0];
                    if (!std::isxdigit(digit)) digit = '0';
                }
                func_by_digit[digit].push_back(&f);
            }
            
            // Output by digit 0-F
            for (int i = 0; i < 16; ++i) {
                char digit = (i < 10) ? ('0' + i) : ('A' + i - 10);
                std::map<char, std::vector<const ElfSymbol*>>::iterator it = func_by_digit.find(digit);
                if (it != func_by_digit.end() && !it->second.empty()) {
                    // Calculate block range for this digit
                    uint64_t block_base = range_start + ((uint64_t)i * 0x10000);
                    uint64_t block_limit = block_base + 0xFFFF;
                    if (block_limit > range_end) block_limit = range_end;
                    ss << "// --- Block [" << digit << "] Range: " << hex_val(block_base) 
                       << " - " << hex_val(block_limit) << " (" << it->second.size() << " functions) ---\n";
                    for (size_t idx = 0; idx < it->second.size(); ++idx) {
                        const ElfSymbol* f = it->second[idx];
                        std::string func_name = f->name;
                        uint64_t abs_addr = range_start + f->value;
                        uint64_t offset = f->value;
                        // Calculate which memory range this function falls in
                        uint64_t func_range_start = range_start + ((offset / 0x10000) * 0x10000);
                        uint64_t func_range_end = func_range_start + 0xFFFF;
                        if (func_range_end > range_end) func_range_end = range_end;
                        
                        // Check if it's a deobfuscated game function
                        bool is_game_func = (func_name.find("coin") != std::string::npos ||
                                            func_name.find("gold") != std::string::npos ||
                                            func_name.find("gem") != std::string::npos ||
                                            func_name.find("player") != std::string::npos ||
                                            func_name.find("game") != std::string::npos ||
                                            func_name.find("level") != std::string::npos ||
                                            func_name.find("score") != std::string::npos ||
                                            func_name.find("health") != std::string::npos ||
                                            func_name.find("damage") != std::string::npos ||
                                            func_name.find("get") != std::string::npos ||
                                            func_name.find("set") != std::string::npos ||
                                            func_name.find("init") != std::string::npos ||
                                            func_name.find("load") != std::string::npos ||
                                            func_name.find("save") != std::string::npos);
                        
                        if (is_game_func) {
                            ss << "// [GAME] ";
                        } else {
                            ss << "//        ";
                        }
                        ss << func_name << "  Addr: " << hex_val(abs_addr) 
                           << "  Offset: " << hex_val(offset)
                           << "  Range: " << hex_val(func_range_start) << "-" << hex_val(func_range_end);
                        if (f->size > 0) {
                            ss << "  Size: " << hex_val(f->size);
                        }
                        ss << "\n";
                        
                        // Add function pointer typedef with address
                        std::string ptr_name = "ptr_" + func_name;
                        // Sanitize
                        for (char& c : ptr_name) {
                            if (c == ':' || c == '(' || c == ')' || c == ' ' || c == '-') {
                                c = '_';
                            }
                        }
                        ss << "using " << ptr_name << " = void (*)(void*);  // " 
                           << hex_val(abs_addr) << " +" << hex_val(offset) << "\n";
                    }
                    ss << "\n";
                }
            }
        }

        // ── Class Hierarchy (grouped by class name patterns) ──
        if (!code_funcs.empty()) {
            ss << "// ============================================================\n";
            ss << "// Class Hierarchy (" << code_funcs.size() << " functions grouped)\n";
            ss << "// ============================================================\n\n";
            
            // Group functions by class
            std::map<std::string, std::vector<const ElfSymbol*>> class_groups;
            for (const auto& f : code_funcs) {
                std::string class_name = extract_class_name(f.name);
                class_groups[class_name].push_back(&f);
            }
            
            // Sort classes by number of functions (descending)
            std::vector<std::pair<std::string, std::vector<const ElfSymbol*>>> sorted_classes;
            for (auto& kv : class_groups) {
                sorted_classes.push_back({kv.first, kv.second});
            }
            std::sort(sorted_classes.begin(), sorted_classes.end(),
                [](const auto& a, const auto& b) {
                    return a.second.size() > b.second.size();
                });
            
            // Output each class
            for (const auto& [class_name, funcs] : sorted_classes) {
                ss << "// ──────────────────────────────────────────────────────────────\n";
                ss << "// class " << class_name << " (" << funcs.size() << " functions)\n";
                ss << "// ──────────────────────────────────────────────────────────────\n";
                
                // Sort functions by offset within class
                std::vector<const ElfSymbol*> sorted_funcs = funcs;
                std::sort(sorted_funcs.begin(), sorted_funcs.end(),
                    [](const ElfSymbol* a, const ElfSymbol* b) {
                        return a->value < b->value;
                    });
                
                for (const auto* f : sorted_funcs) {
                    uint64_t abs_addr = range_start + f->value;
                    uint64_t offset = f->value;
                    
                    ss << "//   " << f->name;
                    if (f->size > 0) {
                        ss << "  [size: " << hex_val(f->size) << "]";
                    }
                    ss << "\n";
                    ss << "//       Addr: " << hex_val(abs_addr) 
                       << "  Offset: " << hex_val(offset) << "\n\n";
                }
                ss << "\n";
            }
            ss << "\n";
        }
        
        // Dynamic symbols that might be game-related
        const auto& dynsyms = m_parser.dynamic_symbols();
        if (!dynsyms.empty()) {
            ss << "// ============================================================\n";
            ss << "// Dynamic Symbols (Imported/Exported)\n";
            ss << "// ============================================================\n\n";
            for (const auto& sym : dynsyms) {
                if (sym.name.empty()) continue;
                uint64_t abs_addr = range_start + sym.value;
                uint64_t offset = sym.value;
                uint64_t sym_range_start = range_start + ((offset / 0x10000) * 0x10000);
                uint64_t sym_range_end = sym_range_start + 0xFFFF;
                if (sym_range_end > range_end) sym_range_end = range_end;
                ss << "// extern \"C\" void* " << sym.name << ";  // Addr: " << hex_val(abs_addr) 
                   << "  Offset: " << hex_val(offset) 
                   << "  Range: " << hex_val(sym_range_start) << "-" << hex_val(sym_range_end) << "\n";
            }
            ss << "\n";
        }
        
        // VTables (deep scanned)
        const auto& deep_vtables = m_parser.vtables();
        if (!deep_vtables.empty()) {
            ss << "// ============================================================\n";
            ss << "// VTables (" << deep_vtables.size() << " classes, deep scanned)\n";
            ss << "// ============================================================\n\n";
            for (const auto& vt : deep_vtables) {
                ss << "// --- " << vt.class_name << " (vtable @ " << hex_val(vt.vtable_addr) 
                   << ", " << vt.func_addrs.size() << " virtual functions) ---\n";
                ss << "struct " << vt.class_name << "_vtable {\n";
                for (size_t j = 0; j < vt.func_addrs.size(); ++j) {
                    ss << "    void* vf" << j << ";  // @ " << hex_val(vt.func_addrs[j]) << "\n";
                }
                ss << "};\n\n";
            }
        }
        
        ss << "#endif // " << guard << "\n";
        
        std::string hpp_filename = fname + ".hpp";
        m_output.write(hpp_filename, ss.str());
        std::cout << Color::wrap(Color::Green, "[+] Saved: " + hpp_filename) << "\n";
    }

    void dump_cpp() {
        std::ostringstream ss;
        std::string fname = base_filename(m_parser.filepath());
        auto [range_start, range_end] = m_parser.address_range();

        // Header guard for include
        std::string guard = fname + "_CPP";
        for (char& c : guard) {
            if (!std::isalnum(c)) c = '_';
            c = std::toupper(c);
        }

        ss << "// ============================================================\n";
        ss << "// " << fname << ".cpp\n";
        ss << "// Auto-generated by ELF Dumper v1.0\n";
        ss << "// ============================================================\n";
        ss << "// Architecture: " << (m_parser.is_64bit() ? "x86-64" : "x86") << "\n";
        ss << "// Base Address: " << hex_val(m_parser.base_address()) << "\n";
        ss << "// Range: " << hex_val(range_start) << " - " << hex_val(range_end) << "\n";
        ss << "// ============================================================\n\n";

        ss << "#include \"" << fname << ".hpp\"\n";
        ss << "#include <dlfcn.h>\n";
        ss << "#include <cstdio>\n";
        ss << "#include <cstring>\n\n";

        // ── Base address constant ──
        ss << "// ============================================================\n";
        ss << "// Base Address & Library Info\n";
        ss << "// ============================================================\n\n";
        ss << "constexpr uintptr_t BASE_ADDR = 0x" << std::hex << std::uppercase
           << m_parser.base_address() << std::dec << ";\n";
        ss << "constexpr uintptr_t RANGE_START = 0x" << std::hex << std::uppercase
           << range_start << std::dec << ";\n";
        ss << "constexpr uintptr_t RANGE_END = 0x" << std::hex << std::uppercase
           << range_end << std::dec << ";\n\n";

        // ── Library loader helper ──
        ss << "// ============================================================\n";
        ss << "// Library Loader Helper\n";
        ss << "// ============================================================\n\n";
        ss << "static void* g_lib_handle = nullptr;\n\n";
        ss << "bool load_library(const char* path) {\n";
        ss << "    g_lib_handle = dlopen(path, RTLD_NOW);\n";
        ss << "    if (!g_lib_handle) {\n";
        ss << "        fprintf(stderr, \"[ELF Dumper] Failed to load: %s\\n\", dlerror());\n";
        ss << "        return false;\n";
        ss << "    }\n";
        ss << "    return true;\n";
        ss << "}\n\n";
        ss << "void* get_symbol(const char* name) {\n";
        ss << "    if (!g_lib_handle) return nullptr;\n";
        ss << "    return dlsym(g_lib_handle, name);\n";
        ss << "}\n\n";
        ss << "void unload_library() {\n";
        ss << "    if (g_lib_handle) {\n";
        ss << "        dlclose(g_lib_handle);\n";
        ss << "        g_lib_handle = nullptr;\n";
        ss << "    }\n";
        ss << "}\n\n";

        // ── Function pointer definitions ──
        const auto& code_funcs = m_parser.code_functions();
        if (!code_funcs.empty()) {
            ss << "// ============================================================\n";
            ss << "// Function Pointers (" << code_funcs.size() << " discovered)\n";
            ss << "// ============================================================\n\n";

            // Group by category (named vs unnamed)
            std::vector<const ElfSymbol*> named_funcs;
            std::vector<const ElfSymbol*> unnamed_funcs;
            for (const auto& f : code_funcs) {
                if (f.name.rfind("func_", 0) == 0) {
                    unnamed_funcs.push_back(&f);
                } else {
                    named_funcs.push_back(&f);
                }
            }

            // Named function pointers
            if (!named_funcs.empty()) {
                ss << "// --- Named Functions (" << named_funcs.size() << ") ---\n\n";
                for (const auto* f : named_funcs) {
                    std::string ptr_name = "ptr_" + f->name;
                    std::string var_name = "g_" + f->name;
                    for (char& c : ptr_name) {
                        if (c == ':' || c == '(' || c == ')' || c == ' ' || c == '-' || c == '.')
                            c = '_';
                    }
                    for (char& c : var_name) {
                        if (c == ':' || c == '(' || c == ')' || c == ' ' || c == '-' || c == '.')
                            c = '_';
                    }
                    ss << "// " << f->name << " @ " << hex_val(f->value)
                       << " (size: " << hex_val(f->size) << ")\n";
                    ss << ptr_name << " " << var_name << " = nullptr;\n\n";
                }
            }

            // Unnamed function pointers
            if (!unnamed_funcs.empty()) {
                ss << "// --- Unnamed Functions (" << unnamed_funcs.size() << ") ---\n\n";
                for (const auto* f : unnamed_funcs) {
                    std::string ptr_name = "ptr_" + f->name;
                    std::string var_name = "g_" + f->name;
                    for (char& c : ptr_name) {
                        if (c == ':' || c == '(' || c == ')' || c == ' ' || c == '-' || c == '.')
                            c = '_';
                    }
                    for (char& c : var_name) {
                        if (c == ':' || c == '(' || c == ')' || c == ' ' || c == '-' || c == '.')
                            c = '_';
                    }
                    ss << ptr_name << " " << var_name << " = nullptr;  // @ "
                       << hex_val(f->value) << "\n";
                }
                ss << "\n";
            }

            // ── Function resolver ──
            ss << "// ============================================================\n";
            ss << "// Function Resolver\n";
            ss << "// ============================================================\n\n";
            ss << "bool resolve_functions() {\n";
            ss << "    if (!g_lib_handle) return false;\n\n";
            ss << "    bool all_ok = true;\n\n";

            // Resolve named functions
            if (!named_funcs.empty()) {
                ss << "    // Named functions\n";
                for (const auto* f : named_funcs) {
                    std::string var_name = "g_" + f->name;
                    for (char& c : var_name) {
                        if (c == ':' || c == '(' || c == ')' || c == ' ' || c == '-' || c == '.')
                            c = '_';
                    }
                    std::string ptr_name = "ptr_" + f->name;
                    for (char& c : ptr_name) {
                        if (c == ':' || c == '(' || c == ')' || c == ' ' || c == '-' || c == '.')
                            c = '_';
                    }
                    ss << "    " << var_name << " = (" << ptr_name << ")dlsym(g_lib_handle, \""
                       << f->name << "\");\n";
                    ss << "    if (!" << var_name << ") {\n";
                    ss << "        fprintf(stderr, \"[!] Failed to resolve: " << f->name << "\\n\");\n";
                    ss << "        all_ok = false;\n";
                    ss << "    }\n\n";
                }
            }
            ss << "    return all_ok;\n";
            ss << "}\n\n";
        }

        // ── Dynamic symbol wrappers ──
        const auto& dynsyms = m_parser.dynamic_symbols();
        if (!dynsyms.empty()) {
            ss << "// ============================================================\n";
            ss << "// Dynamic Symbol Wrappers (" << dynsyms.size() << ")\n";
            ss << "// ============================================================\n\n";

            // Only output FUNC-type symbols
            int func_count = 0;
            for (const auto& sym : dynsyms) {
                if (sym.name.empty() || sym.type_val() != 2) continue; // STT_FUNC = 2
                func_count++;
                std::string safe_name = sym.name;
                for (char& c : safe_name) {
                    if (!std::isalnum(c) && c != '_') c = '_';
                }
                ss << "// " << sym.name << " @ " << hex_val(sym.value) << "\n";
                ss << "static void* (*g_dyn_" << safe_name << ")() = nullptr;\n\n";
            }
            if (func_count == 0) {
                ss << "// No FUNC-type dynamic symbols found\n\n";
            }
        }

        // ── VTable definitions ──
        const auto& deep_vtables = m_parser.vtables();
        if (!deep_vtables.empty()) {
            ss << "// ============================================================\n";
            ss << "// VTable Instances (" << deep_vtables.size() << " classes)\n";
            ss << "// ============================================================\n\n";
            for (const auto& vt : deep_vtables) {
                ss << "// " << vt.class_name << " vtable @ " << hex_val(vt.vtable_addr) << "\n";
                ss << vt.class_name << "_vtable g_" << vt.class_name << "_vtable = {};\n\n";
            }

            // VTable resolver
            ss << "bool resolve_vtables() {\n";
            ss << "    if (!g_lib_handle) return false;\n\n";
            for (const auto& vt : deep_vtables) {
                ss << "    // Resolve " << vt.class_name << " vtable\n";
                for (size_t j = 0; j < vt.func_addrs.size(); ++j) {
                    ss << "    g_" << vt.class_name << "_vtable.vf" << j
                       << " = dlsym(g_lib_handle, reinterpret_cast<const char*>("
                       << "0x" << std::hex << std::uppercase << vt.func_addrs[j] << std::dec
                       << "));  // offset from base\n";
                }
                ss << "\n";
            }
            ss << "    return true;\n";
            ss << "}\n\n";
        }

        // ── String references ──
        const auto& strings = m_parser.strings();
        if (!strings.empty()) {
            ss << "// ============================================================\n";
            ss << "// String References (" << strings.size() << " extracted)\n";
            ss << "// ============================================================\n\n";
            ss << "struct StringRef { uintptr_t addr; const char* str; };\n\n";
            ss << "static StringRef g_strings[] = {\n";
            size_t str_count = 0;
            for (const auto& [addr, str] : strings) {
                if (str_count >= 500) {
                    ss << "    // ... and " << (strings.size() - 500) << " more strings\n";
                    break;
                }
                // Escape the string for C++
                std::string escaped;
                for (char c : str) {
                    if (c == '"') escaped += "\\\"";
                    else if (c == '\\') escaped += "\\\\";
                    else if (c == '\n') escaped += "\\n";
                    else if (c == '\r') escaped += "\\r";
                    else if (c == '\t') escaped += "\\t";
                    else if (static_cast<unsigned char>(c) < 0x20) {
                        char buf[8];
                        snprintf(buf, sizeof(buf), "\\x%02x", (unsigned char)c);
                        escaped += buf;
                    } else {
                        escaped += c;
                    }
                }
                ss << "    {0x" << std::hex << std::uppercase << addr << std::dec
                   << ", \"" << escaped << "\"},\n";
                str_count++;
            }
            ss << "};\n\n";
            ss << "constexpr size_t g_string_count = " << str_count << ";\n\n";
        }

        // ── Hook framework ──
        ss << "// ============================================================\n";
        ss << "// Hook Framework\n";
        ss << "// ============================================================\n\n";
        ss << "template<typename T>\n";
        ss << "struct Hook {\n";
        ss << "    T original = nullptr;\n";
        ss << "    T hooked = nullptr;\n";
        ss << "    bool active = false;\n";
        ss << "};\n\n";
        ss << "// Example hook usage:\n";
        ss << "//  Hook<ptr_func_name> hook_funcName;\n";
        ss << "//  void hooked_funcName(void* self) {\n";
        ss << "//      // your code here\n";
        ss << "//      hook_funcName.original(self);  // call original\n";
        ss << "//  }\n\n";

        // ── Initialization function ──
        ss << "// ============================================================\n";
        ss << "// Initialization\n";
        ss << "// ============================================================\n\n";
        ss << "bool initialize(const char* lib_path) {\n";
        ss << "    if (!load_library(lib_path)) {\n";
        ss << "        return false;\n";
        ss << "    }\n\n";
        if (!code_funcs.empty()) {
            ss << "    if (!resolve_functions()) {\n";
            ss << "        fprintf(stderr, \"[!] Some functions failed to resolve\\n\");\n";
            ss << "    }\n\n";
        }
        if (!deep_vtables.empty()) {
            ss << "    if (!resolve_vtables()) {\n";
            ss << "        fprintf(stderr, \"[!] Some vtables failed to resolve\\n\");\n";
            ss << "    }\n\n";
        }
        ss << "    printf(\"[+] Library initialized: %s\\n\", lib_path);\n";
        ss << "    printf(\"    Base: 0x%lx\\n\", (unsigned long)BASE_ADDR);\n";
        ss << "    printf(\"    Range: 0x%lx - 0x%lx\\n\",\n";
        ss << "           (unsigned long)RANGE_START, (unsigned long)RANGE_END);\n";
        ss << "    return true;\n";
        ss << "}\n\n";

        // ── Cleanup ──
        ss << "void cleanup() {\n";
        ss << "    unload_library();\n";
        ss << "}\n";

        std::string cpp_filename = fname + ".cpp";
        m_output.write(cpp_filename, ss.str());
        std::cout << Color::wrap(Color::Green, "[+] Saved: " + cpp_filename) << "\n";
    }

    // ─── Interactive Commands ───

    void process_command(const std::string& line) {
        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;
        auto lcmd = to_lower(cmd);

        if (lcmd == "help" || lcmd == "?") {
            print_help();
        } else if (lcmd == "info") {
            print_info();
        } else if (lcmd == "sections") {
            print_sections_interactive();
        } else if (lcmd == "search" || lcmd == "s") {
            std::string query;
            std::getline(iss, query);
            auto pos = query.find_first_not_of(" \t");
            if (pos != std::string::npos) query = query.substr(pos); else query.clear();
            do_search(query);
        } else if (lcmd == "offset" || lcmd == "o") {
            std::string offset_str;
            iss >> offset_str;
            do_offset_search(offset_str);
        } else if (lcmd == "range" || lcmd == "r") {
            std::string lo_str, hi_str;
            iss >> lo_str >> hi_str;
            do_range_search(lo_str, hi_str);
        } else if (lcmd == "string" || lcmd == "str") {
            std::string query;
            std::getline(iss, query);
            auto pos = query.find_first_not_of(" \t");
            if (pos != std::string::npos) query = query.substr(pos); else query.clear();
            do_string_search(query);
        } else if (lcmd == "vtable" || lcmd == "vt") {
            do_vtable_search();
        } else if (lcmd == "category" || lcmd == "cat") {
            std::string name;
            iss >> name;
            do_category_search(name);
        } else if (lcmd == "pattern" || lcmd == "p") {
            std::string pat;
            iss >> pat;
            do_pattern_scan(pat);
        } else if (lcmd == "demangle" || lcmd == "dm") {
            std::string name;
            iss >> name;
            std::cout << "  " << SearchHelper::demangle(name) << "\n";
        } else if (lcmd == "dump") {
            run();
        } else if (lcmd == "dump_lua" || lcmd == "lua") {
            dump_lua();
        } else if (lcmd == "funcs") {
            do_list_functions();
        } else {
            std::cout << Color::wrap(Color::Red, "  Unknown command: " + cmd) << " (type 'help')\n";
        }
    }

    void print_help() {
        std::cout << Color::wrap2(Color::Cyan, Color::Bold, "  Commands:\n")
                  << "    help / ?              Show this help\n"
                  << "    info                  Show ELF header info\n"
                  << "    sections              List section headers\n"
                  << "    search <query>        Search symbols by name (substring)\n"
                  << "    offset <hex>          Search symbol at offset (e.g. offset 0x1234)\n"
                  << "    range <lo> <hi>       Search symbols in offset range\n"
                  << "    string <query>        Search strings by content\n"
                  << "    vtable                List all vtable symbols\n"
                  << "    category [name]       List Cocos2d-x categories or filter by name\n"
                  << "    pattern <hex>         Pattern scan (e.g. pattern 7F??45??89)\n"
                  << "    demangle <symbol>     Demangle a C++ symbol name\n"
                  << "    funcs                 List all function symbols\n"
                  << "    dump                  Run full dump to output directory\n"
                  << "    dump_lua / lua        Dump as Lua table to <FileName>_Dump.lua\n"
                  << "    quit / exit / q       Exit\n\n";
    }

    void print_sections_interactive() {
        const auto& secs = m_parser.sections();
        std::cout << Color::wrap2(Color::Magenta, Color::Bold,
            "  Idx  Name                                      Address          Offset           Size\n");
        std::cout << "  " << std::string(108, '-') << "\n";
        for (size_t i = 0; i < secs.size(); ++i) {
            const auto& s = secs[i];
            std::cout << "  " << std::setw(3) << i << "  "
                      << std::setw(42) << std::left << truncate(s.name, 42) << " "
                      << std::setw(16) << std::left << hex_val(s.addr) << " "
                      << std::setw(16) << std::left << hex_val(s.offset) << " "
                      << dec_val(s.size) << "\n";
        }
        std::cout << "\n";
    }

    void print_results(const std::vector<SearchResult>& results, size_t limit = 20) {
        std::cout << "  " << std::setw(18) << std::left << "Offset"
                  << std::setw(10) << std::left << "Size"
                  << std::setw(10) << std::left << "Type"
                  << std::setw(8)  << std::left << "Bind"
                  << "Name\n";
        std::cout << "  " << std::string(100, '-') << "\n";

        size_t shown = (results.size() < limit) ? results.size() : limit;
        for (size_t i = 0; i < shown; ++i) {
            const auto& r = results[i];
            std::cout << "  " << std::setw(18) << std::left << hex_val(r.offset)
                      << std::setw(10) << std::left << dec_val(r.size)
                      << std::setw(10) << std::left << r.type
                      << std::setw(8)  << std::left << r.bind
                      << truncate(r.name, 60) << "\n";
        }

        if (results.size() > limit) {
            std::cout << Color::wrap(Color::Dim, "  ... and " + std::to_string(results.size() - limit) + " more") << "\n";
        }
        std::cout << "\n";
    }
};

// ─── Main ───

// ─── Detect file type by magic bytes ───

enum class FileType { ELF, PE, Unknown };

static FileType detect_file_type(const std::string& filepath) {
    std::ifstream f(filepath, std::ios::binary);
    if (!f.is_open()) return FileType::Unknown;

    uint8_t magic[2] = {};
    f.read(reinterpret_cast<char*>(magic), 2);
    if (magic[0] == 0x7F && magic[1] == 'E') return FileType::ELF;  // ELF: 7F 45 4C 46
    if (magic[0] == 'M' && magic[1] == 'Z')  return FileType::PE;   // PE/DOS: 4D 5A
    return FileType::Unknown;
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hOut, &mode);
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#endif

    if (argc < 2) {
        std::cout << Color::wrap2(Color::Cyan, Color::Bold,
            std::string("Binary Dumper v1.0 (ELF + PE/EXE)\n\n")
            + "Usage:\n"
            + "  elf_dumper <binary_file>                 Interactive mode (auto-detect)\n"
            + "  elf_dumper <elf_file> -o <output_dir>    Full dump mode\n"
            + "  elf_dumper <elf_file> -s <query>         Search symbol\n"
            + "  elf_dumper <elf_file> --offset <hex>     Search by offset\n"
            + "  elf_dumper <elf_file> --string <query>   Search strings\n"
            + "  elf_dumper <elf_file> --pattern <hex>    Pattern scan\n"
            + "  elf_dumper <elf_file> --vtable           List vtables\n"
            + "  elf_dumper <elf_file> --categories       List symbol categories\n"
            + "  elf_dumper <elf_file> --funcs            List all functions\n"
            + "  elf_dumper <elf_file> --lua              Dump as Lua table\n"
            + "\n"
            + "PE/EXE mode (--exe or auto-detected from MZ header):\n"
            + "  elf_dumper <exe_file> --exe              Interactive PE mode\n"
            + "  elf_dumper <exe_file> --exe -o <dir>     Full PE dump\n"
            + "  elf_dumper <exe_file> --exe -s <query>   Search PE symbols\n"
            + "  elf_dumper <exe_file> --exe --funcs      List all PE functions\n"
            + "  elf_dumper <exe_file> --exe --imports    List imported DLLs\n"
            + "  elf_dumper <exe_file> --exe --exports    List exported functions\n"
            + "  elf_dumper <exe_file> --exe --string <q> Search PE strings\n"
            + "  elf_dumper <exe_file> --exe --lua        Dump PE as Lua table\n");
        return 1;
    }

    std::string filepath = argv[1];
    std::string output_dir;
    std::string search_query;
    std::string offset_query;
    std::string string_query;
    std::string pattern_query;
    bool do_dump = false;
    bool do_lua = false;
    bool do_vtable = false;
    bool do_categories = false;
    bool do_funcs = false;
    bool do_imports = false;
    bool do_exports = false;
    bool force_exe = false;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-o" && i + 1 < argc) {
            output_dir = argv[++i];
            do_dump = true;
        } else if (arg == "-s" && i + 1 < argc) {
            search_query = argv[++i];
        } else if (arg == "--offset" && i + 1 < argc) {
            offset_query = argv[++i];
        } else if (arg == "--string" && i + 1 < argc) {
            string_query = argv[++i];
        } else if (arg == "--pattern" && i + 1 < argc) {
            pattern_query = argv[++i];
        } else if (arg == "--vtable") {
            do_vtable = true;
        } else if (arg == "--categories") {
            do_categories = true;
        } else if (arg == "--funcs") {
            do_funcs = true;
        } else if (arg == "--dump") {
            do_dump = true;
        } else if (arg == "--lua") {
            do_lua = true;
        } else if (arg == "--exe") {
            force_exe = true;
        } else if (arg == "--imports") {
            do_imports = true;
        } else if (arg == "--exports") {
            do_exports = true;
        }
    }

    if (output_dir.empty()) {
        output_dir = "dump";
    }

    // ─── Auto-detect file type ───
    FileType ftype = detect_file_type(filepath);
    if (force_exe) ftype = FileType::PE;

    if (ftype == FileType::PE) {
        // ─── PE/EXE Mode ───
        PeDumperApp app(filepath, output_dir);

        bool has_cli_command = !search_query.empty() || !string_query.empty() ||
                               do_funcs || do_imports || do_exports || do_dump || do_lua;

        if (has_cli_command) {
            if (!app.run()) return 1;

            if (!search_query.empty())  app.do_search(search_query);
            if (!string_query.empty())  app.do_string_search(string_query);
            if (do_funcs)               app.do_list_functions();
            if (do_imports)             app.do_list_imports();
            if (do_exports)             app.do_list_exports();
            if (do_lua)                 app.dump_lua();
        } else {
            app.interactive();
        }
    } else {
        // ─── ELF Mode ───
        DumperApp app(filepath, output_dir);

        bool has_cli_command = !search_query.empty() || !offset_query.empty() ||
                               !string_query.empty() || !pattern_query.empty() ||
                               do_vtable || do_categories || do_funcs || do_dump || do_lua;

        if (has_cli_command) {
            if (!app.run()) return 1;

            if (!search_query.empty())  app.do_search(search_query);
            if (!offset_query.empty())  app.do_offset_search(offset_query);
            if (!string_query.empty())  app.do_string_search(string_query);
            if (!pattern_query.empty()) app.do_pattern_scan(pattern_query);
            if (do_vtable)              app.do_vtable_search();
            if (do_categories)          app.do_category_search("");
            if (do_funcs)               app.do_list_functions();
            if (do_lua)                app.dump_lua();
        } else {
            app.interactive();
        }
    }

    return 0;
}
