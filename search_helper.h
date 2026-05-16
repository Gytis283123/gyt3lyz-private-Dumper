#pragma once
#include "elf_parser.h"
#include <string>
#include <vector>
#include <regex>
#include <algorithm>
#include <cctype>
#include <unordered_map>

// ─── Search Helper ───

struct SearchResult {
    uint64_t    offset;
    std::string name;
    std::string type;
    std::string bind;
    uint64_t    size;
    std::string context;  // extra info (category, etc.)
};

class SearchHelper {
public:
    explicit SearchHelper(const ElfParser& parser);

    // Search symbols by name (substring match, case-insensitive)
    std::vector<SearchResult> search_symbol(const std::string& query, bool exact = false) const;

    // Search symbols by offset/address range
    std::vector<SearchResult> search_by_offset(uint64_t offset) const;
    std::vector<SearchResult> search_by_offset_range(uint64_t lo, uint64_t hi) const;

    // Pattern scan on raw binary data (hex pattern like "AB ?? CD ?? EF")
    struct PatternMatch {
        uint64_t offset;
        std::vector<uint8_t> bytes;
    };
    std::vector<PatternMatch> pattern_scan(const std::string& hex_pattern) const;

    // Search strings by content
    std::vector<SearchResult> search_string(const std::string& query) const;

    // Get all symbols categorized by namespace/module
    using CategoryMap = std::unordered_map<std::string, std::vector<SearchResult>>;
    CategoryMap categorize_symbols() const;

    // Get vtable offsets for C++ classes
    std::vector<SearchResult> find_vtables() const;

    // Get all FUNC symbols sorted by offset
    std::vector<SearchResult> get_all_functions() const;

    // Demangle C++ symbol names (simplified)
    static std::string demangle(const std::string& mangled);

private:
    const ElfParser& m_parser;

    // Known library patterns for categorization (Cocos2d-x, etc.)
    struct CocosPattern {
        std::string category;
        std::string pattern;
    };

    static const std::vector<CocosPattern> s_cocos_patterns;

    bool match_ci(const std::string& haystack, const std::string& needle) const;
    std::vector<uint8_t> parse_hex_pattern(const std::string& hex, std::vector<bool>& mask) const;
};
