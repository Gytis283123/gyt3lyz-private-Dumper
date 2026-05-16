#include "search_helper.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cctype>

// ─── Library categorization patterns (Cocos2d-x + generic) ───

const std::vector<SearchHelper::CocosPattern> SearchHelper::s_cocos_patterns = {
    {"Node",       "cocos2d::Node"},
    {"Node",       "cocos2d::Scene"},
    {"Node",       "cocos2d::Layer"},
    {"Node",       "cocos2d::Sprite"},
    {"Node",       "cocos2d::Director"},
    {"Action",     "cocos2d::Action"},
    {"Action",     "cocos2d::Animate"},
    {"Action",     "cocos2d::MoveBy"},
    {"Action",     "cocos2d::MoveTo"},
    {"Action",     "cocos2d::ScaleBy"},
    {"Action",     "cocos2d::ScaleTo"},
    {"Action",     "cocos2d::RotateBy"},
    {"Action",     "cocos2d::RotateTo"},
    {"Action",     "cocos2d::FadeIn"},
    {"Action",     "cocos2d::FadeOut"},
    {"Action",     "cocos2d::Sequence"},
    {"Action",     "cocos2d::Spawn"},
    {"Action",     "cocos2d::CallFunc"},
    {"Action",     "cocos2d::DelayTime"},
    {"UI",         "cocos2d::ui::Button"},
    {"UI",         "cocos2d::ui::Text"},
    {"UI",         "cocos2d::ui::ImageView"},
    {"UI",         "cocos2d::ui::ListView"},
    {"UI",         "cocos2d::ui::ScrollView"},
    {"UI",         "cocos2d::ui::Layout"},
    {"UI",         "cocos2d::ui::Widget"},
    {"UI",         "cocos2d::ui::CheckBox"},
    {"UI",         "cocos2d::ui::Slider"},
    {"UI",         "cocos2d::ui::EditBox"},
    {"UI",         "cocos2d::ui::TextField"},
    {"Audio",      "cocos2d::AudioEngine"},
    {"Audio",      "cocos2d::SimpleAudioEngine"},
    {"Network",    "cocos2d::network::HttpClient"},
    {"Network",    "cocos2d::network::HttpRequest"},
    {"Network",    "cocos2d::network::HttpResponse"},
    {"Network",    "cocos2d::network::WebSocket"},
    {"Network",    "cocos2d::network::SocketIO"},
    {"Physics",    "cocos2d::PhysicsWorld"},
    {"Physics",    "cocos2d::PhysicsBody"},
    {"Physics",    "cocos2d::PhysicsShape"},
    {"Physics",    "cocos2d::PhysicsJoint"},
    {"Physics",    "cocos2d::PhysicsContact"},
    {"Renderer",   "cocos2d::Renderer"},
    {"Renderer",   "cocos2d::TextureCache"},
    {"Renderer",   "cocos2d::Texture2D"},
    {"Renderer",   "cocos2d::GLProgram"},
    {"Renderer",   "cocos2d::GLProgramState"},
    {"Renderer",   "cocos2d::ShaderCache"},
    {"Engine",     "cocos2d::Application"},
    {"Engine",     "cocos2d::Scheduler"},
    {"Engine",     "cocos2d::EventDispatcher"},
    {"Engine",     "cocos2d::FileUtils"},
    {"Engine",     "cocos2d::UserDefault"},
    {"Engine",     "cocos2d::Configuration"},
    {"Engine",     "cocos2d::PoolManager"},
    {"Spine",      "spine::"},
    {"Spine",      "cocos2d::SkeletonAnimation"},
    {"Spine",      "cocos2d::SkeletonRenderer"},
    {"DragonBones","dragonBones::"},
    {"DragonBones","cocos2d::DragonBones"},
    {"Label",      "cocos2d::Label"},
    {"Label",      "cocos2d::LabelTTF"},
    {"Label",      "cocos2d::LabelBMFont"},
    {"Map",        "cocos2d::TMXTiledMap"},
    {"Map",        "cocos2d::TMXLayer"},
    {"Map",        "cocos2d::FastTMXTiledMap"},
    {"Particle",   "cocos2d::ParticleSystem"},
    {"Particle",   "cocos2d::ParticleFire"},
    {"Particle",   "cocos2d::ParticleSmoke"},
    {"3D",         "cocos2d::Sprite3D"},
    {"3D",         "cocos2d::Animate3D"},
    {"3D",         "cocos2d::Skeleton3D"},
    {"3D",         "cocos2d::AttachNode"},
    {"3D",         "cocos2d::AABB"},
    {"3D",         "cocos2d::Ray"},
    {"3D",         "cocos2d::Mesh"},
    {"3D",         "cocos2d::Material"},
    {"3D",         "cocos2d::Technique"},
    {"3D",         "cocos2d::Pass"},
};

// ─── Constructor ───

SearchHelper::SearchHelper(const ElfParser& parser)
    : m_parser(parser)
{}

// ─── Case-insensitive substring match ───

bool SearchHelper::match_ci(const std::string& haystack, const std::string& needle) const {
    if (needle.empty()) return true;
    auto it = std::search(haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](char a, char b) { return std::tolower(a) == std::tolower(b); });
    return it != haystack.end();
}

// ─── Symbol search ───

std::vector<SearchResult> SearchHelper::search_symbol(const std::string& query, bool exact) const {
    std::vector<SearchResult> results;

    auto process = [&](const std::vector<ElfSymbol>& syms) {
        for (const auto& sym : syms) {
            if (sym.name.empty()) continue;
            bool match = exact ? (sym.name == query) : match_ci(sym.name, query);
            if (match) {
                results.push_back({
                    sym.value, sym.name, sym.type_name(), sym.bind_name(), sym.size, ""
                });
            }
        }
    };

    process(m_parser.symbols());
    process(m_parser.dynamic_symbols());
    process(m_parser.code_functions());

    std::sort(results.begin(), results.end(),
        [](const SearchResult& a, const SearchResult& b) { return a.offset < b.offset; });
    return results;
}

// ─── Offset search ───

std::vector<SearchResult> SearchHelper::search_by_offset(uint64_t offset) const {
    return search_by_offset_range(offset, offset);
}

std::vector<SearchResult> SearchHelper::search_by_offset_range(uint64_t lo, uint64_t hi) const {
    std::vector<SearchResult> results;

    auto process = [&](const std::vector<ElfSymbol>& syms) {
        for (const auto& sym : syms) {
            if (sym.name.empty()) continue;
            if (sym.value >= lo && sym.value <= hi) {
                results.push_back({
                    sym.value, sym.name, sym.type_name(), sym.bind_name(), sym.size, ""
                });
            }
        }
    };

    process(m_parser.symbols());
    process(m_parser.dynamic_symbols());
    process(m_parser.code_functions());

    std::sort(results.begin(), results.end(),
        [](const SearchResult& a, const SearchResult& b) { return a.offset < b.offset; });
    return results;
}

// ─── Hex pattern parsing ───

std::vector<uint8_t> SearchHelper::parse_hex_pattern(const std::string& hex, std::vector<bool>& mask) const {
    std::vector<uint8_t> bytes;
    mask.clear();

    std::string cleaned;
    for (char c : hex) {
        if (c != ' ' && c != '-' && c != '.') cleaned += c;
        else if (c == '.' || c == '?') cleaned += "??";
    }

    for (size_t i = 0; i + 1 < cleaned.size(); i += 2) {
        if (cleaned[i] == '?' && cleaned[i+1] == '?') {
            bytes.push_back(0);
            mask.push_back(false);
        } else {
            std::string byte_str = cleaned.substr(i, 2);
            auto val = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
            bytes.push_back(val);
            mask.push_back(true);
        }
    }
    return bytes;
}

// ─── Pattern scan ───

std::vector<SearchHelper::PatternMatch> SearchHelper::pattern_scan(const std::string& hex_pattern) const {
    std::vector<PatternMatch> matches;
    std::vector<bool> mask;
    auto pattern = parse_hex_pattern(hex_pattern, mask);

    if (pattern.empty()) return matches;

    // Re-open the binary file for raw byte scanning
    std::ifstream binfile(m_parser.filepath(), std::ios::binary);
    if (!binfile.is_open()) return matches;

    // Read the entire file into memory
    std::vector<uint8_t> data(m_parser.file_size());
    binfile.read(reinterpret_cast<char*>(data.data()), data.size());
    binfile.close();

    size_t pat_len = pattern.size();
    for (uint64_t i = 0; i + pat_len <= data.size(); ++i) {
        bool found = true;
        for (size_t j = 0; j < pat_len; ++j) {
            if (mask[j] && data[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }
        if (found) {
            PatternMatch pm;
            pm.offset = i;
            for (size_t j = 0; j < pat_len; ++j) {
                pm.bytes.push_back(data[i + j]);
            }
            matches.push_back(pm);
        }
    }

    return matches;
}

// ─── String search ───

std::vector<SearchResult> SearchHelper::search_string(const std::string& query) const {
    std::vector<SearchResult> results;
    for (const auto& [offset, str] : m_parser.strings()) {
        if (match_ci(str, query)) {
            // Truncate long strings for display
            std::string display = str.size() > 120 ? str.substr(0, 120) + "..." : str;
            results.push_back({offset, display, "STRING", "", str.size(), ""});
        }
    }
    std::sort(results.begin(), results.end(),
        [](const SearchResult& a, const SearchResult& b) { return a.offset < b.offset; });
    return results;
}

// ─── Categorize symbols by namespace/library ───

SearchHelper::CategoryMap SearchHelper::categorize_symbols() const {
    CategoryMap categories;

    auto process = [&](const std::vector<ElfSymbol>& syms) {
        for (const auto& sym : syms) {
            if (sym.name.empty()) continue;

            // First try known library patterns (Cocos2d-x, etc.)
            bool matched = false;
            for (const auto& cp : s_cocos_patterns) {
                if (sym.name.find(cp.pattern) != std::string::npos) {
                    categories[cp.category].push_back({
                        sym.value, sym.name, sym.type_name(), sym.bind_name(), sym.size, cp.category
                    });
                    matched = true;
                    break;
                }
            }
            if (matched) continue;

            // Generic namespace-based categorization for any C++ library
            // Extract namespace from mangled names: _ZN<len>namespace<len>class... or _ZNK...
            std::string demangled = demangle(sym.name);
            std::string category = "Global";

            // Try to extract namespace from demangled name
            auto pos = demangled.find("::");
            if (pos != std::string::npos) {
                // Walk back to find the namespace start (after return type)
                std::string before = demangled.substr(0, pos);
                auto last_space = before.find_last_of(" \t");
                if (last_space != std::string::npos) {
                    category = before.substr(last_space + 1);
                } else {
                    category = before;
                }
                // If category contains parentheses, it's probably not a namespace
                if (category.find('(') != std::string::npos || category.find(')') != std::string::npos) {
                    category = "Global";
                }
                // Truncate very long categories
                if (category.length() > 50) {
                    category = category.substr(0, 50);
                }
            }

            // Also categorize by known prefixes in raw symbol names
            if (category == "Global") {
                if (sym.name.find("cocos2d") != std::string::npos ||
                    sym.name.find("cocos") != std::string::npos) {
                    category = "Cocos2d";
                } else if (sym.name.find("std::") != std::string::npos ||
                           sym.name.find("_ZSt") != std::string::npos ||
                           sym.name.find("_ZNSt") != std::string::npos) {
                    category = "StdLib";
                } else if (sym.name.find("_ZTV") != std::string::npos) {
                    category = "VTable";
                } else if (sym.name.find("_ZTI") != std::string::npos) {
                    category = "TypeInfo";
                } else if (sym.name.find("_ZTS") != std::string::npos) {
                    category = "TypeName";
                } else if (sym.name.find("_ZN") == 0) {
                    // C++ mangled name - try to extract first namespace
                    // Format: _ZN<len>ns1<len>ns2...E...
                    size_t i = 3; // skip _ZN
                    while (i < sym.name.size() && std::isdigit(sym.name[i])) {
                        int len = 0;
                        while (i < sym.name.size() && std::isdigit(sym.name[i])) {
                            len = len * 10 + (sym.name[i] - '0');
                            i++;
                        }
                        if (i + len <= sym.name.size()) {
                            std::string ns = sym.name.substr(i, len);
                            // Skip numeric-only namespaces (like nested counts)
                            bool is_numeric = true;
                            for (char c : ns) {
                                if (!std::isdigit(c)) { is_numeric = false; break; }
                            }
                            if (!is_numeric && ns.length() <= 50) {
                                category = ns;
                            }
                            break;
                        }
                        break;
                    }
                } else if (sym.name.find("JNI") != std::string::npos ||
                           sym.name.find("Java_") == 0) {
                    category = "JNI";
                } else if (sym.name.find("lua") != std::string::npos ||
                           sym.name.find("luaL") != std::string::npos) {
                    category = "Lua";
                } else if (sym.name.find("Unity") != std::string::npos ||
                           sym.name.find("il2cpp") != std::string::npos) {
                    category = "Unity";
                } else if (sym.name.find("Unreal") != std::string::npos ||
                           sym.name.find("UE_") != std::string::npos) {
                    category = "Unreal";
                }
            }

            categories[category].push_back({
                sym.value, sym.name, sym.type_name(), sym.bind_name(), sym.size, category
            });
        }
    };

    process(m_parser.symbols());
    process(m_parser.dynamic_symbols());

    return categories;
}

// ─── Find vtables ───

std::vector<SearchResult> SearchHelper::find_vtables() const {
    std::vector<SearchResult> results;

    auto process = [&](const std::vector<ElfSymbol>& syms) {
        for (const auto& sym : syms) {
            if (sym.name.empty()) continue;
            // VTable symbols typically start with "_ZTV" or "vtable for"
            if (sym.name.find("_ZTV") != std::string::npos ||
                sym.name.find("vtable") != std::string::npos ||
                sym.name.find("VTT") != std::string::npos ||
                sym.name.find("_ZTT") != std::string::npos) {
                std::string ctx = "vtable";
                if (sym.name.find("_ZTT") != std::string::npos ||
                    sym.name.find("VTT") != std::string::npos) {
                    ctx = "VTT";
                }
                results.push_back({
                    sym.value, sym.name, sym.type_name(), sym.bind_name(), sym.size, ctx
                });
            }
        }
    };

    process(m_parser.symbols());
    process(m_parser.dynamic_symbols());
    process(m_parser.code_functions());

    std::sort(results.begin(), results.end(),
        [](const SearchResult& a, const SearchResult& b) { return a.offset < b.offset; });
    return results;
}

// ─── Get all functions ───

std::vector<SearchResult> SearchHelper::get_all_functions() const {
    std::vector<SearchResult> results;

    auto process = [&](const std::vector<ElfSymbol>& syms) {
        for (const auto& sym : syms) {
            if (sym.name.empty()) continue;
            if (sym.type_val() == 2) { // STT_FUNC
                results.push_back({
                    sym.value, sym.name, "FUNC", sym.bind_name(), sym.size, ""
                });
            }
        }
    };

    process(m_parser.symbols());
    process(m_parser.dynamic_symbols());
    process(m_parser.code_functions());

    std::sort(results.begin(), results.end(),
        [](const SearchResult& a, const SearchResult& b) { return a.offset < b.offset; });
    return results;
}

// ─── Simplified demangling ───

std::string SearchHelper::demangle(const std::string& mangled) {
    // Very simplified C++ name demangling
    // Handles common Itanium ABI patterns: _Z, _ZN, _ZTV, etc.

    if (mangled.empty() || mangled[0] != '_') return mangled;

    size_t pos = 0;

    // Skip _Z prefix
    if (mangled.substr(0, 2) == "_Z") {
        pos = 2;
    } else if (mangled.substr(0, 4) == "_ZTV") {
        pos = 4;  // vtable
    } else if (mangled.substr(0, 4) == "_ZTT") {
        pos = 4;  // VTT
    } else if (mangled.substr(0, 4) == "_ZTI") {
        pos = 4;  // typeinfo
    } else if (mangled.substr(0, 4) == "_ZTS") {
        pos = 4;  // typeinfo name
    } else if (mangled.substr(0, 3) == "_ZN") {
        pos = 3;  // nested name
    } else {
        return mangled;
    }

    std::string result;
    std::vector<std::string> components;

    // Parse nested names (e.g., _ZN6cocos2d4Node7createE)
    if (mangled[2] == 'N') {
        pos = 3;
        // Skip qualifiers
        while (pos < mangled.size() && (mangled[pos] == 'K' || mangled[pos] == 'V' ||
               mangled[pos] == 'r' || mangled[pos] == 'R' || mangled[pos] == 'O')) {
            pos++;
        }

        while (pos < mangled.size() && std::isdigit(mangled[pos])) {
            int len = 0;
            while (pos < mangled.size() && std::isdigit(mangled[pos])) {
                len = len * 10 + (mangled[pos] - '0');
                pos++;
            }
            if (pos + len > mangled.size()) break;
            components.push_back(mangled.substr(pos, len));
            pos += len;
        }

        for (size_t i = 0; i < components.size(); ++i) {
            if (i > 0) result += "::";
            result += components[i];
        }
    } else {
        // Non-nested name
        while (pos < mangled.size() && std::isdigit(mangled[pos])) {
            int len = 0;
            while (pos < mangled.size() && std::isdigit(mangled[pos])) {
                len = len * 10 + (mangled[pos] - '0');
                pos++;
            }
            if (pos + len > mangled.size()) break;
            result += mangled.substr(pos, len);
            pos += len;
        }
    }

    return result.empty() ? mangled : result;
}
