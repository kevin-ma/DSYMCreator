//
//  macho.h
//  DSYMCreator
//
//  Created by oldman on 8/10/16.
//
//

#ifndef macho_h
#define macho_h

#include <assert.h>
#include <algorithm>
#include <iterator>
#include <vector>
#include <string>

#include "common.h"
#include "dwarf_debug_abbrev_section.h"
#include "dwarf_debug_info_section.h"
#include "dwarf_dummy_debug_line_section.h"
#include "symbol.h"
#include "symbol_table.h"
#include "string_table.h"
#include "util.h"

template <typename T>
struct Macho {
public:
    ByteBuffer dump(const std::string& uuid,
                    const std::vector<Symbol<T>>& symbols,
                    T section_vm_addr_offset) const;
    
private:
    template <typename U>
    static U align_to(U address, uint32_t align) {
        return ((address - 1) / align + 1) * align;
    }
    
    static const uint32_t kSymbolTableOffset = 0x1000;
    static const uint32_t kAlignBase = 0x1000;
};


template <typename T>
ByteBuffer Macho<T>::dump(const std::string& uuid,
                               const std::vector<Symbol<T>>& symbols,
                               T section_vm_addr_offset) const {
    // prepare strings
    std::vector<std::string> names;
    std::transform(symbols.begin(), symbols.end(), std::inserter(names, names.end()), [](const Symbol<T>& s) {
        return s.name;
    });

    // prepare string table
    StringTable string_table;
    auto string_result = string_table.dump(names);
    
    // preapre symbol table
    SymbolTable<T> symbol_table;
    std::map<std::string, uint32_t> off = string_result.name_to_offset;
    auto symbol_buffer = symbol_table.dump(symbols, off);
    
    
    // prepare dwarf sections
    DwarfDummyDebugLineSection debug_line_section;
    auto debug_line_buffer = debug_line_section.dump();
    DwarfDebugAbbrevSection debug_abbrev_section;
    auto debug_abbrev_buffer = debug_abbrev_section.dump();
    DwarfDebugInfoSection<T> debug_info_section;
    auto debug_info_buffer = debug_info_section.dump(symbols, string_result.name_to_offset);
    
    // prepare symtab command
    SymtabCommand symtab_command;
    symtab_command.symoff = kSymbolTableOffset;
    symtab_command.nsyms = uint32_t(symbols.size());
    symtab_command.stroff = uint32_t(symtab_command.symoff + symbol_buffer.size());
    symtab_command.strsize = uint32_t(string_result.buffer.size()) + 2;
    
    // 准备PAGEZERO命令
    PageZeroSegmentCommand<T> page_zero_segment_command;
    page_zero_segment_command.cmdsize = 0x48;
    page_zero_segment_command.nsects = 0;
    
    // prepare text segment command
    TextSectionHeader<T> text_section_header;
    TextSegmentCommand<T> text_segment_command;
    text_segment_command.nsects = 1;
    text_segment_command.cmdsize = sizeof(TextSectionHeader<T>) + sizeof(TextSegmentCommand<T>);
    
    // 计算 __TEXT Segment 的大小
    unsigned long save_offset = (symbol_buffer[9] << 8) + symbol_buffer[8];
    unsigned long total_size = symtab_command.stroff + symtab_command.strsize;
    unsigned long string_end = save_offset + total_size;
    
    unsigned long addr = (text_segment_command.vmaddr + save_offset);
    text_section_header.addr = (uint64_t)addr;
    text_section_header.size = (uint64_t)total_size;
    text_segment_command.vmsize = (uint64_t)align_to(string_end, kAlignBase);
    
    // 准备link edit commnad
    T vmbase = align_to(section_vm_addr_offset, kAlignBase);
    uint32_t link_edit_sections_start_offset = text_segment_command.vmsize + vmbase;
    LinkEditSegmentCommand<T> link_edit_segment_command;
    link_edit_segment_command.vmaddr = vmbase + link_edit_sections_start_offset;
    link_edit_segment_command.filesize = symtab_command.nsyms * 0x10 + symtab_command.strsize;
    link_edit_segment_command.vmsize = align_to(link_edit_segment_command.filesize, kAlignBase);
    link_edit_segment_command.fileoff = kSymbolTableOffset;
    link_edit_segment_command.cmdsize = 0x48;
    link_edit_segment_command.nsects = 0;
    
    // prepare dwarf segement command
    uint32_t dwarf_sections_start_offset = link_edit_segment_command.vmaddr + link_edit_segment_command.vmsize;
    uint32_t offset = dwarf_sections_start_offset;
    DwarfCommonSectionHeader<T> debug_line_section_header("__debug_line", vmbase, offset, (uint32_t)debug_line_buffer.size());
    offset += debug_line_buffer.size();
    DwarfCommonSectionHeader<T> debug_info_section_header("__debug_info", vmbase, offset, (uint32_t)debug_info_buffer.size());
    offset += debug_info_buffer.size();
    DwarfCommonSectionHeader<T> debug_abbrev_section_header("__debug_abbrev", vmbase, offset, (uint32_t)debug_abbrev_buffer.size());
    offset += debug_abbrev_buffer.size();
    DwarfCommonSectionHeader<T> debug_str_section_header("__debug_str", vmbase, offset, (uint32_t)string_result.buffer.size());
    offset += string_result.buffer.size();
    
    DwarfSegmentCommand<T> dwarf_segment_command;
    dwarf_segment_command.vmaddr = vmbase + dwarf_sections_start_offset;
    dwarf_segment_command.fileoff = dwarf_sections_start_offset;
    dwarf_segment_command.filesize = offset - dwarf_sections_start_offset;
    dwarf_segment_command.nsects = 4;
    dwarf_segment_command.cmdsize = sizeof(DwarfSegmentCommand<T>) + 4 * sizeof(DwarfCommonSectionHeader<T>);
    
    // prepare uuid command
    UUIDCommand uuid_command;
    std::string clean_uuid = uuid;
    clean_uuid.erase(std::remove(clean_uuid.begin(), clean_uuid.end(), '-'), clean_uuid.end());     // remove the hyphen in uuid first
    assert(clean_uuid.length() == 32);
    for (int i = 0; i < 16; ++i) {
        std::string str = clean_uuid.substr(2*i, 2);
        uuid_command.uuid[i] = strtol(str.c_str(), NULL, 16);
    }
    
    // prepare mach header
    MachHeader<T> mach_header;
    mach_header.ncmds = 6;
    mach_header.sizeofcmds = sizeof(UUIDCommand) + sizeof(SymtabCommand) + sizeof(TextSegmentCommand<T>) + sizeof(TextSectionHeader<T>);
    mach_header.sizeofcmds = mach_header.sizeofcmds + sizeof(PageZeroSegmentCommand<T>) + sizeof(DwarfSegmentCommand<T>) + sizeof(DwarfCommonSectionHeader<T>) * 4 + sizeof(LinkEditSegmentCommand<T>);
    
    // 修复header信息
//    mach_header.sizeofcmds = 0x250;
    

    
    // 校正
    text_section_header.align = 0x2;
    text_section_header.flags = 0x80000400;
    
    // 符号拼接
    ByteBuffer header_symbol_buffer;
//    header_symbol_buffer
    
    // write
    ByteBuffer buffer;
    util::append_to_buffer(buffer, mach_header);
    util::append_to_buffer(buffer, uuid_command);
    util::append_to_buffer(buffer, symtab_command);
    util::append_to_buffer(buffer, page_zero_segment_command);
    util::append_to_buffer(buffer, text_segment_command);
    util::append_to_buffer(buffer, text_section_header);
    util::append_to_buffer(buffer, link_edit_segment_command);
    util::append_to_buffer(buffer, dwarf_segment_command);
    util::append_to_buffer(buffer, debug_line_section_header);
    util::append_to_buffer(buffer, debug_str_section_header);
    util::append_to_buffer(buffer, debug_abbrev_section_header);
    util::append_to_buffer(buffer, debug_info_section_header);
    assert(buffer.size() <= kSymbolTableOffset);
    buffer.resize(kSymbolTableOffset);
    util::append_to_buffer(buffer, symbol_buffer);
//    util::append_to_buffer(buffer, header_symbol_buffer);
    buffer.resize(buffer.size()+2);
    ByteBuffer string_buffer = string_result.buffer;
    util::append_to_buffer(buffer, string_buffer);
    assert(buffer.size() <= dwarf_sections_start_offset);
    buffer.resize(dwarf_sections_start_offset);
    util::append_to_buffer(buffer, debug_line_buffer);
    util::append_to_buffer(buffer, debug_info_buffer);
    util::append_to_buffer(buffer, debug_abbrev_buffer);
    util::append_to_buffer(buffer, string_result.buffer);
    
    return buffer;
}




#endif /* macho_h */
