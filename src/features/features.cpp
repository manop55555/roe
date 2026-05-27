// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors

#include "roe/features.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <utility>

namespace roe::features {
namespace {

std::string instruction_text(const disasm::Instruction& instruction)
{
    if (instruction.operands.empty()) {
        return instruction.mnemonic;
    }
    return instruction.mnemonic + " " + instruction.operands;
}

// Instruction text with the branch target shown as its resolved symbol name when known.
std::string resolved_instruction_text(const resolver::AnnotatedInstruction& annotated)
{
    if (annotated.branch_target_symbol.has_value()) {
        return annotated.instruction.mnemonic + " " + annotated.branch_target_symbol->name;
    }
    return instruction_text(annotated.instruction);
}

// True if an annotated instruction calls or branches to a named symbol. Tolerates
// the @plt/@got suffixes roe adds to PLT and GOT reference display names.
bool references_symbol(const resolver::AnnotatedInstruction& annotated, std::string_view name)
{
    if (annotated.branch_target_symbol.has_value()) {
        const resolver::ResolvedSymbol& symbol = *annotated.branch_target_symbol;
        if (symbol.name == name || symbol.raw_name == name) {
            return true;
        }
        if (symbol.name.rfind(std::string(name) + "@", 0) == 0) {
            return true;
        }
    }
    if (annotated.reference.has_value()) {
        const resolver::ResolvedReference& reference = *annotated.reference;
        if (reference.name == name || reference.raw_name == name) {
            return true;
        }
        if (reference.name.rfind(std::string(name) + "@", 0) == 0) {
            return true;
        }
    }
    return false;
}

bool splits_block(disasm::BranchKind kind) noexcept
{
    switch (kind) {
    case disasm::BranchKind::ConditionalJump:
    case disasm::BranchKind::UnconditionalJump:
    case disasm::BranchKind::Return:
    case disasm::BranchKind::IndirectJump:
        return true;
    case disasm::BranchKind::None:
    case disasm::BranchKind::Call:
    case disasm::BranchKind::IndirectCall:
        return false;
    }
    return false;
}

bool counts_as_branch(disasm::BranchKind kind) noexcept
{
    switch (kind) {
    case disasm::BranchKind::ConditionalJump:
    case disasm::BranchKind::UnconditionalJump:
    case disasm::BranchKind::Call:
    case disasm::BranchKind::IndirectJump:
    case disasm::BranchKind::IndirectCall:
        return true;
    case disasm::BranchKind::None:
    case disasm::BranchKind::Return:
        return false;
    }
    return false;
}

} // namespace

Result<std::vector<binary::Symbol>> filter_functions(
    const std::vector<binary::Symbol>& functions,
    std::string_view regex_pattern)
{
    std::vector<binary::Symbol> matched;
    try {
        const std::regex pattern{std::string(regex_pattern), std::regex::ECMAScript};
        for (const binary::Symbol& function : functions) {
            if (std::regex_search(function.name, pattern) || std::regex_search(function.raw_name, pattern)) {
                matched.push_back(function);
            }
        }
    } catch (const std::regex_error& error) {
        return Result<std::vector<binary::Symbol>>::err(
            {ErrorCode::Usage, std::string("invalid regular expression: ") + error.what(), 0, false});
    }
    return Result<std::vector<binary::Symbol>>::ok(std::move(matched));
}

std::vector<binary::Symbol> functions_calling(
    const std::vector<FunctionBody>& functions,
    std::string_view symbol_name)
{
    std::vector<binary::Symbol> matched;
    for (const FunctionBody& function : functions) {
        for (const resolver::AnnotatedInstruction& annotated : function.instructions) {
            if (references_symbol(annotated, symbol_name)) {
                matched.push_back(function.symbol);
                break;
            }
        }
    }
    return matched;
}

std::vector<binary::Symbol> functions_containing_string(
    const std::vector<FunctionBody>& functions,
    std::string_view text)
{
    std::vector<binary::Symbol> matched;
    for (const FunctionBody& function : functions) {
        for (const resolver::AnnotatedInstruction& annotated : function.instructions) {
            if (annotated.string_reference.has_value() &&
                annotated.string_reference->value.find(text) != std::string::npos) {
                matched.push_back(function.symbol);
                break;
            }
        }
    }
    return matched;
}

std::vector<Xref> find_xrefs(const std::vector<FunctionBody>& functions, std::string_view target_name)
{
    std::vector<Xref> xrefs;
    for (const FunctionBody& function : functions) {
        for (const resolver::AnnotatedInstruction& annotated : function.instructions) {
            if (!references_symbol(annotated, target_name)) {
                continue;
            }
            Xref xref;
            xref.from_function = function.symbol.name;
            xref.from_function_address = function.symbol.address;
            xref.instruction_address = annotated.instruction.address;
            xref.target_name = std::string(target_name);
            xref.target_address = annotated.instruction.branch_target.value_or(0);
            xref.instruction_text = resolved_instruction_text(annotated);
            xrefs.push_back(std::move(xref));
        }
    }
    return xrefs;
}

std::vector<FunctionStats> compute_stats(const std::vector<FunctionBody>& functions)
{
    std::vector<FunctionStats> stats;
    stats.reserve(functions.size());
    for (const FunctionBody& function : functions) {
        const std::vector<resolver::AnnotatedInstruction>& body = function.instructions;
        FunctionStats entry;
        entry.name = function.symbol.name;
        entry.address = function.symbol.address;

        if (function.symbol.size != 0U) {
            entry.size = function.symbol.size;
        } else if (!body.empty()) {
            const disasm::Instruction& last = body.back().instruction;
            entry.size = (last.address + last.size) - body.front().instruction.address;
        }

        std::map<std::uint64_t, std::size_t> index_of;
        for (std::size_t i = 0; i < body.size(); ++i) {
            index_of.emplace(body[i].instruction.address, i);
        }

        std::set<std::size_t> leaders;
        if (!body.empty()) {
            leaders.insert(0U);
        }
        std::uint64_t branch_count = 0;
        std::vector<std::pair<std::size_t, std::size_t>> spans;
        for (std::size_t i = 0; i < body.size(); ++i) {
            const disasm::Instruction& instruction = body[i].instruction;
            if (counts_as_branch(instruction.branch_kind)) {
                ++branch_count;
            }
            if (splits_block(instruction.branch_kind) && i + 1 < body.size()) {
                leaders.insert(i + 1);
            }
            if (instruction.branch_target.has_value()) {
                const auto target = index_of.find(*instruction.branch_target);
                if (target != index_of.end()) {
                    leaders.insert(target->second);
                    spans.emplace_back(std::min(i, target->second), std::max(i, target->second));
                }
            }
        }

        entry.branch_count = branch_count;
        entry.basic_blocks = body.empty() ? 0U : static_cast<std::uint64_t>(leaders.size());

        std::uint64_t max_depth = 0;
        for (std::size_t position = 0; position < body.size(); ++position) {
            std::uint64_t depth = 0;
            for (const auto& span : spans) {
                if (position >= span.first && position <= span.second) {
                    ++depth;
                }
            }
            max_depth = std::max(max_depth, depth);
        }
        entry.max_nesting_depth = max_depth;

        stats.push_back(std::move(entry));
    }
    return stats;
}

std::vector<resolver::AnnotatedInstruction> annotate_string_references(
    const binary::Object& object,
    const std::vector<resolver::AnnotatedInstruction>& instructions)
{
    std::vector<resolver::AnnotatedInstruction> annotated = instructions;
    if (object.strings.empty()) {
        return annotated;
    }

    std::vector<const binary::StringLiteral*> sorted;
    sorted.reserve(object.strings.size());
    for (const binary::StringLiteral& literal : object.strings) {
        sorted.push_back(&literal);
    }
    std::sort(sorted.begin(), sorted.end(),
        [](const binary::StringLiteral* lhs, const binary::StringLiteral* rhs) { return lhs->address < rhs->address; });

    for (resolver::AnnotatedInstruction& entry : annotated) {
        if (!entry.instruction.reference_target.has_value()) {
            continue;
        }
        const std::uint64_t address = *entry.instruction.reference_target;
        const auto upper = std::upper_bound(sorted.begin(), sorted.end(), address,
            [](std::uint64_t value, const binary::StringLiteral* literal) { return value < literal->address; });
        if (upper == sorted.begin()) {
            continue;
        }
        const binary::StringLiteral* literal = *(upper - 1);
        if (address >= literal->address && address < literal->address + literal->size) {
            entry.string_reference = *literal;
        }
    }
    return annotated;
}

} // namespace roe::features
