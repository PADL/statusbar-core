// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// A clang-tidy plugin with the house check statusbar-block-statements: a block ({...}) holds at most
/// MaxStatements statements (default 4), each counted once whatever its kind (a switch's body is
/// exempt: its cases are a list); an exception is marked
/// `// NOLINT(statusbar-block-statements): <reason>` on the opening brace's line.

#include "clang-tidy/ClangTidyCheck.h"
#include "clang-tidy/ClangTidyModule.h"
#include "clang-tidy/ClangTidyModuleRegistry.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"

namespace statusbar::tidy {

using clang::ast_matchers::MatchFinder;

class BlockStatementsCheck final : public clang::tidy::ClangTidyCheck
{
  public:
    BlockStatementsCheck(llvm::StringRef name, clang::tidy::ClangTidyContext* context)
        : ClangTidyCheck(name, context)
        , max_(Options.get("MaxStatements", 4U))
    {}

    void storeOptions(clang::tidy::ClangTidyOptions::OptionMap& options) override { Options.store(options, "MaxStatements", max_); }

    [[nodiscard]] bool isLanguageVersionSupported(clang::LangOptions const& lang) const override { return lang.CPlusPlus; }

    void registerMatchers(MatchFinder* finder) override
    {
        using namespace clang::ast_matchers;
        finder->addMatcher(compoundStmt(unless(isExpansionInSystemHeader()), unless(hasParent(switchStmt()))).bind("block"), this);
    }

    void check(MatchFinder::MatchResult const& result) override
    {
        auto const* block = result.Nodes.getNodeAs<clang::CompoundStmt>("block");
        auto const brace = block->getLBracLoc();
        if (brace.isInvalid() || brace.isMacroID() || block->size() <= max_) {
            return;
        }
        auto const& sources = *result.SourceManager;
        diag(brace, "block (lines %0-%1) has %2 statements, more than %3; move some into a function, or mark it an exception")
            << sources.getExpansionLineNumber(brace) << sources.getExpansionLineNumber(block->getRBracLoc())
            << static_cast<unsigned>(block->size()) << max_;
    }

  private:
    unsigned max_;
};

class Module final : public clang::tidy::ClangTidyModule
{
  public:
    void addCheckFactories(clang::tidy::ClangTidyCheckFactories& factories) override
    {
        factories.registerCheck<BlockStatementsCheck>("statusbar-block-statements");
    }
};

}  // namespace statusbar::tidy

static clang::tidy::ClangTidyModuleRegistry::Add<statusbar::tidy::Module> const registration(
    "statusbar-module", "statusbar house-style checks");
