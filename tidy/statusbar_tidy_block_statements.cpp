// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// clang-tidy plugin: statusbar-block-statements.
///
/// Counts the statements written directly inside each `{ ... }` block and
/// reports a block holding more than MaxStatements (default 4). A nested
/// block counts as one statement of its parent, not as its contents, so the
/// measure is "how much is going on at this level" rather than total size —
/// `readability-function-size` already bounds the latter, per function.
///
/// The diagnostic is attached to the opening brace, which is what makes
/// `// NOLINT(statusbar-block-statements)` on the brace's line suppress it.
///
/// Three exemptions, each of which was a false positive before it was one:
///
///  - a `switch` body is a single block holding every case, so bounding it
///    would mean bounding the number of cases;
///  - an implicit or defaulted member (a compiler-written copy assignment, a
///    defaulted `operator==`) has a body of one statement per member, and
///    that body's location is the *struct's* declaration, so the finding
///    lands on code nobody wrote;
///  - `*_test.cpp` and `*_fuzzer.cpp` are lists of cases, where a long block
///    is the shape of the file rather than a problem in it.
///
/// Built by cmake/clang_tidy.cmake against the installed clang-tidy's own
/// headers, and loaded with `clang-tidy -load=`. It must be compiled against
/// the same LLVM generation as the clang-tidy binary that loads it.

#include <clang-tidy/ClangTidyCheck.h>
#include <clang-tidy/ClangTidyModule.h>
#include <llvm/Config/llvm-config.h>
#if LLVM_VERSION_MAJOR < 22
// Moved into ClangTidyModule.h in LLVM 22, where including this one warns.
#    include <clang-tidy/ClangTidyModuleRegistry.h>
#endif

#include <clang/AST/ASTContext.h>
#include <clang/AST/Stmt.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/Basic/SourceManager.h>
#include <llvm/ADT/StringRef.h>

namespace statusbar::tidy {

namespace {

using namespace clang::ast_matchers;

/// A file whose long blocks are its shape, not a finding.
auto is_exempt_file(llvm::StringRef path) -> bool
{
    return path.ends_with("_test.cpp") || path.ends_with("_fuzzer.cpp");
}

}  // namespace

class BlockStatementsCheck : public clang::tidy::ClangTidyCheck
{
  public:
    BlockStatementsCheck(llvm::StringRef name, clang::tidy::ClangTidyContext* context)
        : ClangTidyCheck(name, context)
        , max_statements_{Options.get("MaxStatements", default_max_statements)}
    {}

    void storeOptions(clang::tidy::ClangTidyOptions::OptionMap& opts) override
    {
        Options.store(opts, "MaxStatements", max_statements_);
    }

    void registerMatchers(MatchFinder* finder) override
    {
        // The exemptions that the matcher language can state are stated
        // here, so the check() body only has to deal with the file name.
        finder->addMatcher(
            compoundStmt(unless(hasParent(switchStmt())), unless(hasAncestor(functionDecl(anyOf(isImplicit(), isDefaulted())))))
                .bind("block"),
            this);
    }

    void check(MatchFinder::MatchResult const& result) override
    {
        auto const* block = result.Nodes.getNodeAs<clang::CompoundStmt>("block");
        if (block == nullptr) {
            return;
        }
        clang::SourceLocation const brace = block->getLBracLoc();
        if (brace.isInvalid() || result.SourceManager == nullptr) {
            return;
        }
        if (is_exempt_file(result.SourceManager->getFilename(brace))) {
            return;
        }

        // Direct children only: a nested block, a lambda body, an `if`'s
        // own braces each count once, whatever they contain.
        auto const statements = static_cast<unsigned>(block->size());
        if (statements <= max_statements_) {
            return;
        }
        diag(brace, "block contains %0 statements; at most %1 belong at one level") << statements << max_statements_;
    }

  private:
    static constexpr unsigned default_max_statements = 4;

    unsigned max_statements_;
};

namespace {

class StatusbarTidyModule : public clang::tidy::ClangTidyModule
{
  public:
    void addCheckFactories(clang::tidy::ClangTidyCheckFactories& factories) override
    {
        factories.registerCheck<BlockStatementsCheck>("statusbar-block-statements");
    }
};

// Registered on load. The name is what `-checks=statusbar-*` selects.
// NOLINTNEXTLINE(cert-err58-cpp,fuchsia-statically-constructed-objects)
clang::tidy::ClangTidyModuleRegistry::Add<StatusbarTidyModule> const statusbar_module{"statusbar-module", "Statusbar house rules"};

}  // namespace

}  // namespace statusbar::tidy
