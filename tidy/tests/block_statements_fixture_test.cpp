// A byte-for-byte copy of block_statements_fixture.cpp under a _test.cpp
// name. The check must report nothing here at all: the exemption is by
// file name, and this is how it is proved rather than asserted.
int sink(int v);

// 4 statements: at the limit, not reported.
int four()
{
    int a = 1;
    int b = 2;
    int c = a + b;
    return c;
}

// 5 statements: one over, reported at the opening brace.
int five()
{
    int a = 1;
    int b = 2;
    int c = a + b;
    int d = c + 1;
    return d;
}

// A nested block counts as ONE statement of its parent: 3 here, not 7.
int nested()
{
    int a = 1;
    {
        int b = 2;
        int c = 3;
        int d = 4;
        a = b + c + d;
    }
    return a;
}

// A switch body is one block holding every case: exempt.
int switcher(int v)
{
    switch (v) {
        case 0:
            return 0;
        case 1:
            return 1;
        case 2:
            return 2;
        case 3:
            return 3;
        case 4:
            return 4;
        default:
            return -1;
    }
}

// An implicit or defaulted member gets a compiler-written body of one
// statement per member, and that body's location is the STRUCT, not any code
// a person wrote: exempt. The member type has a non-trivial copy assignment
// so the implicit one is actually generated -- a defaulted function nobody
// forces the compiler to emit has no body to find, which is the trap this
// fixture fell into first time round.
struct Member
{
    int v = 0;
    auto operator=(Member const& other) -> Member&
    {
        v = other.v;
        return *this;
    }
    Member() = default;
    Member(Member const&) = default;
};

struct SixMembers
{
    Member a;
    Member b;
    Member c;
    Member d;
    Member e;
    Member f;

    auto operator==(SixMembers const&) const -> bool = default;
};

// Forces the implicit copy assignment (6 member-wise statements) to exist.
void copy_six(SixMembers& to, SixMembers const& from)
{
    to = from;
}

// An explicit NOLINT on the brace's line suppresses it.
int excused()
{  // NOLINT(statusbar-block-statements) five is fine here, it is a table
    int a = 1;
    int b = 2;
    int c = a + b;
    int d = c + 1;
    return d;
}
