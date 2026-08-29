// THE BUG:         std::vector<bool> is not a container of bool. Its operator[]
//                  returns a *proxy reference*, and `auto x = v[i];` captures the
//                  proxy -- which still points into the vector -- instead of a
//                  plain bool copy.
// WHY IT'S MISSED: `auto` is supposed to "just give you the value". For every
//                  other vector, `auto x = v[i];` is an independent copy and
//                  mutating `x` cannot touch the container. std::vector<bool> is
//                  the standard library's one famous exception: it is bit-packed,
//                  so `operator[]` hands back `std::vector<bool>::reference`, a
//                  tiny object holding a pointer-and-mask into the bits. `auto`
//                  faithfully deduces *that proxy type*, so the "copy" is an alias
//                  and `x = true;` flips the bit inside the vector. The exact same
//                  template, instantiated for vector<char>, behaves correctly --
//                  which is what makes the bug so maddening to track down.
// HOW TO DETECT:   No standard warning. clang-tidy is largely silent too. The
//                  defense is to know the special case and avoid `vector<bool>`
//                  in generic code; `deque<bool>` or `vector<char>` behave
//                  normally. Static analyzers that model proxy types can flag it.
// THE FIX:         Don't use std::vector<bool> when you need real bool semantics;
//                  use std::vector<char>, std::deque<bool>, or write
//                  `bool x = v[i];` so the proxy decays to an actual bool.
//
// Build & run:  c++ -std=c++17 -Wall 04_vector_bool_proxy.cpp && ./a.out
#include <iostream>
#include <vector>

// "Take a private copy of the first element and scribble on it."
// Safe for any normal container... except one.
template <typename Container>
void poke_a_copy(Container& c)
{
    auto x = c[0];   // copy? or proxy alias?
    x = true;        // should be a no-op on the container
    (void)x;
}

int main()
{
    std::vector<char> chars{0, 0, 0};   // a normal container of bytes
    std::vector<bool> bits{false, false, false};

    poke_a_copy(chars);
    poke_a_copy(bits);

    std::cout << "vector<char>[0] after poke_a_copy: "
              << static_cast<int>(chars[0]) << "  (expected 0)\n";
    std::cout << "vector<bool>[0] after poke_a_copy: "
              << bits[0] << "  (expected 0)\n";

    std::cout << "\n>>> BUG: the char vector is untouched, but vector<bool>[0]\n"
              << "    flipped to " << bits[0] << ". `auto x = v[0]` captured a\n"
              << "    proxy that writes straight back into the bit-packed vector.\n";

    // THE FIX -- force a genuine bool, or avoid vector<bool>:
    //   bool x = c[0];                 // proxy decays to a real copy
    //   std::vector<char> flags;       // no proxy shenanigans at all
    return 0;
}
