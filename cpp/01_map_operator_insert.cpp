// THE BUG:         Reading a std::map with operator[] silently *inserts* the key.
// WHY IT'S MISSED: `map[key]` looks like a lookup -- in Python, JavaScript, and
//                  most languages it is one. In C++ `operator[]` is defined to
//                  default-construct and insert the element when the key is
//                  absent, then return a reference to it. So a read-only-looking
//                  expression like `if (counts[name] > 0)` or even
//                  `auto v = m[k];` mutates the container. The map grows, a later
//                  `.size()` or range-loop sees phantom entries, and the line
//                  that did the damage looks completely innocent.
// HOW TO DETECT:   There is no warning -- the code is well-formed and "correct" by
//                  the standard. clang-tidy's readability checks and code review
//                  are your only line of defense. Marking the map `const` turns
//                  the accidental `operator[]` into a *compile error*, which is
//                  the cheapest tripwire available.
// THE FIX:         Use `.at(key)` (throws if absent), `.find(key)`, or
//                  `.contains(key)` (C++20) for lookups. Reserve `operator[]`
//                  for "insert-or-assign" intent.
//
// Build & run:  c++ -std=c++20 -Wall 01_map_operator_insert.cpp && ./a.out
#include <iostream>
#include <map>
#include <string>

int main()
{
    std::map<std::string, int> inventory{{"apples", 3}, {"pears", 5}};

    std::cout << "starting items: " << inventory.size() << '\n';

    // A read-only-looking audit: "is anything out of stock?"
    for (const char* item : {"apples", "bananas", "pears", "cherries"}) {
        if (inventory[item] == 0)                 // <-- inserts "bananas" & "cherries"
            std::cout << "  out of stock: " << item << '\n';
    }

    std::cout << "items after the audit: " << inventory.size() << '\n';
    std::cout << "\n>>> BUG: the map grew from 2 to " << inventory.size()
              << ". 'bananas' and 'cherries' were inserted (value 0)\n"
              << "    just by being looked up with operator[].\n";

    // THE FIX -- a real lookup that does not mutate:
    //   auto it = inventory.find(item);
    //   if (it == inventory.end() || it->second == 0) { ... }
    // or, in C++20:
    //   if (!inventory.contains(item) || inventory.at(item) == 0) { ... }
    return 0;
}
