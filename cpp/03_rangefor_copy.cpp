// THE BUG:         A range-for loop (or structured binding) that copies each
//                  element by value, so writes "to the container" go nowhere.
// WHY IT'S MISSED: `for (auto [key, value] : map)` reads exactly like the loop
//                  you wanted, and the body `value *= 10;` compiles, runs, and
//                  mutates... a per-iteration *copy*. The original map is left
//                  untouched. There is no error, no warning, no crash -- the
//                  totals are just quietly never updated. The single missing
//                  character is the `&` in `auto&`. It is one of the most common
//                  bugs in modern C++ and one of the hardest to see in review,
//                  because the loop "obviously" modifies the map.
// HOW TO DETECT:   gcc/clang `-Wrange-loop-construct` / clang-tidy
//                  `performance-for-range-copy` flag *expensive* copies, but a
//                  cheap `int` copy slips past even those. The reliable tell:
//                  "the loop assigns to the element but the container is `auto`,
//                  not `auto&`."
// THE FIX:         Bind by reference when you intend to mutate:
//                  `for (auto& [key, value] : map)`.
//
// Build & run:  c++ -std=c++17 -Wall 03_rangefor_copy.cpp && ./a.out
#include <iostream>
#include <map>
#include <string>

int main()
{
    std::map<std::string, int> scores{{"alice", 1}, {"bob", 2}, {"carol", 3}};

    // Intent: triple everyone's score in place.
    for (auto [name, score] : scores) {   // <-- by value: 'score' is a copy
        score *= 3;
        (void)name;
    }

    std::cout << "after 'tripling' every score:\n";
    int total = 0;
    for (const auto& [name, score] : scores) {
        std::cout << "  " << name << " = " << score << '\n';
        total += score;
    }
    std::cout << "total = " << total << " (expected 18)\n";

    std::cout << "\n>>> BUG: every score is unchanged. The loop multiplied\n"
              << "    short-lived copies; the map never saw the writes.\n"
              << "    Fix: for (auto& [name, score] : scores)  // add the &\n";
    return 0;
}
