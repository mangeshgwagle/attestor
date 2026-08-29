// THE BUG:         Object slicing -- storing a derived object in a container of
//                  the base type copies only the base sub-object and throws the
//                  derived part away.
// WHY IT'S MISSED: The code compiles without a single warning, the push_back
//                  looks ordinary, and virtual dispatch is something you *trust*
//                  to "just work". But `std::vector<Shape>` stores `Shape` by
//                  value. When you push a `Circle`, the copy constructor of
//                  `Shape` runs and silently slices off everything that made it a
//                  Circle -- including which vtable it points at. Every later
//                  `shape.area()` calls `Shape::area`, not `Circle::area`. The
//                  numbers are wrong, the types are gone, and nothing complains.
// HOW TO DETECT:   No standard warning. clang-tidy has no dedicated check either;
//                  the structural tell is "a container of a polymorphic base type
//                  held by value." Making the base abstract (a pure virtual
//                  method) turns the slice into a *compile error*.
// THE FIX:         Store pointers, not values: std::vector<std::unique_ptr<Shape>>
//                  (or std::shared_ptr). Polymorphism requires a pointer or
//                  reference to the base; a by-value copy can never be virtual.
//
// Build & run:  c++ -std=c++17 -Wall 02_object_slicing.cpp && ./a.out
#include <iostream>
#include <vector>
#include <memory>

struct Shape {
    virtual double area() const { return 0.0; }
    virtual const char* name() const { return "Shape"; }
    virtual ~Shape() = default;
};

struct Circle : Shape {
    double r;
    explicit Circle(double radius) : r(radius) {}
    double area() const override { return 3.141592653589793 * r * r; }
    const char* name() const override { return "Circle"; }
};

int main()
{
    std::vector<Shape> shapes;     // <-- by value: the slicing trap
    shapes.push_back(Circle{2.0}); // the Circle is sliced down to a bare Shape

    std::cout << "stored a Circle of radius 2 (area should be ~12.566)\n";
    std::cout << "shapes[0].name() = " << shapes[0].name() << '\n';
    std::cout << "shapes[0].area() = " << shapes[0].area() << '\n';

    std::cout << "\n>>> BUG: it reports '" << shapes[0].name() << "' with area "
              << shapes[0].area() << ".\n"
              << "    The Circle was sliced into a Shape on push_back; the\n"
              << "    override and the radius are gone.\n";

    // THE FIX -- hold the base by pointer so dispatch stays virtual:
    //   std::vector<std::unique_ptr<Shape>> shapes;
    //   shapes.push_back(std::make_unique<Circle>(2.0));
    //   shapes[0]->area();   // -> 12.566
    return 0;
}
