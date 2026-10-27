/* 32-bit C++ runtime fixture: a normal C++ program.
 *
 * Unlike the other fixtures this one is built with the real C runtime and
 * libstdc++, so it exercises what a genuine GCC-built Windows program reaches:
 * CRT startup, static initialisation, std::string in both its small-buffer and
 * heap forms, and iostream insertion.
 *
 * The reason it exists is the member-function calling convention. The recompiler
 * modelled every imported function as cdecl or stdcall, so a C++ member
 * function's arguments were read one stack slot late -- `operator<<(int)` was
 * handed `this` where the number should have been, and printed the address of
 * the string literal written just before it. Every line below is an expected
 * value rather than merely "something was printed", so that cannot come back.
 *
 * Checked by value, not differentially: the reference models four Windows
 * imports and none of libstdc++, so it cannot run this program at all. Claiming
 * differential verification here would be claiming something untrue.
 */
#include <iostream>
#include <string>

class Counter {
 public:
  Counter() : value_(0) {}
  void add(int amount) { value_ += amount; }
  int value() const { return value_; }
  void set_label(const char* label) { label_ = label; }
  std::string describe() const { return "counter=" + label_; }

 private:
  int value_;
  std::string label_;
};

int main() {
  std::cout << "cxx:start\n";

  /* std::string small enough to live inside the object. */
  std::string short_text = "abc";
  std::cout << "short_size=" << static_cast<int>(short_text.size()) << "\n";
  std::cout << "short_value=" << short_text << "\n";

  /* Long enough to move to the heap, so both storage forms are exercised. */
  std::string long_text = "a string long enough to leave the local buffer";
  std::cout << "long_size=" << static_cast<int>(long_text.size()) << "\n";
  std::cout << "long_value=" << long_text << "\n";

  std::string copy = long_text;
  std::cout << "copy_matches=" << (copy == long_text ? 1 : 0) << "\n";
  std::string assigned;
  assigned = short_text;
  std::cout << "assigned_value=" << assigned << "\n";

  /* Member functions: `this` in ECX, arguments on the stack. */
  Counter counter;
  counter.add(7);
  counter.add(35);
  std::cout << "member_value=" << counter.value() << "\n";
  counter.set_label("seven");
  std::cout << "member_string=" << counter.describe() << "\n";

  /* The integer overload that used to print an address. */
  std::cout << "stream_int=" << 4242 << "\n";

  std::cout << "cxx:done\n";
  return 0;
}
