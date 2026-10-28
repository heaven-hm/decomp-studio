// The C runtime shims, checked against the HOST's own implementation.
//
// Every one of these shims exists to reproduce a function the host already has, so the
// host is the oracle: for each input the shim is called and its result compared with
// `strtol`/`strtod`/`strncmp`/... on the same bytes. A shim that disagrees is wrong,
// and this test names the input it disagreed on.
//
// It exists because two shims were found wrong by inspection and neither had a test.
// `strtol` forced base 10 where base 0 must detect the base, so `strtol("0x1f", NULL, 0)`
// returned 0 instead of 31; and the formatter discarded width and precision and had no
// floating-point conversions at all. Both are the kind of thing a comparison against the
// host catches immediately and reading the code does not.

#include "recomp_runtime.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwctype>
#include <string>
#include <vector>

namespace {

int failures = 0;

void check(bool condition, const std::string& what) {
  if (condition) return;
  ++failures;
  std::fprintf(stderr, "FAIL: %s\n", what.c_str());
}

// Writes a guest string and returns its address.
std::uint64_t put_string(std::uint64_t address, const std::string& text) {
  for (std::size_t index = 0; index < text.size(); ++index)
    recomp::store_guest_memory(nullptr, address + index, static_cast<std::uint8_t>(text[index]), 1);
  recomp::store_guest_memory(nullptr, address + text.size(), 0, 1);
  return address;
}

// Reads a guest string.
std::string get_string(std::uint64_t address) {
  std::string text;
  for (std::uint64_t offset = 0; offset < 4096; ++offset) {
    const auto character = static_cast<char>(recomp::load_guest_memory(nullptr, address + offset, 1) & 0xffu);
    if (character == '\0') break;
    text.push_back(character);
  }
  return text;
}

// Calls a shim with up to three integer arguments and returns the result register.
std::uint64_t call(const char* symbol, std::uint64_t a = 0, std::uint64_t b = 0, std::uint64_t c = 0) {
  recomp::GuestContext context{};
  context.registers[4] = 0x700000;
  // The x86-64 Windows convention passes the first four arguments in RCX, RDX, R8 and
  // R9. The register file is positional, so those are indices 1, 2, 8 and 9 -- NOT 1, 2,
  // 3, which is RBX. Getting this wrong made the test report a base of 0 for every
  // `strtol` call and a limit of 0 for every `strncmp`, which looked exactly like a shim
  // bug and was not one.
  context.registers[1] = a;
  context.registers[2] = b;
  context.registers[8] = c;
  // A 32-bit guest passes its arguments on the stack; the shims read them through
  // import_argument, which knows the convention, so the stack form is written too.
  recomp::store_guest_memory(&context, context.registers[4] + 4, a, 4);
  recomp::store_guest_memory(&context, context.registers[4] + 8, b, 4);
  recomp::store_guest_memory(&context, context.registers[4] + 12, c, 4);
  recomp::invoke_shared_shim(&context, "msvcrt.dll", symbol);
  return context.registers[0];
}

}  // namespace

int main() {
  using namespace recomp;
  if (!map_guest_memory(kGuestAddressSpaceBytes)) return 1;
  guest_pointer_width = 8;
  initialize_guest_state(0x100000, 0x70000000, 0x7fff0000);

  // wctype returns a descriptor that is consumed by iswctype; keep the descriptor
  // opaque and verify the pair against the host CRT implementation.
  const auto alpha_name = put_string(0x220000, "alpha");
  const auto guest_alpha = call("wctype", alpha_name);
  const auto host_alpha = std::wctype("alpha");
  check(guest_alpha != 0, "wctype(\"alpha\") returns a descriptor");
  check(call("iswctype", L'A', guest_alpha) ==
            (std::iswctype(L'A', host_alpha) != 0 ? 1u : 0u),
        "iswctype('A', wctype(\"alpha\")) matches the host CRT");
  check(call("iswctype", L'7', guest_alpha) ==
            (std::iswctype(L'7', host_alpha) != 0 ? 1u : 0u),
        "iswctype('7', wctype(\"alpha\")) matches the host CRT");

  // --- strtol, against the host, over the cases that distinguish a real strtol ------
  struct IntegerCase {
    const char* text;
    int base;
  };
  const IntegerCase integer_cases[] = {
      {"0x1f", 0}, {"0X1F", 0}, {"010", 0}, {"10", 0}, {"0", 0}, {"-0x10", 0},
      {"  -42abc", 0}, {"0x1f", 16}, {"777", 8}, {"1011", 2}, {"", 0}, {"abc", 0},
      {"  +17  ", 0}, {"-2147483648", 0}, {"2147483647", 0}, {"zz", 36},
  };
  for (const auto& test : integer_cases) {
    const auto address = put_string(0x200000, test.text);
    const auto end_pointer = 0x210000;
    store_guest_memory(nullptr, end_pointer, 0, 8);
    const auto shimmed = static_cast<std::int64_t>(static_cast<std::int32_t>(
        call("strtol", address, end_pointer, static_cast<std::uint64_t>(test.base))));
    char* host_end = nullptr;
    const auto expected = static_cast<std::int32_t>(std::strtol(test.text, &host_end, test.base));
    check(shimmed == expected,
          std::string("strtol(\"") + test.text + "\", base " + std::to_string(test.base) + ") is " +
              std::to_string(shimmed) + ", the host says " + std::to_string(expected));
    // The end pointer is part of strtol's contract and is what a caller checks to see
    // whether anything was parsed at all.
    const auto shimmed_end = load_guest_memory(nullptr, end_pointer, 8);
    check(shimmed_end == address + static_cast<std::uint64_t>(host_end - test.text),
          std::string("strtol(\"") + test.text + "\") end pointer is " +
              std::to_string(shimmed_end - address) + ", the host says " +
              std::to_string(host_end - test.text));
  }

  // --- strtoul, which must NOT clamp to the signed range ---------------------------
  for (const auto& test : integer_cases) {
    const auto address = put_string(0x200000, test.text);
    const auto shimmed = static_cast<std::uint32_t>(call("strtoul", address, 0, static_cast<std::uint64_t>(test.base)));
    const auto expected = static_cast<std::uint32_t>(std::strtoul(test.text, nullptr, test.base));
    check(shimmed == expected, std::string("strtoul(\"") + test.text + "\") is " + std::to_string(shimmed) +
                                   ", the host says " + std::to_string(expected));
  }

  // --- strtoll/strtoull, where the guest's 64-bit forms must not truncate ------------
  const char* wide_cases[] = {"0x123456789abcdef", "9223372036854775807", "-9223372036854775807", "0"};
  for (const auto* text : wide_cases) {
    const auto address = put_string(0x200000, text);
    const auto shimmed = static_cast<std::int64_t>(call("strtoll", address, 0, 0));
    const auto expected = static_cast<std::int64_t>(std::strtoll(text, nullptr, 0));
    check(shimmed == expected, std::string("strtoll(\"") + text + "\") is " + std::to_string(shimmed) +
                                   ", the host says " + std::to_string(expected));
  }

  // --- strtod/atof, against the host ------------------------------------------------
  const char* float_cases[] = {"1.5", "-2.25e3", "  0.125", "1e-3", "inf", "0x1p4", ".5", "3.", "nan"};
  for (const auto* text : float_cases) {
    const auto address = put_string(0x200000, text);
    const auto bits = call("strtod", address, 0);
    double shimmed = 0;
    std::memcpy(&shimmed, &bits, sizeof(shimmed));
    const auto expected = std::strtod(text, nullptr);
    // A NaN is not equal to itself, so equality is not the test for it; both being NaN is.
    const bool same = (shimmed != shimmed && expected != expected) || shimmed == expected;
    check(same, std::string("strtod(\"") + text + "\") is " + std::to_string(shimmed) + ", the host says " +
                    std::to_string(expected));
    const auto atof_bits = call("atof", address);
    double atof_shimmed = 0;
    std::memcpy(&atof_shimmed, &atof_bits, sizeof(atof_shimmed));
    const auto atof_expected = std::atof(text);
    const bool atof_same = (atof_shimmed != atof_shimmed && atof_expected != atof_expected) ||
                           atof_shimmed == atof_expected;
    check(atof_same, std::string("atof(\"") + text + "\") is " + std::to_string(atof_shimmed) +
                         ", the host says " + std::to_string(atof_expected));
  }

  // --- atoi/atol --------------------------------------------------------------------
  const char* atoi_cases[] = {"0", "42", "  -7", "2147483647", "-2147483648", "abc", "12abc"};
  for (const auto* text : atoi_cases) {
    const auto address = put_string(0x200000, text);
    const auto shimmed = static_cast<std::int32_t>(call("atoi", address));
    check(shimmed == std::atoi(text), std::string("atoi(\"") + text + "\") is " + std::to_string(shimmed) +
                                          ", the host says " + std::to_string(std::atoi(text)));
    const auto long_shimmed = static_cast<std::int32_t>(call("atol", address));
    check(long_shimmed == static_cast<std::int32_t>(std::atol(text)),
          std::string("atol(\"") + text + "\") is " + std::to_string(long_shimmed));
  }

  // --- the string functions, against the host ---------------------------------------
  struct StringCase {
    const char* left;
    const char* right;
  };
  const StringCase string_cases[] = {
      {"", ""}, {"a", ""}, {"", "a"}, {"abc", "abc"}, {"abc", "abd"}, {"abd", "abc"},
      {"abc", "ab"}, {"ab", "abc"}, {"\xff", "\x01"},
  };
  for (const auto& test : string_cases) {
    const auto left = put_string(0x200000, test.left);
    const auto right = put_string(0x201000, test.right);
    const auto sign = [](int value) { return value < 0 ? -1 : value > 0 ? 1 : 0; };
    const auto shimmed = sign(static_cast<std::int32_t>(call("strcmp", left, right)));
    check(shimmed == sign(std::strcmp(test.left, test.right)),
          std::string("strcmp(\"") + test.left + "\", \"" + test.right + "\") is " + std::to_string(shimmed));
    // strncmp must agree with the host for every limit, including limits longer than
    // either string and limits that fall exactly on the terminating NUL.
    for (std::uint64_t limit = 0; limit <= 4; ++limit) {
      const auto shimmed_n = sign(static_cast<std::int32_t>(call("strncmp", left, right, limit)));
      const auto expected_n = sign(std::strncmp(test.left, test.right, static_cast<std::size_t>(limit)));
      check(shimmed_n == expected_n,
            std::string("strncmp(\"") + test.left + "\", \"" + test.right + "\", " + std::to_string(limit) +
                ") is " + std::to_string(shimmed_n) + ", the host says " + std::to_string(expected_n));
    }
    check(static_cast<std::uint64_t>(call("strlen", left)) == std::strlen(test.left),
          std::string("strlen(\"") + test.left + "\") is " +
              std::to_string(call("strlen", left)) + ", the host says " + std::to_string(std::strlen(test.left)));
  }

  // strerror takes one errno argument and returns a guest pointer to CRT-owned
  // storage. The returned pointer must be directly readable by the guest and the
  // ABI must not consume a fictitious destination-buffer argument.
  for (const int error : {0, 2, 13}) {
    const auto result = call("strerror", static_cast<std::uint64_t>(error));
    check(result != 0, "strerror returns a guest pointer");
    check(get_string(result) == std::strerror(error),
          std::string("strerror(") + std::to_string(error) + ") matches the host CRT");
  }

  // Non-v* printf-family entry points receive variadic values inline after their
  // fixed arguments. A value such as 7 must never be interpreted as a va_list
  // pointer (which would read arbitrary guest memory).
  {
    const auto format = put_string(0x240000, "value=%d");
    std::string captured;
    guest_output_capture = &captured;
    check(call("printf", format, 7) == 7, "printf returns bytes written for inline varargs");
    guest_output_capture = nullptr;
    check(captured == "value=7", "printf formats inline integer varargs");

    const auto buffer = 0x250000ull;
    const auto sprintf_format = put_string(0x250100, "hex=%x");
    check(call("sprintf", buffer, sprintf_format, 0x2a) == 6,
          "sprintf returns bytes written for inline varargs");
    check(get_string(buffer) == "hex=2a", "sprintf formats inline integer varargs");
  }

  // --- strcpy/strncpy/strcat, including the padding strncpy is required to do -------
  {
    const auto source = put_string(0x200000, "hello");
    const auto destination = 0x300000;
    call("strcpy", destination, source);
    check(get_string(destination) == "hello", "strcpy did not copy the string");

    // strncpy pads with NUL up to the limit, which is the whole reason it exists and
    // the thing a naive implementation gets wrong.
    for (std::uint64_t limit = 0; limit <= 8; ++limit) {
      for (std::uint64_t offset = 0; offset < 16; ++offset)
        store_guest_memory(nullptr, destination + offset, 0xAA, 1);
      call("strncpy", destination, source, limit);
      char expected[16];
      std::memset(expected, 0xAA, sizeof(expected));
      std::strncpy(expected, "hello", static_cast<std::size_t>(limit));
      bool same = true;
      for (std::uint64_t offset = 0; offset < 16; ++offset)
        if (static_cast<char>(load_guest_memory(nullptr, destination + offset, 1) & 0xffu) != expected[offset])
          same = false;
      check(same, "strncpy with limit " + std::to_string(limit) + " does not match the host");
    }

    put_string(destination, "abc");
    const auto tail = put_string(0x202000, "def");
    call("strcat", destination, tail);
    check(get_string(destination) == "abcdef", "strcat produced '" + get_string(destination) + "'");
  }

  // --- strchr/strrchr/strstr, including the search for the terminating NUL ----------
  {
    const auto text = put_string(0x200000, "abcb");
    const auto base = text;
    check(call("strchr", text, 'b') == base + 1, "strchr did not find the FIRST occurrence");
    check(call("strrchr", text, 'b') == base + 3, "strrchr did not find the LAST occurrence");
    check(call("strchr", text, 'z') == 0, "strchr reported a character that is not there");
    // `strchr(s, 0)` returns a pointer to the terminator, which is a real part of the
    // contract and easy to miss.
    check(call("strchr", text, 0) == base + 4, "strchr for the terminator did not return the end of the string");
    const auto needle = put_string(0x201000, "bc");
    check(call("strstr", text, needle) == base + 1, "strstr did not find the substring");
  }

  if (failures != 0) {
    std::fprintf(stderr, "FAILED: %d C runtime shim check(s) disagreed with the host\n", failures);
    return 1;
  }
  std::printf("PASS: every C runtime shim agrees with the host implementation\n");
  return 0;
}
