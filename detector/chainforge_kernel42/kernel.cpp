// kernel.cpp -- ChainForge 4.2 fixed-point kernel self-check.
//
// Companion to chainforge_kernel_x86_64.asm and detector/chainforge42.py.
// Computes the same linear equations in plain C++ and verifies the shipped
// EXPECTED_VECTORS. This binary is built ONLY by the explicit opt-in
// `chainforge42.py kernel-check` gate when a compiler is present; it is
// never part of the analysis path.
//
// Build: g++ -O2 -std=c++17 kernel.cpp -o kernel_selfcheck

#include <cstdint>
#include <cstdio>

static const uint64_t kWeightsQ16[5] = {22938, 16384, 13107, 6554, 6554};
static const uint64_t kFeaturesSample[5] = {1000000, 500000, 800000,
                                            250000, 400000};
static const uint64_t kDotExpectedShifted = 699932ULL;
static const uint64_t kAlphaQ16 = 55706ULL;
static const uint64_t kOneMinusAlphaQ16 = 9830ULL;

// score(c) = sum_i w[i]*f[i], then arithmetic shift right by 16.
static uint64_t Dot5Q16(const uint64_t* w, const uint64_t* f) {
  uint64_t acc = 0;
  for (int i = 0; i < 5; ++i) {
    acc += w[i] * f[i];  // the SUM of the linear form
  }
  return acc >> 16;      // fixed-point rescale
}

// y[i] += a * x[i] -- one power-iteration row update.
static void SaxpyQ16(uint64_t* y, const uint64_t* x, uint64_t a, int n) {
  for (int i = 0; i < n; ++i) {
    y[i] += a * x[i];
  }
}

// acc' = acc + one_minus_alpha * s / 2^16.
static uint64_t BlendSeed(uint64_t acc, uint64_t s, uint64_t one_minus_alpha) {
  return acc + ((one_minus_alpha * s) >> 16);
}

int main() {
  int failures = 0;

  const uint64_t dot = Dot5Q16(kWeightsQ16, kFeaturesSample);
  if (dot != kDotExpectedShifted) {
    std::printf("FAIL dot5_q16 got=%llu want=%llu\n",
                static_cast<unsigned long long>(dot),
                static_cast<unsigned long long>(kDotExpectedShifted));
    ++failures;
  } else {
    std::printf("PASS dot5_q16 = %llu\n",
                static_cast<unsigned long long>(dot));
  }

  if (kAlphaQ16 + kOneMinusAlphaQ16 == 1ULL << 16) {
    std::printf("PASS alpha + (1-alpha) == 2^16\n");
  } else {
    std::printf("FAIL alpha split\n");
    ++failures;
  }

  uint64_t y[3] = {100, 200, 300};
  const uint64_t x[3] = {10, 20, 30};
  SaxpyQ16(y, x, 3, 3);
  if (y[0] == 130 && y[1] == 260 && y[2] == 390) {
    std::printf("PASS saxpy_q16\n");
  } else {
    std::printf("FAIL saxpy_q16\n");
    ++failures;
  }

  const uint64_t blended = BlendSeed(500, 40, kOneMinusAlphaQ16);
  if (blended == 500 + ((9830ULL * 40) >> 16)) {
    std::printf("PASS blend_seed = %llu\n",
                static_cast<unsigned long long>(blended));
  } else {
    std::printf("FAIL blend_seed got=%llu\n",
                static_cast<unsigned long long>(blended));
    ++failures;
  }

  return failures == 0 ? 0 : 1;
}
