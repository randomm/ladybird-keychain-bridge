#pragma once

#include <cstdio>

namespace lkb {

inline int& failures() {
    static int n = 0;
    return n;
}

} // namespace lkb

#define EXPECT(cond)                                                                               \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::printf("FAILED %s:%d: %s\n", __FILE__, __LINE__, #cond);                          \
            ++::lkb::failures();                                                                   \
        }                                                                                          \
    } while (0)

#define EXPECT_EQ(a, b) EXPECT((a) == (b))
