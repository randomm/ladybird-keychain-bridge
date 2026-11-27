#include "testing/TestAssert.h"

int main() {
    EXPECT(true);
    EXPECT_EQ(2 + 2, 4);
    return ::lkb::failures();
}
