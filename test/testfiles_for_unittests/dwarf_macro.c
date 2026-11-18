#define OUTER 1
#include "mfix.h"
#undef OUTER
#define OUTER 2
int value(void) { return OUTER; }
