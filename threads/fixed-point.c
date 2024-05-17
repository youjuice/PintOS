#include "threads/fixed-point.h"
#include <stdio.h>
#include <stdint.h>

#define FP_UNIT   (1 << 14)

// int 형 -> fp 형
int int_to_fp(int n)	
{
	return n * FP_UNIT;
}

// fp 형 -> int 형
int fp_to_int(int x)
{
	return x / FP_UNIT;
}

// fp 형 -> int 형 (가장 가까운 정수로 변환)
int fp_to_int_round(int x)
{
    if (x >= 0) return (x + FP_UNIT / 2) / FP_UNIT;
    else        return (x - FP_UNIT / 2) / FP_UNIT;
}

// fp 형 + fp 형
int add_fp(int x, int y)
{
    return x + y;
}

// fp 형 + int 형
int add_fp_int(int x, int n)
{
    return x + n * FP_UNIT;
}

// fp 형 - fp 형
int sub_fp(int x, int y)
{
    return x - y;
}

// fp 형 - int 형
int sub_fp_int(int x, int n)
{
    return x - n * FP_UNIT;
}

// fp 형 * fp 형
int multi_fp(int x, int y)
{
    return ((int64_t) x) * y / FP_UNIT;
}

// fp 형 * int 형
int multi_fp_int(int x, int n)
{
    return x * n;
}

// fp 형 / fp 형
int divide_fp(int x, int y)
{
    return ((int64_t) x) * FP_UNIT / y;
}

// fp 형 / int 형
int divide_fp_int(int x, int n)
{
    return x / n;
}