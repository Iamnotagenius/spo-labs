#ifndef HEADER_MACROS
#define HEADER_MACROS

#define VA_NARGS_IMPL(_1, _2, _3, _4, _5, N, ...) N
#define VA_NARGS(...) VA_NARGS_IMPL(__VA_ARGS__, 5, 4, 3, 2, 1)

#define FOO_IMPL2(func, var, count, ...) COMP ## count(func, var, __VA_ARGS__)
#define FOO_IMPL(func, var, count, ...) FOO_IMPL2(func, var, count, __VA_ARGS__) 

#define FOO_IMPLN2(func, var, count, ...) COMPN ## count(func, var, __VA_ARGS__)
#define FOO_IMPLN(func, var, count, ...) FOO_IMPLN2(func, var, count, __VA_ARGS__) 

#define ONE_OF(func, var, ...) FOO_IMPL(func, var, VA_NARGS(__VA_ARGS__), __VA_ARGS__)
#define ONE_OF_NCMP(func, var, ...) FOO_IMPLN(func, var, VA_NARGS(__VA_ARGS__), __VA_ARGS__)
#define ONE_OF_CALL(var, func, ...) FOO_IMPL(var->func, var, VA_NARGS(__VA_ARGS__), __VA_ARGS__)

#define COMP(func, var, str) func(var, str) == 0
#define COMP1(func, var, str, ...) COMP(func, var, str)
#define COMP2(func, var, str, ...) COMP(func, var, str) || COMP1(func, var, __VA_ARGS__)
#define COMP3(func, var, str, ...) COMP(func, var, str) || COMP2(func, var, __VA_ARGS__)
#define COMP4(func, var, str, ...) COMP(func, var, str) || COMP3(func, var, __VA_ARGS__)
#define COMP5(func, var, str, ...) COMP(func, var, str) || COMP4(func, var, __VA_ARGS__)
#define COMP6(func, var, str, ...) COMP(func, var, str) || COMP5(func, var, __VA_ARGS__)
#define COMP7(func, var, str, ...) COMP(func, var, str) || COMP6(func, var, __VA_ARGS__)
#define COMP8(func, var, str, ...) COMP(func, var, str) || COMP7(func, var, __VA_ARGS__)
#define COMP9(func, var, str, ...) COMP(func, var, str) || COMP8(func, var, __VA_ARGS__)
#define COMP10(func, var, str, ...) COMP(func, var, str) || COMP9(func, var, __VA_ARGS__)
#define COMP11(func, var, str, ...) COMP(func, var, str) || COMP10(func, var, __VA_ARGS__)
#define COMP12(func, var, str, ...) COMP(func, var, str) || COMP11(func, var, __VA_ARGS__)
#define COMP13(func, var, str, ...) COMP(func, var, str) || COMP12(func, var, __VA_ARGS__)
#define COMP14(func, var, str, ...) COMP(func, var, str) || COMP13(func, var, __VA_ARGS__)
#define COMP15(func, var, str, ...) COMP(func, var, str) || COMP14(func, var, __VA_ARGS__)
#define COMP16(func, var, str, ...) COMP(func, var, str) || COMP15(func, var, __VA_ARGS__)

#define COMPN(func, var, str) func(var, str, sizeof(str)) == 0
#define COMPN1(func, var, str, ...) COMPN(func, var, str)
#define COMPN2(func, var, str, ...) COMPN(func, var, str) || COMPN1(func, var, __VA_ARGS__)
#define COMPN3(func, var, str, ...) COMPN(func, var, str) || COMPN2(func, var, __VA_ARGS__)
#define COMPN4(func, var, str, ...) COMPN(func, var, str) || COMPN3(func, var, __VA_ARGS__)
#define COMPN5(func, var, str, ...) COMPN(func, var, str) || COMPN4(func, var, __VA_ARGS__)
#define COMPN6(func, var, str, ...) COMPN(func, var, str) || COMPN5(func, var, __VA_ARGS__)
#define COMPN7(func, var, str, ...) COMPN(func, var, str) || COMPN6(func, var, __VA_ARGS__)
#define COMPN8(func, var, str, ...) COMPN(func, var, str) || COMPN7(func, var, __VA_ARGS__)
#define COMPN9(func, var, str, ...) COMPN(func, var, str) || COMPN8(func, var, __VA_ARGS__)
#define COMPN10(func, var, str, ...) COMPN(func, var, str) || COMPN9(func, var, __VA_ARGS__)
#define COMPN11(func, var, str, ...) COMPN(func, var, str) || COMPN10(func, var, __VA_ARGS__)
#define COMPN12(func, var, str, ...) COMPN(func, var, str) || COMPN11(func, var, __VA_ARGS__)
#define COMPN13(func, var, str, ...) COMPN(func, var, str) || COMPN12(func, var, __VA_ARGS__)
#define COMPN14(func, var, str, ...) COMPN(func, var, str) || COMPN13(func, var, __VA_ARGS__)
#define COMPN15(func, var, str, ...) COMPN(func, var, str) || COMPN14(func, var, __VA_ARGS__)
#define COMPN16(func, var, str, ...) COMPN(func, var, str) || COMPN15(func, var, __VA_ARGS__)

#define CALL(var, func, ...) var->func(var, ##__VA_ARGS__)
#define CALL2(var, func, ...) var->func(var, ##__VA_ARGS__)
#define CALL3(var, func, ...) var->func(var, ##__VA_ARGS__)
#define CALL4(var, func, ...) var->func(var, ##__VA_ARGS__)
#define CALL5(var, func, ...) var->func(var, ##__VA_ARGS__)

#define CAST_CALL(type, var, func, ...) ((type)var->func(var, ##__VA_ARGS__))
#define CAST_CALL2(type, var, func, ...) ((type)var->func(var, ##__VA_ARGS__))
#define CAST_CALL3(type, var, func, ...) ((type)var->func(var, ##__VA_ARGS__))
#define CAST_CALL4(type, var, func, ...) ((type)var->func(var, ##__VA_ARGS__))
#define CAST_CALL5(type, var, func, ...) ((type)var->func(var, ##__VA_ARGS__))

#define CHAIN2(var, func, ...) CALL(CALL(var, func), ##__VA_ARGS__)
#define CHAIN3(var, func, ...) CHAIN2(CALL(var, func), ##__VA_ARGS__)
#define CHAIN4(var, func, ...) CHAIN3(CALL(var, func), ##__VA_ARGS__)
#define CHAIN5(var, func, ...) CHAIN4(CALL(var, func), ##__VA_ARGS__)

#define SET_FLAG(flag, bit, some_test) \
    ((some_test) ? ((flag) |= bit) : ((flag) &= ~bit))

#endif
