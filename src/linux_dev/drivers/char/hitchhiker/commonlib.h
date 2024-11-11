/**
 * macros
 */
#define str_temp(x)                          #x
#define str(x)                               str_temp(x)

// #define min(x, y)                            ((x) < (y) ? (x) : (y))
// #define max(x, y)                            ((x) > (y) ? (x) : (y))
#define concat_temp(x, y)                    x ## y
#define concat(x, y)                         concat_temp(x, y)
#define concat3(x, y, z)                     concat(concat(x, y), z)

#define MAP(c, f)                            c(f)