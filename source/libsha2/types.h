#ifndef SHA2TYPES_H
#define SHA2TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char uchar;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned long long uvlong;

typedef struct Uvvlong Uvvlong;
struct Uvvlong {
 uvlong	hi, lo;
};

#define nil	NULL
#define nelem(v)	(sizeof (v)/sizeof ((v)[0]))

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif
