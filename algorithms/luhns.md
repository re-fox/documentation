# Introduction 

I’ve been researching different variants of the Luhn algorithm while building Capa signatures.  This is simply my collection of notes that I’ve been keeping while researching malware.   

This isn’t intended to dive in on how the Luhn formula works, rather to provide RE notes and show reference implementations.  I would recommend reading https://en.wikipedia.org/wiki/Luhn_algorithm to understand the internals. 

Malware authors typically include a version of Luhn's to reduce the number of false positives they get when scraping memory of a victim machine.  Scanning for 16-digit numbers will yield many false positives and Luhn's provides a nice filter.  However, it’s not entirely foolproof, there are plenty of number combinations that are not valid credit card numbers that will pass the checksum.  It is usually paired with other validation routines to produce a high-fidelity list of CC numbers. 

Some malware families will use a combination of regex and custom routines in absence of Luhn's. There are no guarantees on the existence (or lack of) Luhn's when looking at malware that targets CC numbers. 

# Digit Sums
A quick note on digit sums. The digit sum used in Luhn's is performed when you multiply a `number*2` and the product is `> 9`.  Some implementations will perform the steps to calculate those numbers and other implementations will use a lookup table. 

It can be a bit confusing when finding a lookup table for the first time and understanding how the numbers are calculated.

A credit card consists of single digit numbers so a quick lookup table (0-9) can be built.

Consider the following python code:
```
def digital_root(num):
    num *= 2
    if num > 9:
        num = 1 + (num - 1) % 9
    return num

for i in range(0,10,1):
    print("%d = %d" % (i, digital_root(i)))
```
Which will build the following table of `number*2` and the digit sum
```
0 = 0
1 = 2
2 = 4
3 = 6
4 = 8
5 = 1
6 = 3
7 = 5
8 = 7
9 = 9
```


# Implementations 

From Rosetta Code (https://www.rosettacode.org/wiki/Luhn_test_of_credit_card_numbers), a C implementation of Luhns looks like the following:  

```c
int luhn(const char* cc)
{
	const int m[] = {0,2,4,6,8,1,3,5,7,9}; // mapping for rule 3
	int i, odd = 1, sum = 0;
 
	for (i = strlen(cc); i--; odd = !odd) {
		int digit = cc[i] - '0';
		sum += odd ? digit : m[digit];
	}
 
	return sum % 10 == 0;
}
```
This utilizes a lookup table, rather than calculating the digit sum.  

The source code of the Dexter malware family borrows directly from this implementation. 

From (https://github.com/nyx0/Dexter/blob/efe615e7bec4628c4550816b0c5f50fc0c03264f/source/POSGrabber.c#L449)
```c
int IsValidCC(const char* cc,int CClen)
{
	const int m[] = {0,2,4,6,8,1,3,5,7,9}; 
	int i, odd = 1, sum = 0;
 
	for (i = CClen; i--; odd = !odd) {
		int digit = cc[i] - '0';
		sum += odd ? digit : m[digit];
	}
	return sum % 10 == 0;
}
```

## Exploring some variations 

### 255daa6722de6ad03545070dfbef3330 / MMON 

The following is the decompiled function output at `0x00401f30`
```c
bool __cdecl FUN_00401f30(char *param_1)

{
  char cVar1;
  bool bVar2;
  ushort uVar3;
  int iVar4;
  char *pcVar5;
  undefined2 extraout_var;
  int iVar6;
  
  iVar4 = 0;
  while (param_1[iVar4] == '0') {
    iVar4 = iVar4 + 1;
    if (0xf < iVar4) {
      return false;
    }
  }
  if (param_1 != (char *)0x0) {
    pcVar5 = param_1;
    do {
      cVar1 = *pcVar5;
      pcVar5 = pcVar5 + 1;
    } while (cVar1 != '\0');
    if (pcVar5 + -(int)(param_1 + 1) + -0xd < (char *)0x7) {
      pcVar5 = pcVar5 + -(int)(param_1 + 1) + -1;
      bVar2 = false;
      iVar4 = 0;
      if (-1 < (int)pcVar5) {
        do {
          uVar3 = FUN_0040bf90((int)param_1[(int)pcVar5]);
          if (CONCAT22(extraout_var,uVar3) == 0) {
            return false;
          }
          iVar6 = param_1[(int)pcVar5] + -0x30;
          if ((bVar2) && (iVar6 = iVar6 * 2, 9 < iVar6)) {
            iVar6 = iVar6 + (iVar6 / 10) * -10 + 1;
          }
          bVar2 = !bVar2;
          pcVar5 = pcVar5 + -1;
          iVar4 = iVar4 + iVar6;
        } while (pcVar5 < (char *)0x80000000);
      }
      return (bool)('\x01' - (iVar4 % 10 != 0));
    }
    return false;
  }
  return false;
}
```
At a high level there are several key steps.  

The numbers are iterated over in a loop.  Each number is then converted to its ASCII value for calcuation. This is done by subtracting 0x30.  

If this is confusing, consider the following python snippet. 
```python
>>> ord('9') - 0x30 
9 
```

The variable `bVar2` is keeping track of even and odd numbers.  

While the digit sum is being explictally computed via the following:
```c
if ((bVar2) && (iVar6 = iVar6 * 2, 9 < iVar6)) {
  iVar6 = iVar6 + (iVar6 / 10) * -10 + 1;
}
```

Once the checksum is calculated, the negative of the result `% 10` is returned.   

In short, this example didn't utilize a lookup table and explicitly calculated digit sums. 


### ce0296e2d77ec3bb112e270fc260f274 / MMON version 2

The following is the decompiled code from `0x00403f70`

```c
undefined8 __cdecl FUN_00403f70(uint *param_1)

{
  uint *puVar1;
  int iVar2;
  undefined4 extraout_ECX;
  undefined4 *puVar3;
  undefined8 uVar4;
  uint uVar5;
  undefined4 local_118 [49];
  int local_54;
  uint *local_48;
  int local_3c;
  int local_30 [4];
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 uStack8;
  
  iVar2 = 0x45;
  puVar3 = local_118;
  while (iVar2 != 0) {
    iVar2 = iVar2 + -1;
    *puVar3 = 0xcccccccc;
    puVar3 = puVar3 + 1;
  }
  local_30[0] = 0;
  local_30[1] = 1;
  local_30[2] = 2;
  local_30[3] = 3;
  local_20 = 4;
  local_1c = 0xfffffffc;
  local_18 = 0xfffffffd;
  local_14 = 0xfffffffe;
  local_10 = 0xffffffff;
  local_c = 0;
  local_3c = 0;
  local_48 = FUN_00417dc0(param_1);
  while (local_48 = (uint *)((int)local_48 + -1), local_48 < (uint *)0x80000000) {
    local_54 = *(char *)((int)param_1 + (int)local_48) + -0x30;
    local_3c = local_3c + local_54;
    puVar1 = FUN_00417dc0(param_1);
    if ((uint)((int)local_48 - (int)puVar1) % 2 == 0) {
      local_3c = local_3c + local_30[local_54];
    }
  }
  uVar5 = (uint)(local_3c % 10 == 0);
  FUN_00416c30((int)&stack0xfffffffc,(int *)&DAT_0040407c);
  uStack8 = 0x404078;
  uVar4 = FUN_00416c00(extraout_ECX,uVar5);
  return uVar4;
}

```

In this version of MMON the author uses a variation of the traditional lookup table.  

Rather than calculating the digit sum, the values are added to a running total depending on the even/odd state. This final number is checked with a `% 10`.

The negative numbers in the lookup table can be confusing. This can be validated with python:

```python
def digital_root(num):
    lookup_tbl = [0,1,2,3,4,-4,-3,-2,-1,0]
    return lookup_tbl[num] + num

for i in range(0,10,1):
    print("%d = %d" % (i, digital_root(i)))

```
Which will show that the logic maps back to the original lookup table
```
0 = 0
1 = 2
2 = 4
3 = 6
4 = 8
5 = 1
6 = 3
7 = 5
8 = 7
9 = 9
```

This simple variation is important to consider if the signature being used is depending on constants.

### 7f9cdc380eeed16eaab3e48d59f271aa / MMON (again)

The following is the decompiled code from `0x004012d0`

```c
undefined8 __fastcall FUN_004012d0(undefined4 param_1,uint param_2,uint *param_3)

{
  uint uVar1;
  int iVar2;
  int extraout_ECX;
  int extraout_ECX_00;
  uint extraout_EDX;
  uint extraout_EDX_00;
  undefined4 *puVar3;
  undefined8 uVar4;
  undefined4 local_f4 [49];
  int local_30;
  uint local_24;
  uint *local_18;
  uint *local_c;
  undefined4 uStack8;
  
  iVar2 = 0x3c;
  puVar3 = local_f4;
  while (iVar2 != 0) {
    iVar2 = iVar2 + -1;
    *puVar3 = 0xcccccccc;
    puVar3 = puVar3 + 1;
  }
  if (((param_3 != (uint *)0x0) &&
      (local_c = FUN_00417660(param_3), iVar2 = extraout_ECX, param_2 = extraout_EDX,
      0xc < (int)local_c)) && ((int)local_c < 0x14)) {
    local_24 = 0;
    local_30 = 0;
    local_18 = local_c;
    while (local_18 = (uint *)((int)local_18 + -1), local_18 < (uint *)0x80000000) {
      uVar1 = FUN_00417380((int)*(char *)((int)param_3 + (int)local_18));
      iVar2 = extraout_ECX_00;
      param_2 = extraout_EDX_00;
      if (uVar1 == 0) goto LAB_004013bc;
      local_c = (uint *)(*(char *)((int)param_3 + (int)local_18) + -0x30);
      if ((local_24 != 0) && (local_c = (uint *)((int)local_c * 2), 9 < (int)local_c)) {
        local_c = (uint *)((int)local_c % 10 + 1);
      }
      local_24 = (uint)(local_24 == 0);
      local_30 = local_30 + (int)local_c;
    }
    iVar2 = 10;
    param_2 = (uint)(local_30 % 10 == 0);
  }
LAB_004013bc:
  uStack8 = 0x4013cc;
  uVar4 = FUN_004170e0(iVar2,param_2);
  return uVar4;
}
```

This variant is very similar to the version in `255daa6722de6ad03545070dfbef3330`, however there is a slight difference in the digital sum calcuation.  

In this version:
```c
if ((local_24 != 0) && (local_c = (uint *)((int)local_c * 2), 9 < (int)local_c)) {
  local_c = (uint *)((int)local_c % 10 + 1);
}
```
Whereas in `255daa6722de6ad03545070dfbef3330` the digital sum calcuation is
```c
if ((bVar2) && (iVar6 = iVar6 * 2, 9 < iVar6)) {
  iVar6 = iVar6 + (iVar6 / 10) * -10 + 1;
}
```

The differences (ignoring any variable casting) show a slight but an important difference when building signatures.  

In my personal opinion `(number % 10 + 1)` is a more straightforward calcuation.


### 261532875decea7471fb673afd12092a / POSeidon

The following is the decompiled code from `0x004027ab`

```c
undefined4 __fastcall FUN_004027ab(char *param_1,uint param_2)

{
  uint uVar1;
  undefined4 uVar2;
  char cVar3;
  uint uVar4;
  char *pcVar5;
  int iVar6;
  bool bVar7;
  
  iVar6 = 0;
  uVar4 = 0;
  if (param_2 != 0) {
    pcVar5 = param_1 + (param_2 - 1);
    do {
      cVar3 = *pcVar5 + -0x30;
      uVar1 = uVar4 & 0x80000001;
      bVar7 = uVar1 == 0;
      if ((int)uVar1 < 0) {
        bVar7 = (uVar1 - 1 | 0xfffffffe) == 0xffffffff;
      }
      if ((!bVar7) && (cVar3 = cVar3 * '\x02', '\t' < cVar3)) {
        cVar3 = cVar3 + -9;
      }
      iVar6 = iVar6 + cVar3;
      uVar4 = uVar4 + 1;
      pcVar5 = pcVar5 + -1;
    } while (uVar4 < param_2);
  }
  if ((((iVar6 % 10 == 0) && ((cVar3 = *param_1, cVar3 != '3' || (param_2 == 0xf)))) &&
      ((cVar3 != '6' || (param_2 == 0x10)))) &&
     (((cVar3 != '5' || (param_2 == 0x10)) && ((cVar3 != '4' || (param_2 == 0x10)))))) {
    uVar2 = 1;
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}
```

This variation calcuates the digit sum by multiplying by 2 and adding -9. As seen here:
```c
if ((!bVar7) && (cVar3 = cVar3 * '\x02', '\t' < cVar3)) {
  cVar3 = cVar3 + -9;
}
```
It's another small detail that could toss a signature off.

Another interesting attribute is the additional check (after the Luhn checksum) if the digits of the potential CC number begins with a 3,4,5 or 6.  Which is an attempt to filter out the following cards:
```
3 - Travel/Entertainment cards
4 - Visa
5 - MasterCard
6 - Discover Card
```

### d1b675011623c4b0db906d63889390f6 / FrameworkPOS

The following is the decompiled function output at `0x00403210`
```c
void __cdecl FUN_00403210(uint *param_1)

{
  bool bVar1;
  int local_4c;
  int local_3c;
  uint *local_34;
  int local_30 [4];
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  uint local_8;
  
  local_8 = DAT_0042e408 ^ (uint)&stack0xfffffffc;
  local_30[0] = 0;
  local_30[1] = 2;
  local_30[2] = 4;
  local_30[3] = 6;
  local_20 = 8;
  local_1c = 1;
  local_18 = 3;
  local_14 = 5;
  local_10 = 7;
  local_c = 9;
  bVar1 = true;
  local_3c = 0;
  local_34 = FUN_0040b1a0(param_1);
  while (local_34 != (uint *)0x0) {
    local_4c = *(char *)((int)param_1 + (int)(uint *)((int)local_34 + -1)) + -0x30;
    if (!bVar1) {
      local_4c = local_30[local_4c];
    }
    local_3c = local_3c + local_4c;
    bVar1 = !bVar1;
    local_34 = (uint *)((int)local_34 + -1);
  }
  FUN_0040d32c(local_8 ^ (uint)&stack0xfffffffc,(char)(local_3c % 10),0);
  return;
}

```

The version of Luhn's that is compiled into Framework very much resembles the Dexter/Rosetta code version.

No digit sum is calculated and the lookup table of `{0,2,4,6,8,1,3,5,7,9}` is used.

# Conclusions
In these samples the primary difference seemed to be revolving around the calculation of the digit sum.  There were several different methods and variations of lookup tables.  

|Sample|Lookup Table|Digit Sum Method|
|---|---|---|
|`261532875decea7471fb673afd12092a`||`number*2 -9`|
|`255daa6722de6ad03545070dfbef3330`||`(number*2) + (number*2/10) * -10 + 1`|
|`ce0296e2d77ec3bb112e270fc260f274`|`{0,1,2,3,4,-4,-3,-2,-1,0}`| |
|`d1b675011623c4b0db906d63889390f6`|`{0,2,4,6,8,1,3,5,7,9}`||
|`7f9cdc380eeed16eaab3e48d59f271aa`||`number % 10 + 1`|

This is not intended to be an exhaustive list, rather an exploration of some of the variations ITW.

The examples in this post had one distinct advantage for signature writers - The implementation of Luhn’s was its own separate function.  Which makes analysis clean and easy to understand. In some malware families like FastPOS or AbaddonPOS, parts of the algorithm can be peppered in the middle of a function that is also hunting through memory and finding candidate numbers. When writing Capa signatures it is important to be cognizant of the scope of a function and basic blocks. 

With any language, there exists countless ways to compute a checksum or solve any arbitrary problem.  To find more variations, try compiling the Rosetta Code implementation using Clang or different GCC optimization levels.  The Godbolt compiler explorer is a great tool for this exercise (https://godbolt.org/). Depending on the compiler it may make some choices which seem unexpected.  Use these to test and make sure signatures are resilient and can hold up to different variations. 


Another solution is to consider code lifting utilities like RetDec, BinaryNinja's MLIL/HLIL or Ghidra's Decompiler to normalize the operations and remove some opcode variations that can exist at the lowest level. 
