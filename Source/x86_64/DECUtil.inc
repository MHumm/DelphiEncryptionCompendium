{$ifdef FPC}
{$ASMMODE intel}
{$endif}

{$ifndef SwapUInt32_asm}
{$define SwapUInt32_asm}
function SwapUInt32(Source: UInt32): UInt32;
asm
  .NOFRAME
  // Win64: UInt32 arrives in ECX and the result is returned in EAX.
  // A 32-bit move and BSWAP zero-extends into RAX. Leaf: no calls.
  MOV EAX, ECX
  BSWAP EAX
  RET
end;
{$endif}

{$ifndef SwapInt64_asm}
{$define SwapInt64_asm}
function SwapInt64(Source: Int64): Int64;
asm
  .NOFRAME
  // Win64: Int64 arrives in RCX and the result is returned in RAX.
  // BSWAP of the full register matches the Pascal half-swap (see DECUtil.pas).
  MOV RAX, RCX
  BSWAP RAX
  RET
end;
{$endif}


