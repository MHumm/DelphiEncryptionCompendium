{$ifdef FPC}
{$ASMMODE intel}
{$endif}

{$ifndef SwapUInt32_asm}
{$define SwapUInt32_asm}
function SwapUInt32(Source: UInt32): UInt32;
asm
    BSWAP EAX
end;
{$endif}

{$ifndef SwapInt64_asm}
{$define SwapInt64_asm}
function SwapInt64(Source: Int64): Int64;
asm
      MOV     EDX,Source.DWord[0]
      MOV     EAX,Source.DWord[4]
      BSWAP   EDX
      BSWAP   EAX
end;
{$endif}

