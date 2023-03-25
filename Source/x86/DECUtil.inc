{$ifdef FPC}
{$ASMMODE intel}
{$endif}

{$define SwapUInt32_asm}
function SwapUInt32(Source: UInt32): UInt32;
asm
    BSWAP EAX
end;

{$define SwapUInt64_asm}
function SwapInt64(Source: Int64): Int64;
asm
      MOV     EDX,Source.DWord[0]
      MOV     EAX,Source.DWord[4]
      BSWAP   EDX
      BSWAP   EAX
end;
