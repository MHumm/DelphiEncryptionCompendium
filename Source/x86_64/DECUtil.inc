{$ifdef FPC}
{$ASMMODE intel}
{$endif}

{$define SwapUInt32_asm}
function SwapUInt32(Source: UInt32): UInt32;
asm
    MOV   RAX, Source
    BSWAP RAX
    SHR   RAX, 32
end;

{$define SwapInt64_asm}
function SwapInt64(Source: Int64): Int64;
asm
    MOV   RAX, Source
    BSWAP RAX
end;
