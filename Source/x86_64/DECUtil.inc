{$ifdef FPC}
{$ASMMODE intel}
{$endif}

{$ifndef SwapUInt32_asm}
{$define SwapUInt32_asm}
function SwapUInt32(Source: UInt32): UInt32;
asm
    MOV   RAX, Source
    BSWAP RAX
    SHR   RAX, 32
end;
{$endif}

{$ifndef SwapInt64_asm}
{$define SwapInt64_asm}
function SwapInt64(Source: Int64): Int64;
asm
    MOV   RAX, Source
    BSWAP RAX
end;
{$endif}


