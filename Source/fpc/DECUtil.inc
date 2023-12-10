
{$define SwapUInt32_asm}
function SwapUInt32(Source: UInt32): UInt32;
begin
     result := SwapEndian(Source);
end;

{$define SwapInt64_asm}
function SwapInt64(Source: Int64): Int64;
begin
     result := SwapEndian(Source);
end;


