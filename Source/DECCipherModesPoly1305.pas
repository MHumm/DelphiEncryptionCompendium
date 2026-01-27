{*****************************************************************************
  The DEC team (see file NOTICE.txt) licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License. A copy of this licence is found in the root directory
  of this project in the file LICENCE.txt or alternatively at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
*****************************************************************************}

unit DECCipherModesPoly1305;

interface

{$INCLUDE DECOptions.inc}

uses
  {$IFDEF FPC}
  SysUtils,
  {$ELSE}
  System.SysUtils,
  {$ENDIF}
  DECTypes, DECAuthenticatedCipherModesBase;

// ###########################################
// #### The implementation follows the openssl poly1305 one
// on https://github.com/openssl/openssl/blob/master/crypto/poly1305/poly1305.c
// the avx optimization is based on https://github.com/Sreyosi/Improved-SIMD-Implementation-of-Poly1305/
type
  T32ByteArray = Array[0..31] of Byte; // 0 - 16: key, 17-32 nonce
  TPoly1305CpuMode = (pmPas, pmAVX);
type
  TPoly1305 = class(TAuthenticatedCipherModesBase)
  private
    const POLY1305_BLOCK_SIZE = 16;
          POLY1305_DIGEST_SIZE = 16;
          POLY1305_KEY_SIZE = 32;
    type
      TPoly1305Nonce = Array[0..3] of UInt32;
      PPoly1305Nonce = ^TPoly1305Nonce;
      TPoly1305BlockMethod = procedure ( pData : PByteArray; size : integer ) of Object;
      TPoly1305EmitMethod = procedure( var mac: TBlock16Byte ) of Object;
      TPoly1305PadAndFinalize = procedure( authLen, encDecBufLen : int64) of Object;
      THArr = Array[0..4] of UInt32;
      PHArr = ^THArr;
      TRArr = Array[0..3] of UInt32;
      PRArr = ^TRArr;

      TStateAVXArr = Array[0..4] of UInt64;
      T4UInt64 = Array[0..3] of UInt64;
      P4UInt64 = ^T4UInt64;
      T2UInt64 = Array[0..1] of UInt64;
      P2UInt64 = ^T2UInt64;

      PStateAVXArr = ^TStateAVXArr;

      TPoly1305CTX = packed record
        r : TStateAVXArr;
        rr : TStateAVXArr;
        k0, k1, k2, k3, k4 : T4UInt64;  // 4-lane kernels for H0..H3
        k0_5, k1_5, k2_5, k3_5, k4_5 : UInt64; // scalar 5th term multiplier
        h : TStateAVXArr;
        s0, s1 : UInt64;     // nonce
      end;
      PPoly1305CTX = ^TPoly1305CTX;

      TPoly1305State = Array[0..431] of Byte;    // sizeof(TPoly1305Ctx) + 2*xmm register size + 64 alignment bytes

  private
    /// <summary>
    ///   buffer for h and R and other precomputed values. The buffer is shared between
    ///   the pure pascal and the AVX implementation
    /// </summary>
    fPoly1305State : TPoly1305State;

    /// <summary>
    ///   H and R values. These point ot the fPoly1305State buffer
    /// </summary>
    FH : PHArr;
    FR : PRArr;

    /// <summary>
    ///   AVX2 optimized buffers. These point ot the fPoly1305State buffer
    /// </summary>
    fAVXCtx : PPoly1305CTX;
    fXMMMem : PUint64;

    /// <summary>
    /// Initialization vector and nonce - initialized from the 32Byte init vector
    /// </summary>
    fIV : T32ByteArray;
    FNonce : TPoly1305Nonce;

    /// <summary>
    /// Internal state variables - number of remaining bytes, block size and intermediate buffer
    /// </summary>
    fNum : integer;
    fPolyBlockSize : integer;
    fData : Array[0..2*POLY1305_BLOCK_SIZE - 1] of Byte;     // for both the avx and pas version

    /// <summary>
    /// #bytes of encrypted data
    /// </summary>
    fPolyInitComplete : boolean;

    /// <summary>
    /// Reference to the actual poly block function. For future SSE, AVX use
    /// </summary>
    fPolyBlkFunc : TPoly1305BlockMethod;
    fPadAndFinalizeFunc : TPoly1305PadAndFinalize;

    function U8ToU32( pData : PByteArray ) : UInt32; inline;
    procedure U32ToU8(pData : PByteArray; value : UInt32); inline;

    /// <summary>
    /// Poly1305 blocks function
    /// </summary>
    procedure Poly1305Blocks( pData : PByteArray; size : integer; padBit : UInt32 );

    /// <summary>
    /// Finaly MAC creating function
    /// </summary>
    procedure Poly1305Emit( var mac : TBlock16Byte; const nonce : TPoly1305Nonce );
    procedure PadAndFinalizePAS( authLen, encDecBufLen : int64);
    procedure PadAndFinalizeAVX(authLen, encDecBufLen: int64);
  protected
    // ###########################################
    // #### Authentication block functions
    {$IFNDEF PUREPASCAL}
    procedure UpdatePolyAVX( pData : PByteArray; size : integer);
    procedure FinalizeAVX;
    {$ENDIF}
    procedure UpdatePoly( pData : PByteArray; size : integer);
    procedure InitInternal(const InitVector : T32ByteArray);
    procedure Finalize;


    /// <summary>
    ///   Finalizes the Poly1305 calculation
    ///   The last block is padded and one additional block containing
    ///   the processed length + the legnth processed AuthenticationBytes
    ///   is created and fed into the polynom.
    ///   After this call the MAC is valid.
    /// </summary>
    procedure FinalizeMAC( authLen, encDecBufLen : int64); override;
    procedure InitAuth; override;
    procedure UpdateWithEncDecBuf(buf : PUInt8Array; Size   : Integer); override;

    procedure Burn; override;
  public
    /// <summary>
    ///   Defines either pure pascal code is used or specialized assembler routines utilizing AVX instructions
    /// </summary>
    class var CpuMode : TPoly1305CpuMode;


    constructor Create;

    /// <summary>
    ///   Should be called when starting encryption/decryption in order to
    ///   initialize internal tables etc.
    /// </summary>
    /// <param name="EncryptionMethod">
    ///   Encryption method of the cypher used
    /// </param>
    /// <param name="InitVector">
    ///   Initialization vector
    /// </param>
    procedure Init(EncryptionMethod : TEncodeDecodeMethod;
                   InitVector       : TBytes); override;
  end;

implementation

{$R-}{$Q-}

const cMask26 : uint64 = $3ffffff;
      cShl24 : uint64 = $1000000;

//CONSTANT_TIME_CARRY(a,b) ( \
//         (a ^ ((a ^ b) | ((a - b) ^ b))) >> (sizeof(a) * 8 - 1) \
//         )
function ConstTimeCarray32(a, b : UInt32 ) : UInt32; inline;
begin
     Result := (a xor ( (a xor b) or ((a - b) xor b))) shr 31;
end;

// ###########################################
// #### AVX Assembler - and associated procedures
// ###########################################

{$IFNDEF PUREPASCAL}

{$IFDEF FPC} {$ASMMode Intel} {$ENDIF}

procedure Split26( const lo, hi : UInt64; outVal : TPoly1305.PStateAVXArr ); inline;
var t0, t1, t2, t3, t4 : UInt64;
begin
     t0 := lo;
     t1 := (lo shr 26) or (hi shl 38);
     t2 := (lo shr 52) or (hi shl 12);
     t3 := (hi shr 14);
     t4 := hi shr 40;
     outval^[0] := t0 and cMask26;
     outval^[1] := t1 and cMask26;
     outval^[2] := t2 and cMask26;
     outval^[3] := t3 and cMask26;
     outval^[4] := t4 and cMask26;
end;

procedure clamp_r( r : TPoly1305.PStateAVXArr); inline;
begin
     r^[1] := r^[1] and $3ffff03;
     r^[2] := r^[2] and $3ffc0ff;
     r^[3] := r^[3] and $3f03fff;
     r^[4] := r^[4] and $00fffff;
end;


procedure InitPoly1305( ctx : TPoly1305.PPoly1305CTX; key : PByte );
var i : integer;
begin
     FillChar(ctx^, sizeof(ctx^), 0);

     Split26(TPoly1305.P4UInt64(key)^[0], TPoly1305.P4UInt64(key)^[1], @ctx.r[0]);
     clamp_r(@ctx^.r[0]);

     for i := 0 to High(ctx^.rr) do
         ctx^.rr[i] := 5*ctx^.r[i];

     // Precompute k0..k4 once (no per-block _mm256_set_epi64x needed)
     // Note: _mm256_set_epi64x order is [lane3,lane2,lane1,lane0]
     ctx^.k0[3] := ctx^.rr[2];
     ctx^.k0[2] := ctx^.rr[3];
     ctx^.k0[1] := ctx^.rr[4];
     ctx^.k0[0] := ctx^.r[0];
     ctx^.k0_5 := ctx^.rr[1];

     ctx^.k1[3] := ctx^.rr[3];
     ctx^.k1[2] := ctx^.rr[4];
     ctx^.k1[1] := ctx^.r[0];
     ctx^.k1[0] := ctx^.r[1];
     ctx^.k1_5 := ctx^.rr[2];

     ctx^.k2[3] := ctx^.rr[4];
     ctx^.k2[2] := ctx^.r[0];
     ctx^.k2[1] := ctx^.r[1];
     ctx^.k2[0] := ctx^.r[2];
     ctx^.k2_5 := ctx^.rr[3];

     ctx^.k3[3] := ctx^.r[0];
     ctx^.k3[2] := ctx^.r[1];
     ctx^.k3[1] := ctx^.r[2];
     ctx^.k3[0] := ctx^.r[3];
     ctx^.k3_5 := ctx^.rr[4];

     ctx^.k4[3] := ctx^.r[1];
     ctx^.k4[2] := ctx^.r[2];
     ctx^.k4[1] := ctx^.r[3];
     ctx^.k4[0] := ctx^.r[4];
     ctx^.k4_5 := ctx^.r[0];

     // first 16 byte went to R -> the rest is used for the "nonce"
     ctx^.s0 := TPoly1305.P4UInt64(key)^[2];
     ctx^.s1 := TPoly1305.P4UInt64(key)^[3];
end;

procedure FinalizePoly1305( ctx : TPoly1305.PPoly1305CTX;  mac : PByte );
var h : TPoly1305.PStateAVXArr;
    c : UInt64;
    g : TPoly1305.TStateAVXArr;
    mask : UInt64;
    nmask : UInt64;
    f0, f1 : UInt64;
begin
     h := @(ctx^.h[0]);
     c := h^[1] shr 26; h^[1] := h^[1] and cMask26; inc(h^[2], c);
     c := h^[2] shr 26; h^[2] := h^[2] and cMask26; inc(h^[3], c);
     c := h^[3] shr 26; h^[3] := h^[3] and cMask26; inc(h^[4], c);
     c := h^[4] shr 26; h^[4] := h^[4] and cMask26; inc(h^[0], 5*c);
     c := h^[0] shr 26; h^[0] := h^[0] and cMask26; inc(h^[1], c);

     g[0] := h[0] + 5;
     g[1] := h[1] + (g[0] shr 26); g[0] := g[0] and cMask26;
     g[2] := h[2] + (g[1] shr 26); g[0] := g[1] and cMask26;
     g[3] := h[3] + (g[2] shr 26); g[0] := g[2] and cMask26;
     g[4] := h[4] + (g[3] shr 26); g[0] := g[3] and cMask26;

     dec(g[4], 1 shl 26);

     // mask is either 0 or all ones depending on the last bit
     // works only for disabled range checking and overflow checking!
     mask := (g[4] shr 63) - 1;
     g[4] := g[4] and cMask26;
     nmask := not mask;
     h^[0] := (h^[0] and nmask) or (g[0] and mask);
     h^[1] := (h^[1] and nmask) or (g[1] and mask);
     h^[2] := (h^[2] and nmask) or (g[2] and mask);
     h^[3] := (h^[3] and nmask) or (g[3] and mask);
     h^[4] := (h^[4] and nmask) or (g[4] and mask);

     // pack into 128-bit LE
     f0 := h^[0] or (h^[1] shl 26) or (h^[2] shl 52);
     f1 := (h^[2] shr 12) or (h^[3] shl 14) or (h^[4] shl 40);

     // add s
     TPoly1305.P2UInt64(mac)^[0] := f0 + ctx^.s0;
     TPoly1305.P2UInt64(mac)^[1] := f1 + ctx^.s1 + UInt64(TPoly1305.P2UInt64(@mac[0])^[0] < f0);
end;

// central xmm register save and restor (we don't need that in a tight loop)

{$IFDEF X86ASM}

procedure poly1305_block_avx2_ctx(ctx : TPoly1305.PPoly1305CTX; t : TPoly1305.PStateAVXArr); {$IFDEF FPC} assembler; {$ENDIF}
asm
   push ebp;
   mov	ecx, edx
   mov	ebp, esp
   push	edi
   push	esi
   mov	esi, eax
   push	ebx

   // reserver mem on the local stack -> aligned 32bytes
   and	esp, -32
   sub	esp, 64


   mov	eax, DWORD PTR [edx+32]
   add	eax, DWORD PTR [esi+312]
   {$IFDEF AVXSUP}vmovdqu	ymm0, [ecx]                                 {$ELSE}db $C5,$FE,$6F,$01;{$ENDIF}
   mov	edi, DWORD PTR [esi+240]
   mov	ecx, eax
   mov	DWORD PTR [esp+52], 0
   mov	eax, DWORD PTR [esi+244]
   mov	edx, DWORD PTR [edx+36]
   mov	DWORD PTR [esp+56], ecx
   adc	edx, DWORD PTR [esi+316]
   {$IFDEF AVXSUP}vpaddq	ymm0, ymm0, [esi+280]                        {$ELSE}db $C5,$FD,$D4,$86,$18,$01,$00,$00;{$ENDIF}
   {$IFDEF AVXSUP}vpmuludq	ymm1, ymm0, [esi+80]                       {$ELSE}db $C5,$FD,$F4,$4E,$50;{$ENDIF}
   {$IFDEF AVXSUP}vmovdqa	xmm2, xmm1                                  {$ELSE}db $C5,$F9,$6F,$D1;{$ENDIF}
   imul	eax, ecx
   {$IFDEF AVXSUP}vextracti128	xmm1, ymm1, $1                         {$ELSE}db $C4,$E3,$7D,$39,$C9,$01;{$ENDIF}
   mov	DWORD PTR [esp+60], edx
   {$IFDEF AVXSUP}vpmuludq	ymm3, ymm0, [esi+112]                      {$ELSE}db $C5,$FD,$F4,$5E,$70;{$ENDIF}
   imul	edi, edx
   {$IFDEF AVXSUP}vpaddq	xmm1, xmm1, xmm2                             {$ELSE}db $C5,$F1,$D4,$CA;{$ENDIF}
   {$IFDEF AVXSUP}vpsrldq	xmm2, xmm1, 8                               {$ELSE}db $C5,$E9,$73,$D9,$08;{$ENDIF}
   {$IFDEF AVXSUP}vpaddq	xmm1, xmm1, xmm2                             {$ELSE}db $C5,$F1,$D4,$CA;{$ENDIF}
   {$IFDEF AVXSUP}vpmuludq	ymm2, ymm0, [esi+144]                      {$ELSE}db $C5,$FD,$F4,$96,$90,$00,$00,$00;{$ENDIF}
   add	edi, eax
   mov	eax, ecx
   mul	DWORD PTR [esi+240]
   mov	ecx, eax
   mov	ebx, edx
   {$IFDEF AVXSUP}vmovd	eax, xmm1                                     {$ELSE}db $C5,$F9,$7E,$C8;{$ENDIF}
   add	ebx, edi
   {$IFDEF AVXSUP}vpextrd	edx, xmm1, 1                                {$ELSE}db $C4,$E3,$79,$16,$CA,$01;{$ENDIF}
   {$IFDEF AVXSUP}vmovdqa	xmm1, xmm3                                  {$ELSE}db $C5,$F9,$6F,$CB;{$ENDIF}
   add	ecx, eax
   adc	ebx, edx
   mov	eax, DWORD PTR [esp+56]
   mov	edx, DWORD PTR [esi+252]
   mov	edi, ecx
   and	edi, 67108863
   {$IFDEF AVXSUP}vextracti128	xmm3, ymm3, $1                         {$ELSE}db $C4,$E3,$7D,$39,$DB,$01;{$ENDIF}
   imul	edx, eax
   mov	DWORD PTR [esp+48], edi
   mov	edi, DWORD PTR [esp+60]
   {$IFDEF AVXSUP}vpaddq	xmm3, xmm3, xmm1                             {$ELSE}db $C5,$E1,$D4,$D9;{$ENDIF}
   imul	edi, DWORD PTR [esi+248]
   mov	eax, DWORD PTR [esp+56]
   {$IFDEF AVXSUP}vpsrldq	xmm6, xmm3, 8                               {$ELSE}db $C5,$C9,$73,$DB,$08;{$ENDIF}
   {$IFDEF AVXSUP}vmovdqa	xmm1, xmm2                                  {$ELSE}db $C5,$F9,$6F,$CA;{$ENDIF}
   {$IFDEF AVXSUP}vpaddq	xmm3, xmm3, xmm6                             {$ELSE}db $C5,$E1,$D4,$DE;{$ENDIF}
   {$IFDEF AVXSUP}vextracti128	xmm2, ymm2, $1                         {$ELSE}db $C4,$E3,$7D,$39,$D2,$01;{$ENDIF}
   {$IFDEF AVXSUP}vpaddq	xmm2, xmm2, xmm1                             {$ELSE}db $C5,$E9,$D4,$D1;{$ENDIF}
   {$IFDEF AVXSUP}vmovq	QWORD PTR [esp+32], xmm3                      {$ELSE}db $C5,$F9,$D6,$5C,$24,$20;{$ENDIF}
   {$IFDEF AVXSUP}vpmuludq	ymm1, ymm0, [esi+176]                      {$ELSE}db $C5,$FD,$F4,$8E,$B0,$00,$00,$00;{$ENDIF}
   {$IFDEF AVXSUP}vmovdqa	xmm4, xmm1                                  {$ELSE}db $C5,$F9,$6F,$E1;{$ENDIF}
   add	edi, edx
   mul	DWORD PTR [esi+248]
   {$IFDEF AVXSUP}vpmuludq	ymm0, ymm0, [esi+208]                      {$ELSE}db $C5,$FD,$F4,$86,$D0,$00,$00,$00;{$ENDIF}
   {$IFDEF AVXSUP}vmovdqa	xmm7, xmm0                                  {$ELSE}db $C5,$F9,$6F,$F8;{$ENDIF}
   {$IFDEF AVXSUP}vpsrldq	xmm5, xmm2, 8                               {$ELSE}db $C5,$D1,$73,$DA,$08;{$ENDIF}
   {$IFDEF AVXSUP}vextracti128	xmm1, ymm1, $1                         {$ELSE}db $C4,$E3,$7D,$39,$C9,$01;{$ENDIF}
   {$IFDEF AVXSUP}vextracti128	xmm0, ymm0, $1                         {$ELSE}db $C4,$E3,$7D,$39,$C0,$01;{$ENDIF}
   {$IFDEF AVXSUP}vpaddq	xmm2, xmm2, xmm5                             {$ELSE}db $C5,$E9,$D4,$D5;{$ENDIF}
   {$IFDEF AVXSUP}vpaddq	xmm1, xmm1, xmm4                             {$ELSE}db $C5,$F1,$D4,$CC;{$ENDIF}
   add	edx, edi
   {$IFDEF AVXSUP}vpsrldq	xmm4, xmm1, 8                               {$ELSE}db $C5,$D9,$73,$D9,$08;{$ENDIF}
   {$IFDEF AVXSUP}vpaddq	xmm0, xmm0, xmm7                             {$ELSE}db $C5,$F9,$D4,$C7;{$ENDIF}
   add	eax, DWORD PTR [esp+32]
   adc	edx, DWORD PTR [esp+36]
   shrd	ecx, ebx, 26
   {$IFDEF AVXSUP}vmovq	QWORD PTR [esp+32], xmm2                      {$ELSE}db $C5,$F9,$D6,$54,$24,$20;{$ENDIF}
   {$IFDEF AVXSUP}vpaddq	xmm1, xmm1, xmm4                             {$ELSE}db $C5,$F1,$D4,$CC;{$ENDIF}
   shr	ebx, 26
   add	ecx, eax
   mov	eax, DWORD PTR [esp+56]
   mov	DWORD PTR [esp+44], 0
   mov	edi, ecx
   {$IFDEF AVXSUP}vpsrldq	xmm7, xmm0, 8                               {$ELSE}db $C5,$C1,$73,$D8,$08;{$ENDIF}
   adc	ebx, edx
   and	edi, 67108863
   imul	eax, DWORD PTR [esi+260]
   {$IFDEF AVXSUP}vpaddq	xmm0, xmm0, xmm7                             {$ELSE}db $C5,$F9,$D4,$C7;{$ENDIF}
   mov	DWORD PTR [esp+40], edi
   mov	edi, DWORD PTR [esp+60]
   imul	edi, DWORD PTR [esi+256]
   add	edi, eax
   mov	eax, DWORD PTR [esp+56]
   mul	DWORD PTR [esi+256]
   add	edx, edi
   add	eax, DWORD PTR [esp+32]
   adc	edx, DWORD PTR [esp+36]
   shrd	ecx, ebx, 26
   shr	ebx, 26
   add	eax, ecx
   mov	ecx, DWORD PTR [esp+56]
   mov	edi, DWORD PTR [esp+60]
   mov	DWORD PTR [esp+32], eax
   mov	eax, DWORD PTR [esi+268]
   adc	edx, ebx
   imul	edi, DWORD PTR [esi+264]
   mov	DWORD PTR [esp+36], edx
   imul	eax, ecx
   add	edi, eax
   mov	eax, ecx
   mul	DWORD PTR [esi+264]
   mov	ecx, eax
   mov	ebx, edx
   {$IFDEF AVXSUP}vmovd	eax, xmm1                                     {$ELSE}db $C5,$F9,$7E,$C8;{$ENDIF}
   add	ebx, edi
   {$IFDEF AVXSUP}vpextrd	edx, xmm1, 1                                {$ELSE}db $C4,$E3,$79,$16,$CA,$01;{$ENDIF}
   add	eax, ecx
   mov	ecx, DWORD PTR [esp+32]
   adc	edx, ebx
   mov	ebx, DWORD PTR [esp+36]
   mov	edi, DWORD PTR [esp+60]
   shrd	ecx, ebx, 26
   shr	ebx, 26
   add	eax, ecx
   mov	ecx, DWORD PTR [esp+56]
   adc	edx, ebx
   imul	edi, DWORD PTR [esi+272]
   mov	DWORD PTR [esp+24], eax
   mov	DWORD PTR [esp+28], edx
   mov	edx, DWORD PTR [esi+276]
   mov	eax, ecx
   imul	edx, ecx
   add	edi, edx
   mul	DWORD PTR [esi+272]
   mov	ecx, eax
   mov	ebx, edx
   {$IFDEF AVXSUP}vmovd	eax, xmm0                                     {$ELSE}db $C5,$F9,$7E,$C0;{$ENDIF}
   add	ebx, edi
   {$IFDEF AVXSUP}vpextrd	edx, xmm0, 1                                {$ELSE}db $C4,$E3,$79,$16,$C2,$01;{$ENDIF}
   add	eax, ecx
   mov	ecx, DWORD PTR [esp+24]
   adc	edx, ebx
   mov	ebx, DWORD PTR [esp+28]
   mov	edi, 5
   shrd	ecx, ebx, 26
   shr	ebx, 26
   add	ecx, eax
   adc	ebx, edx
   mov	eax, ecx
   mov	DWORD PTR [esp+56], ecx
   mov	edx, ebx
   shrd	eax, ebx, 26
   mov	DWORD PTR [esp+60], ebx
   mov	DWORD PTR [esi+284], 0
   shr	edx, 26
   mov	DWORD PTR [esi+300], 0
   lea	ebx, [edx+edx*4]
   mov	DWORD PTR [esi+308], 0
   mul	edi
   mov	DWORD PTR [esi+316], 0
   add	edx, ebx
   add	eax, DWORD PTR [esp+48]
   adc	edx, DWORD PTR [esp+52]
   mov	ebx, eax
   shrd	eax, edx, 26
   and	ebx, 67108863
   shr	edx, 26
   add	eax, DWORD PTR [esp+40]
   adc	edx, DWORD PTR [esp+44]
   mov	DWORD PTR [esi+288], eax
   mov	eax, DWORD PTR [esp+32]
   mov	DWORD PTR [esi+280], ebx
   and	eax, 67108863
   mov	DWORD PTR [esi+292], edx
   mov	DWORD PTR [esi+296], eax
   mov	eax, DWORD PTR [esp+24]
   and	eax, 67108863
   mov	DWORD PTR [esi+304], eax
   mov	eax, DWORD PTR [esp+56]
   and	eax, 67108863
   mov	DWORD PTR [esi+312], eax
   {$IFDEF AVXSUP}vzeroupper                                          {$ELSE}db $C5,$F8,$77;{$ENDIF}
   lea	esp, [ebp-12]
   pop	ebx
   pop	esi
   pop	edi
   pop	ebp
end;


{$ENDIF}

{$IFDEF X64ASM}

procedure StoreXMM( pXMM : PUInt64 ); register; {$IFDEF FPC} assembler; {$ENDIF}
asm
   {$IFDEF AVXSUP}vmovaps [rcx], xmm6;                                {$ELSE}db $C5,$F8,$29,$31;{$ENDIF}
   {$IFDEF AVXSUP}vmovaps [rcx + 16], xmm7;                           {$ELSE}db $C5,$F8,$29,$79,$10;{$ENDIF}
end;

procedure RestoreXMM( pXMM : PUint64 ); register; {$IFDEF FPC} assembler; {$ENDIF}
asm
   {$IFDEF AVXSUP}vmovntdqa xmm6, [rcx];                              {$ELSE}db $C4,$E2,$79,$2A,$31;{$ENDIF}
   {$IFDEF AVXSUP}vmovntdqa xmm7, [rcx + 16];                         {$ELSE}db $C4,$E2,$79,$2A,$79,$10;{$ENDIF}
end;

procedure poly1305_block_avx2_ctx(ctx : TPoly1305.PPoly1305CTX; t : TPoly1305.PStateAVXArr); {$IFDEF FPC} assembler; {$ENDIF}
asm
   {$IFDEF UNIX}
   // Linux uses a diffrent ABI -> copy over the registers so they meet with winABI
   // (note that the 5th and 6th parameter are are on the stack)
   // The parameters are passed in the following order:
   // RDI, RSI, RDX, RCX -> mov to RCX, RDX, R8, R9
   mov rcx, rdi;
   mov rdx, rsi;
   {$ENDIF}

   // H = h + t
   {$IFDEF AVXSUP}vmovdqu	ymm0, [rdx]                                 {$ELSE}db $C5,$FE,$6F,$02;{$ENDIF} // load t[0..3]
   mov	rax, rcx
   mov	rcx, [rdx + 32]  // load t[4]
   {$IFDEF AVXSUP}vpaddq	ymm0, ymm0, [rax + 280]                      {$ELSE}db $C5,$FD,$D4,$80,$18,$01,$00,$00;{$ENDIF} // load h[0..3]
   mov	r8, [rax + 240]

   // calc c0 to c4
   {$IFDEF AVXSUP}vpmuludq	ymm1, ymm0, [rax + 80]                     {$ELSE}db $C5,$FD,$F4,$48,$50;{$ENDIF}
   {$IFDEF AVXSUP}vmovdqa	xmm2, xmm1                                  {$ELSE}db $C5,$F9,$6F,$D1;{$ENDIF}
   {$IFDEF AVXSUP}vextracti128	xmm1, ymm1, $1                         {$ELSE}db $C4,$E3,$7D,$39,$C9,$01;{$ENDIF}
   add	rcx, [rax + 312]
   {$IFDEF AVXSUP}vpmuludq	ymm3, ymm0, [rax + 112]                    {$ELSE}db $C5,$FD,$F4,$58,$70;{$ENDIF}
   mov	r11, [rax + 256]
   imul	r8, rcx
   {$IFDEF AVXSUP}vpaddq	xmm1, xmm1, xmm2                             {$ELSE}db $C5,$F1,$D4,$CA;{$ENDIF}
   {$IFDEF AVXSUP}vpsrldq	xmm2, xmm1, 8                               {$ELSE}db $C5,$E9,$73,$D9,$08;{$ENDIF}
   imul	r11, rcx
   {$IFDEF AVXSUP}vpaddq	xmm1, xmm1, xmm2                             {$ELSE}db $C5,$F1,$D4,$CA;{$ENDIF}
   {$IFDEF AVXSUP}vpmuludq	ymm2, ymm0, [rax + 144]                    {$ELSE}db $C5,$FD,$F4,$90,$90,$00,$00,$00;{$ENDIF}
   {$IFDEF AVXSUP}vmovq	rdx, xmm1                                     {$ELSE}db $C4,$E1,$F9,$7E,$CA;{$ENDIF}
   {$IFDEF AVXSUP}vmovdqa	xmm1, xmm3                                  {$ELSE}db $C5,$F9,$6F,$CB;{$ENDIF}
   {$IFDEF AVXSUP}vextracti128	xmm3, ymm3, $1                         {$ELSE}db $C4,$E3,$7D,$39,$DB,$01;{$ENDIF}
   add	rdx, r8
   mov	r8, [rax + 248]
   {$IFDEF AVXSUP}vpaddq	xmm3, xmm3, xmm1                             {$ELSE}db $C5,$E1,$D4,$D9;{$ENDIF}
   {$IFDEF AVXSUP}vmovdqa	xmm1, xmm2                                  {$ELSE}db $C5,$F9,$6F,$CA;{$ENDIF}
   {$IFDEF AVXSUP}vpsrldq	xmm7, xmm3, 8                               {$ELSE}db $C5,$C1,$73,$DB,$08;{$ENDIF}
   {$IFDEF AVXSUP}vextracti128	xmm2, ymm2, $1                         {$ELSE}db $C4,$E3,$7D,$39,$D2,$01;{$ENDIF}
   mov	r9, rdx
   shr	rdx, 26
   imul	r8, rcx
   {$IFDEF AVXSUP}vpaddq	xmm3, xmm3, xmm7                             {$ELSE}db $C5,$E1,$D4,$DF;{$ENDIF}
   and	r9d, 67108863
   {$IFDEF AVXSUP}vpaddq	xmm2, xmm2, xmm1                             {$ELSE}db $C5,$E9,$D4,$D1;{$ENDIF}
   {$IFDEF AVXSUP}vmovq	r10, xmm3                                     {$ELSE}db $C4,$C1,$F9,$7E,$DA;{$ENDIF}
   {$IFDEF AVXSUP}vpmuludq	ymm1, ymm0, [rax + 176]                    {$ELSE}db $C5,$FD,$F4,$88,$B0,$00,$00,$00;{$ENDIF}
   {$IFDEF AVXSUP}vmovdqa	xmm4, xmm1                                  {$ELSE}db $C5,$F9,$6F,$E1;{$ENDIF}
   {$IFDEF AVXSUP}vpsrldq	xmm6, xmm2, 8                               {$ELSE}db $C5,$C9,$73,$DA,$08;{$ENDIF}
   {$IFDEF AVXSUP}vextracti128	xmm1, ymm1, $1                         {$ELSE}db $C4,$E3,$7D,$39,$C9,$01;{$ENDIF}
   {$IFDEF AVXSUP}vpmuludq	ymm0, ymm0, [rax + 208]                    {$ELSE}db $C5,$FD,$F4,$80,$D0,$00,$00,$00;{$ENDIF}
   add	r8, r10
   {$IFDEF AVXSUP}vpaddq	xmm2, xmm2, xmm6                             {$ELSE}db $C5,$E9,$D4,$D6;{$ENDIF}
   {$IFDEF AVXSUP}vpaddq	xmm1, xmm1, xmm4                             {$ELSE}db $C5,$F1,$D4,$CC;{$ENDIF}
   add	r8, rdx
   {$IFDEF AVXSUP}vmovq	rdx, xmm2                                     {$ELSE}db $C4,$E1,$F9,$7E,$D2;{$ENDIF}
   {$IFDEF AVXSUP}vmovdqa	xmm4, xmm0                                  {$ELSE}db $C5,$F9,$6F,$E0;{$ENDIF}
   add	rdx, r11
   mov	r11, [rax + 264]
   mov	r10, r8

   // carry chain 26-bit, reduction mod 2^130-5
   // + write back to h
   {$IFDEF AVXSUP}vextracti128	xmm0, ymm0, $1                         {$ELSE}db $C4,$E3,$7D,$39,$C0,$01;{$ENDIF}
   {$IFDEF AVXSUP}vpsrldq	xmm5, xmm1, 8                               {$ELSE}db $C5,$D1,$73,$D9,$08;{$ENDIF}
   shr	r8, 26
   {$IFDEF AVXSUP}vpaddq	xmm0, xmm0, xmm4                             {$ELSE}db $C5,$F9,$D4,$C4;{$ENDIF}
   and	r10d, 67108863
   imul	r11, rcx
   {$IFDEF AVXSUP}vpaddq	xmm1, xmm1, xmm5                             {$ELSE}db $C5,$F1,$D4,$CD;{$ENDIF}
   {$IFDEF AVXSUP}vpsrldq	xmm4, xmm0, 8                               {$ELSE}db $C5,$D9,$73,$D8,$08;{$ENDIF}
   add	r8, rdx
   {$IFDEF AVXSUP}vmovq	rdx, xmm1                                     {$ELSE}db $C4,$E1,$F9,$7E,$CA;{$ENDIF}
   imul	rcx, [rax + 272]
   {$IFDEF AVXSUP}vpaddq	xmm0, xmm0, xmm4                             {$ELSE}db $C5,$F9,$D4,$C4;{$ENDIF}
   add	rdx, r11
   mov	r11, r8
   and	r8d, 67108863
   shr	r11, 26
   mov	[rax + 296], r8
   add	r11, rdx
   {$IFDEF AVXSUP}vmovq	rdx, xmm0                                     {$ELSE}db $C4,$E1,$F9,$7E,$C2;{$ENDIF}
   add	rcx, rdx
   mov	rdx, r11
   shr	rdx, 26
   add	rcx, rdx
   mov	rdx, rcx
   and	ecx, 67108863
   shr	rdx, 26
   mov	[rax + 312], rcx
   lea	rdx, [rdx + rdx*4]
   add	rdx, r9
   mov	r9, rdx
   shr	rdx, 26
   add	rdx, r10
   and	r9d, 67108863
   mov	[rax + 288], rdx
   mov	rdx, r11
   and	edx, 67108863
   mov	[rax + 280], r9
   mov	[rax + 304], rdx

   {$IFDEF AVXSUP}vzeroupper                                          {$ELSE}db $C5,$F8,$77;{$ENDIF}
end;

{$ENDIF}


{$ENDIF}

// ###########################################
// #### Poly1305
// ###########################################


{ TPoly1305 }

procedure TPoly1305.U32ToU8(pData: PByteArray; value: UInt32);
begin
     pData^[0] := Byte(value);
     pData^[1] := Byte(value shr 8);
     pData^[2] := Byte(value shr 16);
     pData^[3] := Byte(value shr 24);
end;

function TPoly1305.U8ToU32(pData: PByteArray): UInt32;
begin
     Result := (UInt32(pData^[0]) and $ff) or
               ((UInt32(pData^[1]) and $ff) shl 8) or
               ((UInt32(pData^[2]) and $ff) shl 16) or
               ((UInt32(pData^[3]) and $ff) shl 24);
end;


procedure TPoly1305.InitAuth;
var aLen : integer;
    vec : TBytes;
begin
     InitInternal(fIV);

     aLen := Length(FDataToAuthenticate);
     // update the polynom with the unencrypted authentication data
     if aLen > 0 then
     begin
          // pad to blocksize if ncessary
          if aLen mod POLY1305_BLOCK_SIZE <> 0 then
          begin
               aLen := aLen + POLY1305_BLOCK_SIZE - aLen mod POLY1305_BLOCK_SIZE;
               SetLength(vec, aLen);
               Move(FDataToAuthenticate[0], vec[0], Length(FDataToAuthenticate));
          end
          else
              vec := FDataToAuthenticate;
          fPolyBlkFunc( @vec[0], Length(vec));
     end;
end;


procedure TPoly1305.Burn;
begin
     inherited;

     FillChar(fPoly1305State, sizeof(fPoly1305State), 0);
     FillChar(FNonce, sizeof(FNonce), 0);
     FillChar(fIV, sizeof(fIV), 0);
     FillChar(fData, sizeof(fData), 0);
     fNum := 0;
end;

function AlignPtr64( A : Pointer ) : Pointer;
begin
     Result := A;
     if (NativeUint(A) and $3F) <> 0 then
        Result := Pointer( NativeUint(Result) + $40 - NativeUint(Result) and $3F );
end;


constructor TPoly1305.Create;
begin
     inherited Create;

     FCalcAuthenticationTagLength := sizeof(TBlock16Byte);
     fAVXCtx := AlignPtr64(@fPoly1305State[0]);
     FH := @fAVXCtx^.h[0];
     FR := @fAVXCtx^.r[0];

     inc(fAVXCtx);
     fXMMMem := PUInt64(fAVXCtx);
     dec(fAVXCtx);

     case CpuMode of
      pmPas: begin
                  fPadAndFinalizeFunc := PadAndFinalizePAS;
                  fPolyBlkFunc := UpdatePoly;
             end;
      pmAVX: begin
                  {$IFNDEF PUREPASCAL}
                  fPadAndFinalizeFunc := PadAndFinalizeAVX;
                  fPolyBlkFunc := UpdatePolyAVX;
                  {$ELSE}
                  fPadAndFinalizeFunc := PadAndFinalizePAS;
                  fPolyBlkFunc := UpdatePoly;
                  {$ENDIF}
             end;
     end;
     fPolyBlockSize := POLY1305_BLOCK_SIZE;
end;

procedure TPoly1305.Finalize;
var mac : TBlock16Byte;
begin
     if fNum > 0 then
     begin
          fData[fNum] := 1; // padbit..
          inc(fNum);
          while fNum < Length(fData) do
          begin
               fData[fNum] := 0;
               inc(fNum);
          end;

          Poly1305Blocks(@fData[0], POLY1305_BLOCK_SIZE, 0);
          fNum := 0;
     end;

     Poly1305Emit(mac, FNonce);

     SetLength(FCalcAuthenticationTag, sizeof(mac));
     Move(mac, FCalcAuthenticationTag[0], sizeof(mac));

     FillChar(mac, sizeof(mac), 0);
end;

{$IFNDEF PUREPASCAL}

procedure TPoly1305.FinalizeAVX;
var mac : TBlock16Byte;
    t : TStateAVXArr;
begin
     if fNum > 0 then
     begin
          fData[fNum] := 1; // padbit..
          inc(fNum);
          while fNum < Length(fData) do
          begin
               fData[fNum] := 0;
               inc(fNum);
          end;

          Split26(PUint64(@fData[0])^, PUint64(@fData[8])^, @t[0]);
          {$IFDEF x64}
          StoreXMM(fXMMMem)
          {$ENDIF}
          poly1305_block_avx2_ctx(fAVXCtx, @t[0]);
          {$IFDEF x64}
          RestoreXMM(fXMMMem);
          {$ENDIF}
          fNum := 0;
     end;

     FinalizePoly1305(fAVXCtx, @mac[0]);

     SetLength(FCalcAuthenticationTag, sizeof(mac));
     Move(mac, FCalcAuthenticationTag[0], sizeof(mac));

     FillChar(mac, sizeof(mac), 0);
end;
{$ENDIF}


procedure TPoly1305.Init(EncryptionMethod: TEncodeDecodeMethod;
  InitVector: TBytes);
begin
     inherited;

     // the poly1305 format needs to be initialized correctly from the outside!
     // for chacha20 one needs to set initialize the chacha block with the key,
     // 96bit nonce and counter to 0 -> the first 32bytes of that chacha scrambled block
     // defines the iv
     if Length(InitVector) <> ( Length(fIV) ) then
        raise Exception.Create('The initVector must be 32Bytes long!');

     // in this library this only works for chacha since it has an internal counter
     // don't know how to deal with aes here...
     // build the poly1305 iv from the first 256 bits
     FillChar( fIV, sizeof(fIV), 0);
     Move( initVector[0], fIV, Length(initVector));
end;

procedure TPoly1305.InitInternal(const InitVector: T32ByteArray);
begin
     fPolyInitComplete := True;

     FillChar(fAVXCtx^, sizeof(fAVXCtx^), 0);

    ///* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
//     st->r[0] = U8TOU32(&key[0]) & 0x0fffffff;
//     st->r[1] = U8TOU32(&key[4]) & 0x0ffffffc;
//     st->r[2] = U8TOU32(&key[8]) & 0x0ffffffc;
//     st->r[3] = U8TOU32(&key[12]) & 0x0ffffffc;
     FR^[0] := U8ToU32(@initVector[0]) and $0fffffff;
     FR^[1] := U8ToU32(@initVector[4]) and $0ffffffc;
     FR^[2] := U8ToU32(@initVector[8]) and $0ffffffc;
     FR^[3] := U8ToU32(@initVector[12]) and $0ffffffc;


     FNonce[0] := U8ToU32(@initVector[16]);
     FNonce[1] := U8ToU32(@initVector[20]);
     FNonce[2] := U8ToU32(@initVector[24]);
     FNonce[3] := U8ToU32(@initVector[28]);

     // initialize avx members
     {$IFNDEF PUREPASCAL}
     if CpuMode = pmAVX then
        InitPoly1305(fAVXCtx, @InitVector[0]);
     {$ENDIF}
     fNum := 0;
end;

procedure TPoly1305.FinalizeMAC( authLen, encDecBufLen : int64);
begin
     inherited;

     fPadAndFinalizeFunc(authLen, encDecBufLen);
end;

procedure TPoly1305.PadAndFinalizePAS( authLen, encDecBufLen : int64);
var lens : Array[0..1] of Int64;
begin
     // pad the last block with 0
     if fNum > 0 then
     begin
          fData[fNum] := 0;
          inc(fNum);
          while fNum < Length(fData) do
          begin
               fData[fNum] := 0;
               inc(fNum);
          end;

          Poly1305Blocks(@fData[0], POLY1305_BLOCK_SIZE, 1);
          fNum := 0;
     end;


     // finalize with the tag with the lengths!
     lens[0] := authLen;
     lens[1] := encDecBufLen;
     Poly1305Blocks(@lens[0], POLY1305_BLOCK_SIZE, 1);

     Finalize;
end;

{$IFNDEF PUREPASCAL}
procedure TPoly1305.PadAndFinalizeAVX( authLen, encDecBufLen : int64);
var lens : Array[0..1] of UInt64;
    t : TStateAVXArr;
begin
     // pad the last block with 0
     {$IFDEF x64}
     StoreXMM(fXMMMem);
     {$ENDIF}
     if fNum > 0 then
     begin
          fData[fNum] := 0;
          inc(fNum);
          while fNum < Length(fData) do
          begin
               fData[fNum] := 0;
               inc(fNum);
          end;

          Split26(PUint64(@fData[0])^, PUint64(@fData[8])^, @t[0]);
          t[4] := t[4] + cShl24;

          poly1305_block_avx2_ctx(fAVXCtx, @t[0]);
          fNum := 0;
     end;


     // the last block contains the lenghts
     lens[0] := authLen;
     lens[1] := encDecBufLen;
     Split26(lens[0], lens[1], @t[0]);
     t[4] := t[4] + cShl24;
     poly1305_block_avx2_ctx(fAVXCtx, @t[0]);
     {$IFDEF x64}
     RestoreXMM(fXMMMem);
     {$ENDIF}

     FinalizeAVX;
end;
{$ENDIF}


procedure TPoly1305.Poly1305Blocks(pData: PByteArray; size: integer;
  padBit: UInt32);
var r0, r1, r2, r3 : UInt32;
    s1, s2, s3 : UInt32;
    h0, h1, h2, h3, h4, c : UInt32;
    d0, d1, d2, d3 : UInt64;
begin
     //r0 = st->r[0];
//     r1 = st->r[1];
//     r2 = st->r[2];
//     r3 = st->r[3];
     r0 := FR^[0];
     r1 := FR^[1];
     r2 := FR^[2];
     r3 := FR^[3];

     //s1 = r1 + (r1 >> 2);
//     s2 = r2 + (r2 >> 2);
//     s3 = r3 + (r3 >> 2);
     s1 := r1 + (r1 shr 2);
     s2 := r2 + (r2 shr 2);
     s3 := r3 + (r3 shr 2);

     //h0 = st->h[0];
//     h1 = st->h[1];
//     h2 = st->h[2];
//     h3 = st->h[3];
//     h4 = st->h[4];
     h0 := FH^[0];
     h1 := FH^[1];
     h2 := FH^[2];
     h3 := FH^[3];
     h4 := FH^[4];

     while size >= POLY1305_BLOCK_SIZE do
     begin
          ///* h += m[i] */
//          h0 = (u32)(d0 = (u64)h0 + U8TOU32(inp + 0));
//          h1 = (u32)(d1 = (u64)h1 + (d0 >> 32) + U8TOU32(inp + 4));
//          h2 = (u32)(d2 = (u64)h2 + (d1 >> 32) + U8TOU32(inp + 8));
//          h3 = (u32)(d3 = (u64)h3 + (d2 >> 32) + U8TOU32(inp + 12));
//          h4 += (u32)(d3 >> 32) + padbit;
          d0 := UInt64(h0) + U8ToU32(pData);
          h0 := UInt32(d0);
          d1 := UInt64(h1) + d0 shr 32 + U8ToU32(@pData^[4]);     // the delphi compiler seems to be intelligent enough to replace the shift by accessing the high 4 bytes
          h1 := UInt32(d1);
          d2 := UInt64(h2) + d1 shr 32 + U8ToU32(@pData^[8]);
          h2 := UInt32(d2);
          d3 := UInt64(h3) + d2 shr 32 + U8ToU32(@pData^[12]);
          h3 := UInt32(d3);
          h4 := h4 + padbit + UInt32( d3 shr 32);

//          /* h *= r "%" p, where "%" stands for "partial remainder" */
          //d0 = ((u64)h0 * r0) +
//               ((u64)h1 * s3) +
//               ((u64)h2 * s2) +
//               ((u64)h3 * s1);
          d0 := UInt64(h0)*r0 + UInt64(h1)*s3 + UInt64(h2)*s2 + UInt64(h3)*s1;

//          d1 = ((u64)h0 * r1) +
//               ((u64)h1 * r0) +
//               ((u64)h2 * s3) +
//               ((u64)h3 * s2) +
//               (h4 * s1);
          d1 := UInt64(h0)*r1 + UInt64(h1)*r0 + UInt64(h2)*s3 + UInt64(h3)*s2 + h4*s1;

//          d2 = ((u64)h0 * r2) +
//               ((u64)h1 * r1) +
//               ((u64)h2 * r0) +
//               ((u64)h3 * s3) +
//               (h4 * s2);
          d2 := UInt64(h0)*r2 + UInt64(h1)*r1 + UInt64(h2)*r0 + UInt64(h3)*s3 + h4*s2;

//          d3 = ((u64)h0 * r3) +
//               ((u64)h1 * r2) +
//               ((u64)h2 * r1) +
//               ((u64)h3 * r0) +
//               (h4 * s3);
//          h4 = (h4 * r0);
//
          d3 := UInt64(h0)*r3 + UInt64(h1)*r2 + UInt64(h2)*r1 + UInt64(h3)*r0 + h4*s3;
          h4 := h4*r0;

          //* last reduction step: */
      //  /* a) h4:h0 = h4<<128 + d3<<96 + d2<<64 + d1<<32 + d0 */
//        h0 = (u32)d0;
//        h1 = (u32)(d1 += d0 >> 32);
//        h2 = (u32)(d2 += d1 >> 32);
//        h3 = (u32)(d3 += d2 >> 32);
//        h4 += (u32)(d3 >> 32);
          h0 := UInt32(d0);
          d1 := d1 + d0 shr 32;
          h1 := UInt32(d1);
          d2 := d2 + d1 shr 32;
          h2 := UInt32(d2);
          d3 := d3 + d2 shr 32;
          h3 := UInt32(d3);
          h4 := h4 + UInt32(d3 shr 32);

          //* b) (h4:h0 += (h4:h0>>130) * 5) %= 2^130 */
//        c = (h4 >> 2) + (h4 & ~3U);
//        h4 &= 3;
//        h0 += c;
//        h1 += (c = CONSTANT_TIME_CARRY(h0,c));
//        h2 += (c = CONSTANT_TIME_CARRY(h1,c));
//        h3 += (c = CONSTANT_TIME_CARRY(h2,c));
//        h4 += CONSTANT_TIME_CARRY(h3,c);
          c := (h4 shr 2) + (h4 and (not UInt32(3)));
          h4 := h4 and 3;
          h0 := h0 + c;
          c := ConstTimeCarray32(h0, c);
          h1 := h1 + c;
          c := ConstTimeCarray32(h1, c);
          h2 := h2 + c;
          c := ConstTimeCarray32(h2, c);
          h3 := h3 + c;
          h4 := h4 + ConstTimeCarray32(h3, c);

          inc(PByte(pData), POLY1305_BLOCK_SIZE);
          dec(size, POLY1305_BLOCK_SIZE);
     end;

     FH^[0] := h0;
     FH^[1] := h1;
     FH^[2] := h2;
     FH^[3] := h3;
     FH^[4] := h4;
end;

procedure TPoly1305.Poly1305Emit(var mac: TBlock16Byte;
  const nonce: TPoly1305Nonce);
var h0, h1, h2, h3, h4 : UInt32;
    g0, g1, g2, g3, g4 : UInt32;
    t: UInt64;
    mask : UInt32;
begin
     // h0 = st->h[0];
     // h1 = st->h[1];
     //h2 = st->h[2];
//     h3 = st->h[3];
//     h4 = st->h[4];
      h0 := FH^[0];
      h1 := FH^[1];
      h2 := FH^[2];
      h3 := FH^[3];
      h4 := FH^[4];

   // /* compare to modulus by computing h + -p */
//      g0 = (u32)(t = (u64)h0 + 5);
//      g1 = (u32)(t = (u64)h1 + (t >> 32));
//      g2 = (u32)(t = (u64)h2 + (t >> 32));
//      g3 = (u32)(t = (u64)h3 + (t >> 32));
//      g4 = h4 + (u32)(t >> 32);
     t := UInt64(h0) + 5;
     g0 := UInt32(t);
     t := UInt64(h1) + t shr 32;
     g1 := UInt32(t);
     t := UInt64(h2) + t shr 32;
     g2 := UInt32(t);
     t := UInt64(h3) + t shr 32;
     g3 := UInt32(t);
     g4 := h4 + UInt32( t shr 32 );

     //* if there was carry into 131st bit, h3:h0 = g3:g0 */
     //mask = 0 - (g4 >> 2);
//     g0 &= mask;
//     g1 &= mask;
//     g2 &= mask;
//     g3 &= mask;
//     mask = ~mask;
//     h0 = (h0 & mask) | g0;
//     h1 = (h1 & mask) | g1;
//     h2 = (h2 & mask) | g2;
//     h3 = (h3 & mask) | g3;
     mask := UInt32( -(g4 shr 2) );
     g0 := g0 and mask;
     g1 := g1 and mask;
     g2 := g2 and mask;
     g3 := g3 and mask;
     mask := not mask;
     h0 := (h0 and mask) or g0;
     h1 := (h1 and mask) or g1;
     h2 := (h2 and mask) or g2;
     h3 := (h3 and mask) or g3;

     //  /* mac = (h + nonce) % (2^128) */
     //h0 = (u32)(t = (u64)h0 + nonce[0]);
//     h1 = (u32)(t = (u64)h1 + (t >> 32) + nonce[1]);
//     h2 = (u32)(t = (u64)h2 + (t >> 32) + nonce[2]);
//     h3 = (u32)(t = (u64)h3 + (t >> 32) + nonce[3]);
     t := UInt64(h0) + nonce[0];
     h0 := UInt32(t);
     t := UInt64(h1) + t shr 32 + nonce[1];
     h1 := UInt32(t);
     t := UInt64(h2) + t shr 32 + nonce[2];
     h2 := UInt32(t);
     t := UInt64(h3) + t shr 32 + nonce[3];
     h3 := UInt32(t);

     U32ToU8(@mac[0], h0);
     U32ToU8(@mac[4], h1);
     U32ToU8(@mac[8], h2);
     U32ToU8(@mac[12], h3);
end;

procedure TPoly1305.UpdatePoly(pData: PByteArray; size: integer);
var num : integer;
    rem : integer;
begin
     num := fNum;

     if num <> 0 then
     begin
          rem := POLY1305_BLOCK_SIZE - num;
          if size >= rem then
          begin
               Move( pData^, fData[num], rem);
               Poly1305Blocks(@fData[0], POLY1305_BLOCK_SIZE, 1);
               inc( PByte(pData), rem);
               dec( size, rem);
          end
          else
          begin
               //* Still not enough data to process a block. */
               move( pData^, fData[num], size );
               inc(fNum, size);
               exit;
          end;
     end;

     rem := size mod POLY1305_BLOCK_SIZE;
     size := size - rem;

     if size >= POLY1305_BLOCK_SIZE then
     begin
          Poly1305Blocks(pData, size, 1);
          inc(PByte(pData), size);
     end;

     if rem > 0 then
        Move( pData^, fData[0], rem );

     fNum := rem;
end;

{$IFNDEF PUREPASCAL}
procedure TPoly1305.UpdatePolyAVX(pData: PByteArray; size: integer);
var num : integer;
    rem : integer;
    t : TStateAVXArr;
begin
     num := fNum;

     {$IFDEF x64}
     StoreXMM(fXMMMem);
     {$ENDIF}

     if num <> 0 then
     begin
          rem := POLY1305_BLOCK_SIZE - num;
          if size >= rem then
          begin
               Move( pData^, fData[num], rem);
               Split26(PUInt64(@fData[0])^, PUInt64(@fData[8])^, @t[0]);
               t[4] := t[4] + cShl24;
               poly1305_block_avx2_ctx(fAVXCtx, @t[0]);

               inc( PByte(pData), rem);
               dec( size, rem);
          end
          else
          begin
               // Still not enough data to process a block.
               move( pData^, fData[num], size );
               inc(fNum, size);
               {$IFDEF x64}
               RestoreXMM(fXMMMem);
               {$endif}

               exit;
          end;
     end;

     while size >= POLY1305_BLOCK_SIZE do
     begin
          Split26(PUInt64(@pData^[0])^, PUInt64(@pData^[8])^, @t[0]);
          t[4] := t[4] + cShl24;

          poly1305_block_avx2_ctx(fAVXCtx, @t[0]);
          inc(PByte(pData), POLY1305_BLOCK_SIZE);
          dec(size, POLY1305_BLOCK_SIZE);
     end;

     {$IFDEF x64}
     RestoreXMM(fXMMMem);
     {$ENDIF}

     if size > 0 then
        Move( pData^, fData[0], size );

     fNum := size;
end;
{$ENDIF}


procedure TPoly1305.UpdateWithEncDecBuf(buf: PUInt8Array; Size: Integer);
begin
     fPolyBlkFunc(PByteArray(buf), size);
end;

end.
