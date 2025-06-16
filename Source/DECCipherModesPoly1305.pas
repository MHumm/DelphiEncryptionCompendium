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
type
  TPoly1305 = class(TAuthenticatedCipherModesBase)
  private
    const POLY1305_BLOCK_SIZE = 16;
          POLY1305_DIGEST_SIZE = 16;
          POLY1305_KEY_SIZE = 32;

          POLY1305_SSE2_BLOCK_SIZE = 32;
    type
      TPoly1305Nonce = Array[0..3] of UInt32;
      TPoly1305BlockMethod = procedure ( pData : PByteArray; size : integer ) of Object;
      TPoly1305EmitMethod = procedure( var mac: TBlock16Byte ) of Object;
      THArr = Array[0..4] of UInt32;
      PHArr = ^THArr;
      TRArr = Array[0..3] of UInt32;
      PRArr = ^TRArr;
      TYMM = Array[0..7] of UInt32;
      TYMM64 = Array[0..3] of Int64;
      TXMM = Array[0..3] of UInt32;

      TPoly1305StateFlag = (poly1305_started = 1, poly1305_final_shift8 = 4,
	                           poly1305_final_shift16 = 8,
                            poly1305_final_r2_r = 16, // use [r^2,r] for the final block */
	                           poly1305_final_r_1 = 32 // use [r,1] for the final block */
                           );

      type
        TH = packed record
          case byte of
            0: (H : Array[0..2] of UInt64);
            1: (HH: Array[0..19] of Uint32);
            2: (H32 : THArr);
          end;

        TPoly1305_state_internal_t = packed record
          hmac : TH;
          R : Array[0..4] of Uint32;
          R2 : Array[0..4] of UInt32;
          R3 : Array[0..4] of UInt32;
          R4 : Array[0..4] of UInt32;
          pad : Array[0..1] of UInt64;
          flags : Uint64;
        end;
        PPoly1305_state_internal_t = ^TPoly1305_state_internal_t;

      TPoly1305State = Array[0..191] of Byte;
  private
    // avx structures
    fPoly1305State : TPoly1305State;
    fPPoly1305State : PPoly1305_state_internal_t;

    // pas structures
    FH : PHArr;
    FR : PRArr;

    //

    fIV : T32ByteArray;
    FNonce : TPoly1305Nonce;

    FEncryptionMethod : TEncodeDecodeMethod;

    // reminder...
    fNum : integer;
    fData : Array[0..POLY1305_BLOCK_SIZE - 1] of Byte;

    FAuthDataLen : integer;
    FCipherLen : integer;
    fPolyInitComplete : boolean;
    fPolyBlkFunc : TPoly1305BlockMethod;
    fPolyEmitFunc : TPoly1305EmitMethod;

    function U8ToU32( pData : PByteArray ) : UInt32;
    procedure U32ToU8(pData : PByteArray; value : UInt32);

    procedure Poly1305Blocks( pData : PByteArray; size : integer; padBit : UInt32 );
    procedure Poly1305Emit( var mac : TBlock16Byte; const nonce : TPoly1305Nonce );
    procedure Poly1305Finalize( var mac : TBlock16Byte );

    procedure Poly1305Init_SSE( initVec : PByte );
    procedure Poly1305Blocks_SSE( pData : PByteArray; size : integer );
    procedure Poly1305Emit_SSE( var mac : TBlock16Byte );

    procedure Burn;
  protected
    // ###########################################
    // #### base functionality

    // ###########################################
    // #### Authentication block functions
    procedure BeginPoly1304Auth;
  public
    class var UseSSE : boolean;

    constructor Create;

    procedure UpdatePoly( pData : PByteArray; size : integer);
    procedure InitInternal(const InitVector : T32ByteArray);
    procedure PadAndFinalizeAEAD;
    procedure Finalize;

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

    /// <summary>
    ///   Encodes a block of data using the supplied cipher.
    ///   The function can be called multiple times. Internally the
    ///   hash is updated on each call.
    /// </summary>
    procedure Encode(Source, Dest  : PUInt8Array;
                           CiphertextSize    : Integer); override;

    /// <summary>
    ///   Decodes a block of data using the supplied cipher.
    ///   The function can be called multiple times. Internally the
    ///   hash is updated on each call.
    /// </summary>
    procedure Decode(Source,
                        Dest   : PUInt8Array;
                        Size   : Integer
                        ); override;
  end;

implementation

{$R-}{$Q-}

//CONSTANT_TIME_CARRY(a,b) ( \
//         (a ^ ((a ^ b) | ((a - b) ^ b))) >> (sizeof(a) * 8 - 1) \
//         )
function ConstTimeCarray32(a, b : UInt32 ) : UInt32; inline;
begin
     Result := (a xor ( (a xor b) or (a - b) xor b )) shr 31;
end;

{ TPoly1305 }

procedure TPoly1305.BeginPoly1304Auth;
var aLen : integer;
    vec : TBytes;
begin
     InitInternal(fIV);

     // update the polynom with the unencrypted authentication data
     FAuthDataLen := Length(FDataToAuthenticate);
     if fAuthDataLen > 0 then
     begin
          // pad to blocksize if ncessary
          aLen := Length(FDataToAuthenticate);
          if aLen mod POLY1305_BLOCK_SIZE <> 0 then
          begin
            aLen := aLen + POLY1305_BLOCK_SIZE - aLen mod POLY1305_BLOCK_SIZE;
            SetLength(vec, aLen);
            Move(FDataToAuthenticate[0], vec[0], FAuthDataLen);
            //vec[FAuthDataLen] := 1;
          end
          else
              vec := FDataToAuthenticate;
          fPolyBlkFunc( @vec[0], POLY1305_BLOCK_SIZE);
     end;
     FCipherLen := 0;
end;


procedure TPoly1305.Burn;
begin
     FillChar(FH, sizeof(FH), 0);
     FillChar(FNonce, sizeof(FNonce), 0);
     FillChar(FR, sizeof(FR), 0);
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

     fPPoly1305State := @fPoly1305State[0];
     FH := @fPoly1305State[0];
     FR := @fPoly1305State[sizeof(THarr)];

     if useSSE then
     begin
          fPolyBlkFunc := Poly1305Blocks_SSE; // Poly1305Blocks_AVX
          fPolyEmitFunc := Poly1305Emit_SSE;
     end
     else
     begin
          fPolyBlkFunc := UpdatePoly;
          fPolyEmitFunc := Poly1305Finalize;
     end;
end;

procedure TPoly1305.Decode(Source, Dest: PUInt8Array; Size: Integer);
begin
  if not fPolyInitComplete then
     BeginPoly1304Auth;

  fPolyBlkFunc( PByteArray( Source ), Size );
  inc( FCipherLen, Size );

  FEncryptionMethod( Source, Dest, Size );
end;

procedure TPoly1305.Encode(Source, Dest: PUInt8Array;
  CiphertextSize: Integer);
begin
  if not fPolyInitComplete then
     BeginPoly1304Auth;

  FEncryptionMethod( Source, Dest, CipherTextSize );
  fPolyBlkFunc( PByteArray( dest ), CipherTextSize );
  inc( FCipherLen, CipherTextSize );
end;


procedure TPoly1305.Finalize;
var mac : TBlock16Byte;
begin
     if not fPolyInitComplete then
        BeginPoly1304Auth;

     fPolyEmitFunc( mac );

     SetLength(FCalcAuthenticationTag, sizeof(mac));
     Move(mac, FCalcAuthenticationTag[0], sizeof(mac));

     FillChar(mac, sizeof(mac), 0);
     Burn;
end;

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

     FAuthDataLen := 0;
     FCipherLen := 0;
     FEncryptionMethod := EncryptionMethod;
end;

procedure TPoly1305.InitInternal(const InitVector: T32ByteArray);
begin
     fPolyInitComplete := True;

     if UseSSE then
     begin
          Poly1305Init_SSE(@initVector[0]);
     end
     else
     begin
          FillChar(FH^, sizeof(FH^), 0);

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
    end;

    fNum := 0;

end;

procedure TPoly1305.PadAndFinalizeAEAD;
var lens : Array[0..1] of UInt64;
begin
     if not fPolyInitComplete then
        BeginPoly1304Auth;

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
     lens[0] := FAuthDataLen;
     lens[1] := FCipherLen;
     Poly1305Blocks(@lens[0], POLY1305_BLOCK_SIZE, 1);

     Finalize;
end;

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
          d1 := UInt64(h1) + d0 shr 32 + U8ToU32(@pData^[4]);
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

type
  XMMWORD = Array[0..7] of Word;

// dump from poly1305-donna-x86-sse2-incremental-source.c
procedure _poly1305_init_ext_sse2(st : TPoly1305.PPoly1305_state_internal_t; key : PByte; bytes : integer); cdecl;
asm
   push	ebp
   pxor	xmm0, xmm0
   mov	ebp, esp
   push	edi
   push	esi
   push	ebx
   and	esp, -8
   sub	esp, 56
   mov	edx, DWORD PTR [ebp+12]
   mov	eax, DWORD PTR [ebp+8]
   movups	XMMWORD PTR [eax+32], xmm0
   movups	XMMWORD PTR [eax], xmm0
   movups	XMMWORD PTR [eax+16], xmm0
   mov	ebx, DWORD PTR [edx]
   mov	eax, DWORD PTR [edx+4]
   mov	ecx, DWORD PTR [edx+8]
   mov	edi, DWORD PTR [edx+12]
   mov	esi, ebx
   shr	ebx, 26
   and	esi, 67108863
   mov	DWORD PTR [esp+40], esi
   mov	esi, eax
   shr	eax, 20
   sal	esi, 6
   or	esi, ebx
   mov	ebx, esi
   mov	esi, DWORD PTR [esp+40]
   and	ebx, 67108611
   mov	DWORD PTR [esp+36], ebx
   mov	ebx, ecx
   shr	ecx, 14
   sal	ebx, 12
   or	ebx, eax
   mov	eax, edi
   shr	edi, 8
   sal	eax, 18
   and	ebx, 67092735
   and	edi, 1048575
   or	eax, ecx
   mov	ecx, eax
   mov	eax, DWORD PTR [ebp+8]
   and	ecx, 66076671
   mov	DWORD PTR [eax+40], esi
   mov	esi, eax
   mov	eax, DWORD PTR [esp+36]
   mov	DWORD PTR [esi+48], ebx
   mov	DWORD PTR [esi+52], ecx
   mov	DWORD PTR [esi+56], edi
   mov	DWORD PTR [esi+44], eax
   mov	eax, DWORD PTR [edx+16]
   mov	DWORD PTR [esi+100], eax
   mov	eax, DWORD PTR [edx+20]
   mov	DWORD PTR [esi+104], eax
   mov	eax, DWORD PTR [edx+24]
   mov	DWORD PTR [esi+108], eax
   mov	eax, DWORD PTR [edx+28]
   lea	edx, [ecx+ecx*4]
   mov	DWORD PTR [esi+112], eax
   mov	esi, edx
   lea	edx, [edi+edi]
   mov	DWORD PTR [esp+28], edi
   lea	edi, [ebx+ebx]
   mov	eax, edi
   mov	DWORD PTR [esp+48], edx
   mul	esi
   mov	DWORD PTR [esp+12], esi
   mov	DWORD PTR [esp+32], ebx
   lea	ebx, [ebx+ebx*4]
   mov	esi, eax
   mov	eax, DWORD PTR [esp+36]
   mov	edi, edx
   lea	eax, [eax+eax*4]
   mul	DWORD PTR [esp+48]
   add	esi, eax
   mov	eax, DWORD PTR [esp+40]
   adc	edi, edx
   mul	eax
   add	esi, eax
   adc	edi, edx
   mov	eax, esi
   mov	edx, edi
   mov	edi, DWORD PTR [esp+36]
   mov	DWORD PTR [esp], eax
   and	eax, 67108863
   mov	DWORD PTR [esp+4], edx
   lea	esi, [edi+edi]
   mov	DWORD PTR [esp+8], eax
   mov	eax, ebx
   mov	DWORD PTR [esp+20], esi
   mul	DWORD PTR [esp+48]
   mov	esi, DWORD PTR [esp+40]
   lea	edi, [esi+esi]
   lea	esi, [ecx+ecx]
   mov	DWORD PTR [esp+24], edi
   mov	edi, edx
   mov	DWORD PTR [esp+16], esi
   mov	esi, eax
   mov	eax, DWORD PTR [esp+20]
   mul	DWORD PTR [esp+40]
   add	esi, eax
   mov	eax, ecx
   mov	ecx, DWORD PTR [esp+36]
   adc	edi, edx
   mul	DWORD PTR [esp+12]
   add	eax, esi
   mov	esi, DWORD PTR [esp]
   adc	edx, edi
   mov	edi, DWORD PTR [esp+4]
   shrd	esi, edi, 26
   shr	edi, 26
   add	esi, eax
   mov	eax, esi
   adc	edi, edx
   and	eax, 67108863
   mov	DWORD PTR [esp], eax
   mov	eax, ecx
   mul	ecx
   mov	ecx, eax
   mov	ebx, edx
   mov	eax, DWORD PTR [esp+32]
   mul	DWORD PTR [esp+24]
   add	ecx, eax
   mov	eax, DWORD PTR [esp+12]
   adc	ebx, edx
   mul	DWORD PTR [esp+48]
   add	eax, ecx
   adc	edx, ebx
   shrd	esi, edi, 26
   shr	edi, 26
   add	esi, eax
   mov	eax, esi
   adc	edi, edx
   and	eax, 67108863
   mov	DWORD PTR [esp+48], eax
   mov	eax, DWORD PTR [esp+40]
   mul	DWORD PTR [esp+16]
   mov	ecx, eax
   mov	ebx, edx
   mov	eax, DWORD PTR [esp+20]
   mul	DWORD PTR [esp+32]
   add	ecx, eax
   adc	ebx, edx
   mov	edx, DWORD PTR [esp+28]
   lea	eax, [edx+edx*4]
   mul	edx
   add	eax, ecx
   adc	edx, ebx
   shrd	esi, edi, 26
   shr	edi, 26
   add	eax, esi
   mov	DWORD PTR [esp+40], eax
   mov	ebx, DWORD PTR [esp+32]
   adc	edx, edi
   mov	esi, eax
   mov	DWORD PTR [esp+44], edx
   and	esi, 67108863
   mov	edi, DWORD PTR [esp+48]
   mov	eax, ebx
   mul	ebx
   mov	ecx, eax
   mov	ebx, edx
   mov	eax, DWORD PTR [esp+28]
   mul	DWORD PTR [esp+24]
   add	ecx, eax
   mov	eax, DWORD PTR [esp+36]
   adc	ebx, edx
   mul	DWORD PTR [esp+16]
   add	eax, ecx
   mov	ecx, DWORD PTR [esp+40]
   adc	edx, ebx
   mov	ebx, DWORD PTR [esp+44]
   shrd	ecx, ebx, 26
   shr	ebx, 26
   add	eax, ecx
   adc	edx, ebx
   mov	ecx, eax
   mov	ebx, DWORD PTR [esp+8]
   shrd	eax, edx, 26
   mov	edx, DWORD PTR [esp]
   and	ecx, 67108863
   lea	eax, [eax+eax*4]
   mov	DWORD PTR [esp+32], ecx
   add	eax, ebx
   mov	ebx, eax
   shr	eax, 26
   add	edx, eax
   mov	eax, DWORD PTR [ebp+8]
   and	ebx, 67108863
   mov	DWORD PTR [esp+40], ebx
   mov	DWORD PTR [eax+60], ebx
   mov	DWORD PTR [eax+64], edx
   mov	DWORD PTR [eax+68], edi
   mov	DWORD PTR [eax+72], esi
   mov	DWORD PTR [eax+76], ecx
   lea	eax, [esi+esi*4]
   mov	ebx, eax
   lea	eax, [ecx+ecx]
   lea	ecx, [edi+edi]
   mov	DWORD PTR [esp+36], edx
   mov	DWORD PTR [esp+28], eax
   mov	eax, ecx
   lea	edi, [edi+edi*4]
   mul	ebx
   mov	DWORD PTR [esp+12], ebx
   mov	ecx, eax
   mov	eax, DWORD PTR [esp+40]
   mov	ebx, edx
   mul	eax
   add	ecx, eax
   adc	ebx, edx
   mov	edx, DWORD PTR [esp+36]
   lea	eax, [edx+edx*4]
   mul	DWORD PTR [esp+28]
   add	ecx, eax
   adc	ebx, edx
   mov	edx, DWORD PTR [esp+36]
   lea	eax, [edx+edx]
   lea	edx, [esi+esi]
   mov	DWORD PTR [esp+16], eax
   mov	eax, DWORD PTR [esp+40]
   mov	DWORD PTR [esp+24], edx
   add	eax, eax
   mov	DWORD PTR [esp+20], eax
   mov	eax, ecx
   and	eax, 67108863
   mov	DWORD PTR [esp+8], eax
   mov	eax, edi
   mul	DWORD PTR [esp+28]
   mov	DWORD PTR [esp], eax
   mov	eax, esi
   mov	DWORD PTR [esp+4], edx
   mul	DWORD PTR [esp+12]
   mov	esi, eax
   mov	edi, edx
   add	esi, DWORD PTR [esp]
   mov	eax, DWORD PTR [esp+16]
   adc	edi, DWORD PTR [esp+4]
   mul	DWORD PTR [esp+40]
   add	eax, esi
   adc	edx, edi
   shrd	ecx, ebx, 26
   shr	ebx, 26
   add	ecx, eax
   mov	eax, DWORD PTR [esp+48]
   adc	ebx, edx
   mul	DWORD PTR [esp+20]
   mov	esi, ecx
   and	esi, 67108863
   mov	DWORD PTR [esp], esi
   mov	esi, eax
   mov	eax, DWORD PTR [esp+36]
   mov	edi, edx
   mul	eax
   add	esi, eax
   mov	eax, DWORD PTR [esp+28]
   adc	edi, edx
   mul	DWORD PTR [esp+12]
   add	eax, esi
   adc	edx, edi
   shrd	ecx, ebx, 26
   shr	ebx, 26
   add	eax, ecx
   mov	ecx, DWORD PTR [esp+32]
   adc	edx, ebx
   mov	esi, eax
   lea	ebx, [ecx+ecx*4]
   mov	edi, edx
   mov	eax, ebx
   mov	DWORD PTR [esp+44], edi
   mul	ecx
   mov	ecx, eax
   mov	ebx, edx
   mov	eax, DWORD PTR [esp+40]
   mov	DWORD PTR [esp+40], esi
   mul	DWORD PTR [esp+24]
   add	ecx, eax
   mov	eax, DWORD PTR [esp+16]
   adc	ebx, edx
   mul	DWORD PTR [esp+48]
   add	eax, ecx
   adc	edx, ebx
   shrd	esi, edi, 26
   shr	edi, 26
   add	esi, eax
   mov	eax, DWORD PTR [esp+24]
   adc	edi, edx
   mul	DWORD PTR [esp+36]
   mov	ecx, eax
   mov	ebx, edx
   mov	eax, DWORD PTR [esp+32]
   mul	DWORD PTR [esp+20]
   add	ecx, eax
   mov	eax, DWORD PTR [esp+48]
   adc	ebx, edx
   mul	eax
   add	eax, ecx
   mov	ecx, esi
   adc	edx, ebx
   shrd	ecx, edi, 26
   mov	ebx, edi
   shr	ebx, 26
   add	eax, ecx
   adc	edx, ebx
   mov	DWORD PTR [esp+48], eax
   mov	ebx, DWORD PTR [ebp+8]
   shrd	eax, edx, 26
   mov	DWORD PTR [esp+52], edx
   lea	edx, [eax+eax*4]
   mov	eax, DWORD PTR [esp+8]
   add	edx, eax
   mov	eax, DWORD PTR [esp]
   mov	ecx, edx
   shr	edx, 26
   add	edx, eax
   and	ecx, 67108863
   mov	DWORD PTR [ebx+80], ecx
   mov	DWORD PTR [ebx+84], edx
   mov	edx, DWORD PTR [esp+40]
   mov	eax, DWORD PTR [esp+48]
   mov	DWORD PTR [ebx+116], 0
   and	edx, 67108863
   mov	DWORD PTR [ebx+88], edx
   mov	edx, esi
   and	eax, 67108863
   and	edx, 67108863
   mov	DWORD PTR [ebx+96], eax
   mov	DWORD PTR [ebx+92], edx
   lea	esp, [ebp-12]
   pop	ebx
   pop	esi
   pop	edi
   pop	ebp
end;

procedure _Poly1305_Blocks_sse2( st : TPoly1305.PPoly1305_state_internal_t; m : PByte; bytes : integer ); cdecl;
label L6, L7, L8, L10, L12, L13, L14, L15, L16, L18, L19, L28, L29;
const LC3 : TPoly1305.TXMM = ( 1, 0, 0, 0 );
	     LC4 : TPoly1305.TXMM = ( 16777216, 0, 16777216, 0);
	     LC5 : TPoly1305.TXMM = ( 67108863, 0, 67108863, 0);
	     LC6 : TPoly1305.TXMM = ( 5, 0, 5, 0);
asm
   push	ebp
   mov	ebp, esp
   push	edi
   push	esi
   push	ebx
   and	esp, -16
   sub	esp, 1168
   mov	esi, DWORD PTR [ebp+8]
   mov	eax, DWORD PTR [ebp+12]
   movdqa	xmm0, XMMWORD PTR LC4
   mov	ecx, DWORD PTR [ebp+16]
   mov	edx, DWORD PTR [esi+116]
   movaps	XMMWORD PTR [esp+1136], xmm0
   test	dl, 4
   je	L6
   movdqa	xmm7, xmm0
   psrldq	xmm7, 8
   movaps	XMMWORD PTR [esp+1136], xmm7
L6:
   test	dl, 8
   je	L7
   pxor	xmm7, xmm7
   movaps	XMMWORD PTR [esp+1136], xmm7
L7:
   test	dl, 1
   jne	L8
   movq	xmm0, QWORD PTR [eax+16]
   movq	xmm1, QWORD PTR [eax]
   or	edx, 1
   add	eax, 32
   movq	xmm2, QWORD PTR [eax-8]
   sub	ecx, 32
   movdqa	xmm7, XMMWORD PTR LC5
   movdqa	xmm5, XMMWORD PTR LC5
   punpcklqdq	xmm1, xmm0
   movq	xmm0, QWORD PTR [eax-24]
   mov	DWORD PTR [esi+116], edx
   pand	xmm7, xmm1
   punpcklqdq	xmm0, xmm2
   movdqa	xmm2, xmm1
   psrlq	xmm2, 26
   psrlq	xmm1, 52
   pand	xmm2, XMMWORD PTR LC5
   movaps	XMMWORD PTR [esp+1120], xmm2
   movdqa	xmm2, xmm0
   psrlq	xmm0, 40
   por	xmm0, XMMWORD PTR [esp+1136]
   psllq	xmm2, 12
   por	xmm1, xmm2
   movdqa	xmm2, xmm0
   pand	xmm5, xmm1
   psrlq	xmm1, 26
   pand	xmm1, XMMWORD PTR LC5
   test	dl, 48
   je	L10
L29:
   movd	xmm3, DWORD PTR [esi+56]
   and	edx, 16
   movdqu	xmm4, XMMWORD PTR [esi+40]
   movaps	XMMWORD PTR [esp+320], xmm3
   jne	L28
   movdqa	xmm6, xmm4
   movdqa	xmm0, xmm4
   punpckldq	xmm6, XMMWORD PTR LC3
   punpckhdq	xmm0, XMMWORD PTR LC3
L12:
   pshufd	xmm4, xmm6, 80
   movaps	XMMWORD PTR [esp+304], xmm4
   pshufd	xmm4, xmm6, 250
   movaps	XMMWORD PTR [esp+336], xmm4
   pshufd	xmm4, xmm0, 80
   pshufd	xmm0, xmm0, 250
   movaps	XMMWORD PTR [esp+288], xmm4
   movaps	XMMWORD PTR [esp+272], xmm0
   jmp	L13
 //  .p2align 4,,10
 //  .p2align 3
L8:
   movdqu	xmm1, XMMWORD PTR [esi]
   movdqu	xmm0, XMMWORD PTR [esi+16]
   movdqu	xmm7, XMMWORD PTR [esi]
   pshufd	xmm1, xmm1, 250
   pshufd	xmm5, xmm0, 80
   movaps	XMMWORD PTR [esp+1120], xmm1
   pshufd	xmm1, xmm0, 250
   movdqu	xmm0, XMMWORD PTR [esi+32]
   pshufd	xmm7, xmm7, 80
   pshufd	xmm2, xmm0, 80
   test	dl, 48
   jne	L29
L10:
   movdqu	xmm0, XMMWORD PTR [esi+60]
   pshufd	xmm0, xmm0, 0
   movaps	XMMWORD PTR [esp+304], xmm0
   movdqu	xmm0, XMMWORD PTR [esi+60]
   pshufd	xmm0, xmm0, 85
   movaps	XMMWORD PTR [esp+336], xmm0
   movdqu	xmm0, XMMWORD PTR [esi+60]
   pshufd	xmm0, xmm0, 170
   movaps	XMMWORD PTR [esp+288], xmm0
   movdqu	xmm0, XMMWORD PTR [esi+60]
   pshufd	xmm0, xmm0, 255
   movaps	XMMWORD PTR [esp+272], xmm0
   movd	xmm0, DWORD PTR [esi+76]
   pshufd	xmm0, xmm0, 0
   movaps	XMMWORD PTR [esp+320], xmm0
L13:
   movdqa	xmm0, XMMWORD PTR [esp+336]
   movdqa	xmm4, XMMWORD PTR [esp+288]
   pmuludq	xmm0, XMMWORD PTR LC6
   movaps	XMMWORD PTR [esp+48], xmm0
   movdqa	xmm6, XMMWORD PTR [esp+320]
   movdqa	xmm0, XMMWORD PTR [esp+272]
   pmuludq	xmm6, XMMWORD PTR LC6
   movaps	XMMWORD PTR [esp+32], xmm6
   pmuludq	xmm4, XMMWORD PTR LC6
   pmuludq	xmm0, XMMWORD PTR LC6
   cmp	ecx, 63
   jbe	L14
   movdqu	xmm6, XMMWORD PTR [esi+80]
   lea	edx, [ecx-64]
   movaps	XMMWORD PTR [esp], xmm0
   movaps	XMMWORD PTR [esp+160], xmm0
   and	edx, -64
   movdqa	xmm0, XMMWORD PTR [esp+1120]
   pshufd	xmm6, xmm6, 0
   movaps	XMMWORD PTR [esp+112], xmm4
   lea	edx, [eax+64+edx]
   movaps	XMMWORD PTR [esp+208], xmm6
   movdqu	xmm6, XMMWORD PTR [esi+80]
   movaps	XMMWORD PTR [esp+16], xmm4
   pshufd	xmm3, xmm6, 85
   pshufd	xmm6, xmm6, 170
   movaps	XMMWORD PTR [esp+256], xmm6
   movdqu	xmm6, XMMWORD PTR [esi+80]
   movaps	XMMWORD PTR [esp+192], xmm3
   pshufd	xmm6, xmm6, 255
   movaps	XMMWORD PTR [esp+240], xmm6
   movd	xmm6, DWORD PTR [esi+96]
   pshufd	xmm6, xmm6, 0
   movaps	XMMWORD PTR [esp+224], xmm6
   movdqa	xmm6, XMMWORD PTR LC5
   movaps	XMMWORD PTR [esp+1152], xmm6
   movdqa	xmm6, XMMWORD PTR [esp+32]
   movaps	XMMWORD PTR [esp+176], xmm6
   movdqa	xmm6, XMMWORD PTR [esp+240]
   pmuludq	xmm6, XMMWORD PTR LC6
   movaps	XMMWORD PTR [esp+144], xmm6
   movdqa	xmm6, XMMWORD PTR [esp+224]
   pmuludq	xmm6, XMMWORD PTR LC6
   movaps	XMMWORD PTR [esp+128], xmm6
   movdqa	xmm6, XMMWORD PTR [esp+48]
   movaps	XMMWORD PTR [esp+96], xmm6
   movdqa	xmm6, xmm3
   pmuludq	xmm6, XMMWORD PTR LC6
   movaps	XMMWORD PTR [esp+80], xmm6
   movdqa	xmm6, XMMWORD PTR [esp+256]
   pmuludq	xmm6, XMMWORD PTR LC6
   movaps	XMMWORD PTR [esp+64], xmm6
   movdqa	xmm6, xmm2
   movdqa	xmm2, xmm1
   movdqa	xmm1, xmm7
//   .p2align 4,,10
//   .p2align 3
L15:
   movdqa	xmm7, XMMWORD PTR [esp+64]
   movdqa	xmm4, XMMWORD PTR [esp+80]
   add	eax, 64
   movdqa	xmm3, xmm7
   pmuludq	xmm4, xmm6
   pmuludq	xmm3, xmm2
   movaps	XMMWORD PTR [esp+1120], xmm4
   movaps	XMMWORD PTR [esp+1104], xmm3
   movdqa	xmm3, xmm7
   movdqa	xmm7, XMMWORD PTR [esp+144]
   pmuludq	xmm3, xmm6
   movdqa	xmm4, xmm7
   pmuludq	xmm4, xmm2
   movaps	XMMWORD PTR [esp+1088], xmm3
   movdqa	xmm3, xmm7
   pmuludq	xmm3, xmm6
   movaps	XMMWORD PTR [esp+1072], xmm4
   movdqa	xmm4, xmm7
   movdqa	xmm7, XMMWORD PTR [esp+128]
   pmuludq	xmm4, xmm5
   movaps	XMMWORD PTR [esp+1056], xmm3
   movdqa	xmm3, xmm7
   pmuludq	xmm3, xmm5
   movaps	XMMWORD PTR [esp+1040], xmm4
   movdqa	xmm4, xmm7
   pmuludq	xmm4, xmm6
   movaps	XMMWORD PTR [esp+992], xmm3
   movdqa	xmm3, XMMWORD PTR [esp+208]
   movaps	XMMWORD PTR [esp+1024], xmm4
   movdqa	xmm4, xmm7
   pmuludq	xmm6, xmm3
   pmuludq	xmm4, xmm0
   movaps	XMMWORD PTR [esp+944], xmm6
   movdqa	xmm6, xmm3
   movaps	XMMWORD PTR [esp+1008], xmm4
   movdqa	xmm4, xmm7
   pmuludq	xmm6, xmm1
   pmuludq	xmm4, xmm2
   movaps	XMMWORD PTR [esp+928], xmm6
   movdqa	xmm6, xmm3
   movaps	XMMWORD PTR [esp+976], xmm4
   movdqa	xmm4, xmm3
   pmuludq	xmm6, xmm0
   pmuludq	xmm4, xmm2
   movaps	XMMWORD PTR [esp+912], xmm6
   movdqa	xmm6, xmm3
   movaps	XMMWORD PTR [esp+960], xmm4
   pmuludq	xmm6, xmm5
   movdqa	xmm4, XMMWORD PTR [esp+192]
   pmuludq	xmm2, xmm4
   movdqa	xmm3, xmm4
   pmuludq	xmm3, xmm5
   movaps	XMMWORD PTR [esp+896], xmm6
   movdqa	xmm6, XMMWORD PTR [esp+256]
   movaps	XMMWORD PTR [esp+864], xmm2
   movdqa	xmm2, xmm4
   pmuludq	xmm5, xmm6
   pmuludq	xmm2, xmm1
   movaps	XMMWORD PTR [esp+880], xmm3
   movaps	XMMWORD PTR [esp+800], xmm5
   movdqa	xmm5, xmm6
   movaps	XMMWORD PTR [esp+848], xmm2
   movdqa	xmm2, xmm4
   pmuludq	xmm5, xmm1
   pmuludq	xmm2, xmm0
   movaps	XMMWORD PTR [esp+784], xmm5
   movaps	XMMWORD PTR [esp+832], xmm2
   movdqa	xmm2, xmm6
   pmuludq	xmm2, xmm0
   movaps	XMMWORD PTR [esp+816], xmm2
   movdqa	xmm2, XMMWORD PTR [esp+240]
   movdqa	xmm5, xmm2
   pmuludq	xmm0, xmm2
   pmuludq	xmm5, xmm1
   movaps	XMMWORD PTR [esp+752], xmm0
   movaps	XMMWORD PTR [esp+768], xmm5
   pmuludq	xmm1, XMMWORD PTR [esp+224]
   movq	xmm0, QWORD PTR [eax-64]
   movq	xmm4, QWORD PTR [eax-56]
   movaps	XMMWORD PTR [esp+736], xmm1
   movq	xmm1, QWORD PTR [eax-48]
   movdqa	xmm6, XMMWORD PTR [esp+96]
   movdqa	xmm7, XMMWORD PTR [esp+112]
   punpcklqdq	xmm0, xmm1
   movq	xmm1, QWORD PTR [eax-40]
   punpcklqdq	xmm4, xmm1
   movdqa	xmm1, xmm0
   movdqa	xmm2, xmm4
   psrlq	xmm1, 26
   movdqa	xmm3, xmm4
   psrlq	xmm4, 40
   psrlq	xmm3, 14
   por	xmm4, XMMWORD PTR [esp+1136]
   pand	xmm3, XMMWORD PTR [esp+1152]
   psllq	xmm2, 12
   pmuludq	xmm6, xmm4
   movdqa	xmm5, xmm2
   movdqa	xmm2, xmm0
   psrlq	xmm2, 52
   por	xmm2, xmm5
   pand	xmm2, XMMWORD PTR [esp+1152]
   movaps	XMMWORD PTR [esp+720], xmm6
   movdqa	xmm6, xmm7
   pmuludq	xmm6, xmm3
   movaps	XMMWORD PTR [esp+704], xmm6
   movdqa	xmm6, xmm7
   movdqa	xmm7, XMMWORD PTR [esp+160]
   pmuludq	xmm6, xmm4
   movdqa	xmm5, xmm7
   pmuludq	xmm5, xmm2
   movaps	XMMWORD PTR [esp+688], xmm6
   movdqa	xmm6, xmm7
   pmuludq	xmm6, xmm3
   movaps	XMMWORD PTR [esp+640], xmm5
   movaps	XMMWORD PTR [esp+672], xmm6
   movdqa	xmm6, xmm7
   movdqa	xmm7, XMMWORD PTR [esp+1152]
   pmuludq	xmm6, xmm4
   pand	xmm1, xmm7
   pand	xmm0, xmm7
   movaps	XMMWORD PTR [esp+656], xmm6
   movdqa	xmm6, XMMWORD PTR [esp+176]
   movdqa	xmm5, xmm6
   pmuludq	xmm5, xmm4
   movaps	XMMWORD PTR [esp+624], xmm5
   movdqa	xmm5, xmm6
   pmuludq	xmm5, xmm1
   movaps	XMMWORD PTR [esp+608], xmm5
   movdqa	xmm5, xmm6
   pmuludq	xmm5, xmm2
   movaps	XMMWORD PTR [esp+592], xmm5
   movdqa	xmm5, xmm6
   pmuludq	xmm5, xmm3
   movaps	XMMWORD PTR [esp+576], xmm5
   movdqa	xmm5, XMMWORD PTR [esp+304]
   movdqa	xmm6, xmm5
   pmuludq	xmm4, xmm5
   pmuludq	xmm6, xmm3
   movaps	XMMWORD PTR [esp+544], xmm4
   movdqa	xmm4, xmm5
   movaps	XMMWORD PTR [esp+560], xmm6
   movdqa	xmm6, xmm5
   pmuludq	xmm4, xmm0
   pmuludq	xmm6, xmm1
   movaps	XMMWORD PTR [esp+528], xmm6
   movdqa	xmm6, xmm5
   pmuludq	xmm6, xmm2
   movaps	XMMWORD PTR [esp+512], xmm6
   movdqa	xmm6, XMMWORD PTR [esp+336]
   movdqa	xmm5, xmm6
   pmuludq	xmm3, xmm6
   pmuludq	xmm5, xmm2
   movaps	XMMWORD PTR [esp+480], xmm3
   movaps	XMMWORD PTR [esp+496], xmm5
   movdqa	xmm5, xmm6
   pmuludq	xmm5, xmm0
   movaps	XMMWORD PTR [esp+464], xmm5
   movdqa	xmm5, xmm6
   movdqu	xmm7, XMMWORD PTR [eax-16]
   paddq	xmm4, XMMWORD PTR [esp+608]
   pmuludq	xmm5, xmm1
   movaps	XMMWORD PTR [esp+448], xmm5
   movdqa	xmm5, XMMWORD PTR [esp+288]
   pmuludq	xmm2, xmm5
   movdqa	xmm3, xmm5
   pmuludq	xmm3, xmm1
   movaps	XMMWORD PTR [esp+416], xmm2
   movdqa	xmm2, xmm5
   pmuludq	xmm2, xmm0
   movaps	XMMWORD PTR [esp+432], xmm3
   movdqa	xmm3, XMMWORD PTR [esp+272]
   pmuludq	xmm1, xmm3
   movaps	XMMWORD PTR [esp+400], xmm2
   movdqa	xmm2, xmm3
   pmuludq	xmm2, xmm0
   pmuludq	xmm0, XMMWORD PTR [esp+320]
   movaps	XMMWORD PTR [esp+368], xmm0
   movdqu	xmm0, XMMWORD PTR [eax-32]
   movaps	XMMWORD PTR [esp+384], xmm1
   punpckldq	xmm0, xmm7
   movdqa	xmm1, xmm0
   movdqu	xmm0, XMMWORD PTR [eax-32]
   movdqa	xmm3, xmm1
   punpckhdq	xmm0, xmm7
   movdqa	xmm5, xmm2
   pxor	xmm2, xmm2
   movdqa	xmm7, xmm0
   punpckldq	xmm3, xmm2
   punpckhdq	xmm1, xmm2
   punpckldq	xmm7, xmm2
   psllq	xmm1, 6
   movdqa	xmm6, xmm3
   paddq	xmm5, XMMWORD PTR [esp+432]
   movdqa	xmm3, xmm2
   movdqa	xmm2, xmm7
   psllq	xmm2, 12
   punpckhdq	xmm0, xmm3
   movaps	XMMWORD PTR [esp+352], xmm2
   psllq	xmm0, 18
   movdqa	xmm2, XMMWORD PTR [esp+1008]
   paddq	xmm2, XMMWORD PTR [esp+1040]
   movdqa	xmm3, xmm2
   movdqa	xmm2, XMMWORD PTR [esp+1120]
   paddq	xmm2, XMMWORD PTR [esp+1104]
   paddq	xmm2, xmm3
   movdqa	xmm3, XMMWORD PTR [esp+720]
   paddq	xmm3, XMMWORD PTR [esp+928]
   paddq	xmm3, xmm2
   movdqa	xmm2, XMMWORD PTR [esp+640]
   paddq	xmm2, XMMWORD PTR [esp+704]
   paddq	xmm2, xmm3
   paddq	xmm2, xmm4
   movdqa	xmm4, XMMWORD PTR [esp+816]
   paddq	xmm4, XMMWORD PTR [esp+880]
   paddq	xmm2, xmm6
   movdqa	xmm3, xmm4
   movdqa	xmm7, xmm2
   movdqa	xmm4, XMMWORD PTR [esp+1024]
   paddq	xmm4, XMMWORD PTR [esp+960]
   psrlq	xmm7, 26
   paddq	xmm4, xmm3
   movdqa	xmm3, XMMWORD PTR [esp+624]
   paddq	xmm3, XMMWORD PTR [esp+768]
   paddq	xmm4, xmm3
   movdqa	xmm3, XMMWORD PTR [esp+496]
   paddq	xmm3, XMMWORD PTR [esp+560]
   paddq	xmm4, xmm3
   paddq	xmm4, xmm5
   movdqa	xmm5, xmm7
   paddq	xmm4, xmm0
   paddq	xmm1, xmm5
   movdqa	xmm0, XMMWORD PTR [esp+912]
   paddq	xmm0, XMMWORD PTR [esp+992]
   movdqa	xmm7, xmm4
   movdqa	xmm6, XMMWORD PTR [esp+1088]
   paddq	xmm6, XMMWORD PTR [esp+1072]
   psrlq	xmm7, 26
   movdqa	xmm3, xmm7
   paddq	xmm3, XMMWORD PTR [esp+1136]
   paddq	xmm6, xmm0
   movdqa	xmm0, XMMWORD PTR [esp+688]
   paddq	xmm0, XMMWORD PTR [esp+848]
   paddq	xmm0, xmm6
   movdqa	xmm6, XMMWORD PTR [esp+592]
   paddq	xmm6, XMMWORD PTR [esp+672]
   paddq	xmm0, xmm6
   movdqa	xmm6, XMMWORD PTR [esp+464]
   paddq	xmm6, XMMWORD PTR [esp+528]
   paddq	xmm0, xmm6
   movdqa	xmm6, XMMWORD PTR [esp+944]
   paddq	xmm6, XMMWORD PTR [esp+864]
   paddq	xmm0, xmm1
   movdqa	xmm1, XMMWORD PTR [esp+752]
   paddq	xmm1, XMMWORD PTR [esp+800]
   paddq	xmm6, xmm1
   movdqa	xmm1, XMMWORD PTR [esp+544]
   paddq	xmm1, XMMWORD PTR [esp+736]
   paddq	xmm1, xmm6
   movdqa	xmm6, XMMWORD PTR [esp+416]
   paddq	xmm6, XMMWORD PTR [esp+480]
   paddq	xmm1, xmm6
   movdqa	xmm6, XMMWORD PTR [esp+384]
   paddq	xmm6, XMMWORD PTR [esp+368]
   movdqa	xmm5, xmm6
   paddq	xmm5, xmm1
   movdqa	xmm7, xmm5
   movdqa	xmm5, XMMWORD PTR [esp+832]
   paddq	xmm5, XMMWORD PTR [esp+896]
   paddq	xmm7, xmm3
   movdqa	xmm3, XMMWORD PTR [esp+1056]
   paddq	xmm3, XMMWORD PTR [esp+976]
   movdqa	xmm6, xmm7
   movdqa	xmm7, xmm0
   paddq	xmm3, xmm5
   psrlq	xmm7, 26
   movdqa	xmm1, xmm6
   movdqa	xmm5, XMMWORD PTR [esp+656]
   paddq	xmm5, XMMWORD PTR [esp+784]
   psrlq	xmm1, 26
   pmuludq	xmm1, XMMWORD PTR LC6
   paddq	xmm5, xmm3
   movdqa	xmm3, XMMWORD PTR [esp+512]
   paddq	xmm3, XMMWORD PTR [esp+576]
   paddq	xmm3, xmm5
   movdqa	xmm5, XMMWORD PTR [esp+448]
   paddq	xmm5, XMMWORD PTR [esp+400]
   paddq	xmm3, xmm5
   movdqa	xmm5, XMMWORD PTR [esp+352]
   paddq	xmm5, xmm7
   movdqa	xmm7, XMMWORD PTR [esp+1152]
   paddq	xmm5, xmm3
   pand	xmm2, xmm7
   pand	xmm4, xmm7
   pand	xmm0, xmm7
   paddq	xmm1, xmm2
   movdqa	xmm2, xmm5
   pand	xmm6, xmm7
   movdqa	xmm3, xmm1
   psrlq	xmm2, 26
   pand	xmm5, xmm7
   psrlq	xmm3, 26
   paddq	xmm2, xmm4
   pand	xmm1, xmm7
   paddq	xmm0, xmm3
   movdqa	xmm3, xmm2
   pand	xmm2, xmm7
   psrlq	xmm3, 26
   paddq	xmm6, xmm3
   cmp	eax, edx
   jne	L15
   movaps	XMMWORD PTR [esp+1120], xmm0
   movdqa	xmm4, XMMWORD PTR [esp+16]
   movdqa	xmm7, xmm1
   and	ecx, 63
   movdqa	xmm0, XMMWORD PTR [esp]
   movdqa	xmm1, xmm2
   movdqa	xmm2, xmm6
L14:
   cmp	ecx, 31
   jbe	L16
   movdqa	xmm6, XMMWORD PTR [esp+48]
   movdqa	xmm3, XMMWORD PTR [esp+32]
   pmuludq	xmm6, xmm2
   movaps	XMMWORD PTR [esp+1152], xmm6
   movdqa	xmm6, xmm1
   pmuludq	xmm6, xmm4
   pmuludq	xmm4, xmm2
   movaps	XMMWORD PTR [esp+1104], xmm6
   movdqa	xmm6, xmm1
   pmuludq	xmm6, xmm0
   movaps	XMMWORD PTR [esp+1088], xmm4
   movaps	XMMWORD PTR [esp+1072], xmm6
   movdqa	xmm6, xmm2
   pmuludq	xmm6, xmm0
   pmuludq	xmm0, xmm5
   movaps	XMMWORD PTR [esp+1056], xmm6
   movdqa	xmm6, xmm5
   movdqa	xmm4, xmm0
   movdqa	xmm0, xmm2
   pmuludq	xmm6, xmm3
   pmuludq	xmm0, xmm3
   movaps	XMMWORD PTR [esp+1024], xmm6
   movdqa	xmm6, xmm3
   pmuludq	xmm6, xmm1
   movaps	XMMWORD PTR [esp+1040], xmm0
   movdqa	xmm0, XMMWORD PTR [esp+1120]
   pmuludq	xmm0, xmm3
   movaps	XMMWORD PTR [esp+1008], xmm6
   movdqa	xmm6, XMMWORD PTR [esp+304]
   pmuludq	xmm2, xmm6
   movdqa	xmm3, xmm6
   paddq	xmm0, xmm4
   movdqa	xmm4, XMMWORD PTR [esp+1152]
   paddq	xmm4, XMMWORD PTR [esp+1104]
   pmuludq	xmm3, xmm1
   paddq	xmm0, xmm4
   movdqa	xmm4, XMMWORD PTR [esp+1120]
   movaps	XMMWORD PTR [esp+976], xmm2
   movdqa	xmm2, xmm6
   pmuludq	xmm2, xmm7
   movaps	XMMWORD PTR [esp+992], xmm3
   movdqa	xmm3, xmm6
   pmuludq	xmm3, XMMWORD PTR [esp+1120]
   movdqa	xmm6, xmm3
   movdqa	xmm3, XMMWORD PTR [esp+304]
   paddq	xmm6, XMMWORD PTR [esp+1024]
   pmuludq	xmm3, xmm5
   paddq	xmm0, xmm2
   movdqa	xmm2, XMMWORD PTR [esp+336]
   movaps	XMMWORD PTR [esp+1104], xmm0
   movdqa	xmm0, xmm2
   pmuludq	xmm1, xmm2
   pmuludq	xmm0, xmm7
   movaps	XMMWORD PTR [esp+960], xmm3
   movdqa	xmm3, XMMWORD PTR [esp+336]
   pmuludq	xmm3, xmm5
   movaps	XMMWORD PTR [esp+928], xmm1
   movdqa	xmm1, xmm0
   movdqa	xmm0, xmm2
   pmuludq	xmm0, xmm4
   movdqa	xmm4, XMMWORD PTR [esp+1088]
   paddq	xmm4, XMMWORD PTR [esp+1072]
   movaps	XMMWORD PTR [esp+944], xmm3
   movdqa	xmm3, XMMWORD PTR [esp+288]
   paddq	xmm6, xmm4
   movdqa	xmm4, xmm6
   pmuludq	xmm5, xmm3
   movdqa	xmm2, xmm3
   movdqa	xmm6, XMMWORD PTR [esp+272]
   pmuludq	xmm2, XMMWORD PTR [esp+1120]
   paddq	xmm4, xmm1
   movaps	XMMWORD PTR [esp+1152], xmm4
   movdqa	xmm4, xmm3
   movdqa	xmm1, xmm6
   movdqa	xmm3, XMMWORD PTR [esp+1120]
   pmuludq	xmm4, xmm7
   pmuludq	xmm1, xmm7
   paddq	xmm0, XMMWORD PTR [esp+960]
   paddq	xmm2, XMMWORD PTR [esp+944]
   pmuludq	xmm3, xmm6
   movdqa	xmm6, XMMWORD PTR [esp+320]
   pmuludq	xmm6, xmm7
   movdqa	xmm7, XMMWORD PTR [esp+1056]
   paddq	xmm7, XMMWORD PTR [esp+1008]
   paddq	xmm0, xmm7
   paddq	xmm0, xmm4
   paddq	xmm3, xmm5
   movdqa	xmm4, XMMWORD PTR [esp+1040]
   paddq	xmm4, XMMWORD PTR [esp+992]
   paddq	xmm2, xmm4
   paddq	xmm2, xmm1
   movdqa	xmm1, XMMWORD PTR [esp+976]
   paddq	xmm1, XMMWORD PTR [esp+928]
   paddq	xmm3, xmm1
   paddq	xmm3, xmm6
   test	eax, eax
   je	L18
   movdqu	xmm5, XMMWORD PTR [eax+16]
   movdqu	xmm1, XMMWORD PTR [eax]
   paddq	xmm3, XMMWORD PTR [esp+1136]
   punpckldq	xmm1, xmm5
   movdqa	xmm4, xmm1
   movdqu	xmm1, XMMWORD PTR [eax]
   movdqa	xmm6, xmm4
   punpckhdq	xmm1, xmm5
   pxor	xmm5, xmm5
   punpckldq	xmm6, xmm5
   punpckhdq	xmm4, xmm5
   movdqa	xmm7, xmm6
   psllq	xmm4, 6
   movdqa	xmm6, xmm1
   punpckldq	xmm6, xmm5
   punpckhdq	xmm1, xmm5
   movdqa	xmm5, XMMWORD PTR [esp+1104]
   psllq	xmm6, 12
   psllq	xmm1, 18
   paddq	xmm5, xmm7
   paddq	xmm0, xmm6
   movaps	XMMWORD PTR [esp+1104], xmm5
   paddq	xmm2, xmm1
   movdqa	xmm5, XMMWORD PTR [esp+1152]
   paddq	xmm5, xmm4
   movaps	XMMWORD PTR [esp+1152], xmm5
L18:
   movdqa	xmm7, XMMWORD PTR [esp+1104]
   movdqa	xmm4, xmm2
   pand	xmm2, XMMWORD PTR LC5
   psrlq	xmm4, 26
   movdqa	xmm1, xmm7
   paddq	xmm4, xmm3
   pand	xmm7, XMMWORD PTR LC5
   psrlq	xmm1, 26
   movdqa	xmm3, xmm4
   paddq	xmm1, XMMWORD PTR [esp+1152]
   pand	xmm4, XMMWORD PTR LC5
   psrlq	xmm3, 26
   pmuludq	xmm3, XMMWORD PTR LC6
   paddq	xmm7, xmm3
   movdqa	xmm5, xmm1
   movdqa	xmm3, xmm7
   pand	xmm1, XMMWORD PTR LC5
   psrlq	xmm5, 26
   psrlq	xmm3, 26
   pand	xmm7, XMMWORD PTR LC5
   paddq	xmm0, xmm5
   paddq	xmm3, xmm1
   movdqa	xmm1, XMMWORD PTR LC5
   movdqa	xmm6, xmm0
   movaps	XMMWORD PTR [esp+1120], xmm3
   pand	xmm0, XMMWORD PTR LC5
   psrlq	xmm6, 26
   paddq	xmm2, xmm6
   movdqa	xmm5, xmm0
   movdqa	xmm0, xmm2
   pand	xmm1, xmm2
   psrlq	xmm0, 26
   paddq	xmm4, xmm0
   movdqa	xmm2, xmm4
L16:
   test	eax, eax
   je	L19
   pshufd	xmm3, xmm5, 8
   pshufd	xmm4, xmm7, 8
   pshufd	xmm5, xmm1, 8
   pshufd	xmm6, XMMWORD PTR [esp+1120], 8
   pshufd	xmm0, xmm2, 8
   movdqa	xmm1, xmm3
   movdqa	xmm2, xmm4
   punpcklqdq	xmm2, xmm6
   punpcklqdq	xmm1, xmm5
   movq	QWORD PTR [esi+32], xmm0
   movups	XMMWORD PTR [esi], xmm2
   movups	XMMWORD PTR [esi+16], xmm1
   lea	esp, [ebp-12]
   pop	ebx
   pop	esi
   pop	edi
   pop	ebp
   ret
//   .p2align 4,,10
//   .p2align 3
L28:
   movdqu	xmm6, XMMWORD PTR [esi+60]
   movdqu	xmm0, XMMWORD PTR [esi+60]
   punpckldq	xmm6, xmm4
   punpckhdq	xmm0, xmm4
   movd	xmm4, DWORD PTR [esi+76]
   punpcklqdq	xmm4, xmm3
   movaps	XMMWORD PTR [esp+320], xmm4
   jmp	L12
//   .p2align 4,,10
//   .p2align 3
L19:
   movdqa	xmm3, xmm1
   movdqa	xmm6, xmm7
   movdqa	xmm0, xmm5
   movdqa	xmm4, XMMWORD PTR [esp+1120]
   psrldq	xmm3, 8
   psrldq	xmm6, 8
   psrldq	xmm4, 8
   psrldq	xmm0, 8
   paddq	xmm7, xmm6
   movaps	XMMWORD PTR [esp+1136], xmm3
   movdqa	xmm3, XMMWORD PTR [esp+1120]
   movd	edx, xmm7
   movaps	XMMWORD PTR [esp+1152], xmm0
   paddq	xmm5, XMMWORD PTR [esp+1152]
   paddq	xmm1, XMMWORD PTR [esp+1136]
   mov	edi, edx
   shr	edx, 26
   movdqa	xmm0, xmm2
   paddq	xmm3, xmm4
   psrldq	xmm0, 8
   and	edi, 67108863
   movd	eax, xmm3
   paddq	xmm2, xmm0
   add	eax, edx
   movd	edx, xmm5
   mov	ebx, eax
   shr	eax, 26
   add	eax, edx
   movd	edx, xmm1
   and	ebx, 67108863
   mov	ecx, eax
   shr	eax, 26
   add	eax, edx
   and	ecx, 67108863
   movd	edx, xmm2
   mov	DWORD PTR [esp+1152], ecx
   mov	ecx, eax
   shr	eax, 26
   add	eax, edx
   and	ecx, 67108863
   mov	edx, eax
   shr	eax, 26
   lea	eax, [eax+eax*4]
   and	edx, 67108863
   add	eax, edi
   mov	edi, eax
   shr	eax, 26
   add	eax, ebx
   and	edi, 67108863
   mov	ebx, eax
   shr	eax, 26
   and	ebx, 67108863
   mov	DWORD PTR [esp+1120], ebx
   mov	ebx, DWORD PTR [esp+1152]
   add	eax, ebx
   mov	ebx, eax
   shr	eax, 26
   add	eax, ecx
   and	ebx, 67108863
   mov	ecx, eax
   shr	eax, 26
   mov	DWORD PTR [esp+1152], ebx
   mov	ebx, DWORD PTR [esp+1120]
   add	eax, edx
   and	ecx, 67108863
   mov	DWORD PTR [esp+1136], ecx
   mov	edx, eax
   mov	ecx, eax
   and	edx, 67108863
   shr	ecx, 26
   mov	DWORD PTR [esp+1104], edx
   lea	edx, [ecx+ecx*4]
   add	edx, edi
   mov	ecx, edx
   shr	edx, 26
   and	ecx, 67108863
   add	edx, ebx
   or	eax, -67108864
   lea	ebx, [ecx+5]
   mov	DWORD PTR [esp+1088], ebx
   shr	ebx, 26
   lea	edi, [ebx+edx]
   mov	DWORD PTR [esp+1072], edi
   shr	edi, 26
   mov	ebx, edi
   mov	edi, DWORD PTR [esp+1152]
   add	ebx, edi
   mov	edi, DWORD PTR [esp+1136]
   mov	DWORD PTR [esp+1056], ebx
   shr	ebx, 26
   add	ebx, edi
   mov	DWORD PTR [esp+1040], ebx
   shr	ebx, 26
   add	eax, ebx
   mov	edi, eax
   shr	edi, 31
   mov	ebx, edi
   mov	edi, eax
   sar	edi, 31
   sub	ebx, 1
   and	edx, edi
   and	ecx, edi
   and	eax, ebx
   mov	DWORD PTR [esp+1120], edx
   mov	edx, DWORD PTR [esp+1152]
   and	edx, edi
   mov	DWORD PTR [esp+1152], edx
   mov	edx, DWORD PTR [esp+1136]
   and	edx, edi
   mov	DWORD PTR [esp+1136], edx
   mov	edx, DWORD PTR [esp+1104]
   and	edx, edi
   mov	edi, DWORD PTR [esp+1088]
   mov	DWORD PTR [esp+1104], edx
   and	edi, ebx
   and	edi, 67108863
   or	edi, ecx
   mov	ecx, DWORD PTR [esp+1072]
   mov	DWORD PTR [esi], edi
   mov	edi, DWORD PTR [esp+1120]
   and	ecx, ebx
   and	ecx, 67108863
   or	ecx, edi
   mov	DWORD PTR [esi+4], ecx
   mov	ecx, DWORD PTR [esp+1056]
   mov	edi, DWORD PTR [esp+1152]
   and	ecx, ebx
   mov	edx, ecx
   mov	ecx, DWORD PTR [esp+1040]
   and	edx, 67108863
   or	edx, edi
   and	ecx, ebx
   mov	edi, DWORD PTR [esp+1136]
   mov	DWORD PTR [esi+8], edx
   mov	edx, ecx
   and	edx, 67108863
   or	edx, edi
   mov	DWORD PTR [esi+12], edx
   mov	edx, DWORD PTR [esp+1104]
   or	eax, edx
   mov	DWORD PTR [esi+16], eax
   lea	esp, [ebp-12]
   pop	ebx
   pop	esi
   pop	edi
   pop	ebp
end;

procedure _Poly1305_finish_SSE2(st : TPoly1305.PPoly1305_state_internal_t; m : PByte; leftover : integer; var mac : TBlock16Byte) cdecl;
label L63, L33, L34, L35, L36, L37, L38, L42, L43, L64, L65, L99;
asm
   push	ebp
   mov	ebp, esp
   push	edi
   push	esi
   push	ebx
   and	esp, -16
   sub	esp, 64
   mov	ebx, DWORD PTR [ebp+8]
   mov	edx, DWORD PTR [ebp+16]
   mov	eax, DWORD PTR [ebx+116]
   mov	DWORD PTR [esp+28], eax
   test	edx, edx
   je	L63
   mov	edi, DWORD PTR [ebp+12]
   pxor	xmm0, xmm0
   lea	esi, [esp+32]
   movaps	XMMWORD PTR [esp+32], xmm0
   mov	ecx, esi
   movaps	XMMWORD PTR [esp+48], xmm0
   sub	edi, esi
   test	BYTE PTR [ebp+16], 16
   je	L34
   mov	eax, DWORD PTR [ebp+12]
   lea	ecx, [esp+48]
   movdqu	xmm4, XMMWORD PTR [eax]
   movaps	XMMWORD PTR [esp+32], xmm4
L34:
   test	BYTE PTR [ebp+16], 8
   je	L35
   mov	eax, DWORD PTR [ecx+edi]
   mov	edx, DWORD PTR [ecx+4+edi]
   add	ecx, 8
   mov	DWORD PTR [ecx-8], eax
   mov	DWORD PTR [ecx-4], edx
L35:
   test	BYTE PTR [ebp+16], 4
   je	L36
   mov	eax, DWORD PTR [ecx+edi]
   add	ecx, 4
   mov	DWORD PTR [ecx-4], eax
L36:
   test	BYTE PTR [ebp+16], 2
   je	L37
   movzx	eax, WORD PTR [ecx+edi]
   add	ecx, 2
   mov	WORD PTR [ecx-2], ax
L37:
   test	BYTE PTR [ebp+16], 1
   je	L38
   movzx	edx, BYTE PTR [ecx+edi]
   mov	BYTE PTR [ecx], dl
L38:
   cmp	DWORD PTR [ebp+16], 16
   je	L65
   mov	eax, DWORD PTR [ebp+16]
   mov	edx, DWORD PTR [esp+28]
   mov	BYTE PTR [esp+32+eax], 1
   cmp	eax, 15
   jbe	L42
   or	edx, 4
   mov	DWORD PTR [ebx+116], edx
   mov	DWORD PTR [esp+8], 32
   mov	DWORD PTR [esp+4], esi
   mov	DWORD PTR [esp], ebx
   call	_Poly1305_Blocks_sse2
   mov	eax, DWORD PTR [ebx+116]
   mov	DWORD PTR [esp+28], eax
L63:
   test	al, 1
   je	L33
   mov	edx, DWORD PTR [esp+28]
   or	edx, 16
L43:
   mov	DWORD PTR [ebx+116], edx
   mov	DWORD PTR [esp+8], 32
   mov	DWORD PTR [esp+4], 0
   mov	DWORD PTR [esp], ebx
   call	_Poly1305_Blocks_sse2
L33:
   mov	esi, DWORD PTR [ebx+4]
   mov	edx, DWORD PTR [ebx+8]
   mov	ecx, DWORD PTR [ebx+12]
   mov	eax, esi
   mov	edi, esi
   mov	esi, edx
   shr	edi, 6
   sal	esi, 20
   or	esi, edi
   mov	edi, edx
   mov	edx, ecx
   shr	ecx, 18
   shr	edi, 12
   sal	edx, 14
   or	edx, edi
   mov	edi, ecx
   mov	ecx, DWORD PTR [ebx+16]
   sal	eax, 26
   or	eax, DWORD PTR [ebx]
   sal	ecx, 8
   or	ecx, edi
  //APP
  // # 526 "poly1305-donna-x86-sse2-incremental-source - Kopie.c" 1
   //addl DWORD PTR [ebx+100], eax;
//   adcl DWORD PTR [ebx+104], esi;
//   adcl DWORD PTR [ebx+108], edx;
//   adcl DWORD PTR [ebx+112], ecx;
   add DWORD PTR [ebx+100], eax;
   adc DWORD PTR [ebx+104], esi;
   adc DWORD PTR [ebx+108], edx;
   adc DWORD PTR [ebx+112], ecx;

   //# 0 "" 2
  //NO_APP
   pxor	xmm0, xmm0
   movd	xmm3, esi
   movd	xmm1, edx
   movups	XMMWORD PTR [ebx], xmm0
   movd	xmm2, ecx
   movups	XMMWORD PTR [ebx+16], xmm0
   punpckldq	xmm1, xmm2
   movups	XMMWORD PTR [ebx+32], xmm0
   movups	XMMWORD PTR [ebx+48], xmm0
   movups	XMMWORD PTR [ebx+64], xmm0
   movups	XMMWORD PTR [ebx+80], xmm0
   movups	XMMWORD PTR [ebx+96], xmm0
   movups	XMMWORD PTR [ebx+112], xmm0
   movd	xmm0, eax
   mov	eax, DWORD PTR [ebp+20]
   punpckldq	xmm0, xmm3
   punpcklqdq	xmm0, xmm1
   movups	XMMWORD PTR [eax], xmm0
   lea	esp, [ebp-12]
   pop	ebx
   pop	esi
   pop	edi
   pop	ebp

   jmp L99;

// now that is some kind of epiolog
L65:
	  mov	edx, DWORD PTR [esp+28]
	  or	edx, 4
L64:
   mov	DWORD PTR [ebx+116], edx
   mov	DWORD PTR [esp+8], 32
   mov	DWORD PTR [esp+4], esi
   mov	DWORD PTR [esp], ebx
	  call	_poly1305_blocks_sse2
   mov	edx, DWORD PTR [ebx+116]
   test	dl, 1
   je	L33
   or	edx, 32
   jmp	L43
//	.p2align 4,,10
//	.p2align 3
L42:
	  or	edx, 8
	  jmp	L64

// return:
L99:
end;

procedure TPoly1305.Poly1305Emit_SSE(var mac: TBlock16Byte);
begin
     FillChar(mac, sizeof(mac), 0);
     //nonce is not used - it is already stored
     _Poly1305_finish_SSE2( fPPoly1305State, nil, 0, mac)
end;


procedure TPoly1305.Poly1305Finalize(var mac: TBlock16Byte);
begin
     if fNum > 0 then
     begin
          fData[fNum] := 1;
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
end;

procedure TPoly1305.Poly1305Init_SSE(initVec: PByte);
begin
     FillChar(fPoly1305State[0], Length(fPoly1305State), 0);

     _poly1305_init_ext_sse2( fPPoly1305State, initVec, 0);
end;

procedure TPoly1305.Poly1305Blocks_SSE(pData: PByteArray; size: integer);
begin
     _Poly1305_Blocks_sse2( fPPoly1305State, PByte(pData), size );
end;

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

initialization
  TPoly1305.UseSSE := False;

end.
