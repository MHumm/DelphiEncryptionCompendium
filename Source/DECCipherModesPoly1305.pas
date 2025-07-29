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
    type
      TPoly1305Nonce = Array[0..3] of UInt32;
      TPoly1305BlockMethod = procedure ( pData : PByteArray; size : integer ) of Object;
      TPoly1305EmitMethod = procedure( var mac: TBlock16Byte ) of Object;
      TPoly1305PadAndFinalize = procedure( authLen, encDecBufLen : int64) of Object;
      THArr = Array[0..4] of UInt32;
      PHArr = ^THArr;
      TRArr = Array[0..3] of UInt32;
      PRArr = ^TRArr;
      TPoly1305State = Array[0..160] of Byte;
  private
    /// <summary>
    ///   avx buffer for h and R (may be extended in future fo for SSE, AVX)
    /// </summary>
    fPoly1305State : TPoly1305State;

    /// <summary>
    ///   H and R values. These point ot the fPoly1305State buffer
    /// </summary>
    FH : PHArr;
    FR : PRArr;

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
    fData : Array[0..2*POLY1305_BLOCK_SIZE - 1] of Byte;     // for both the sse and pas version

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
  protected
    // ###########################################
    // #### Authentication block functions
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

//CONSTANT_TIME_CARRY(a,b) ( \
//         (a ^ ((a ^ b) | ((a - b) ^ b))) >> (sizeof(a) * 8 - 1) \
//         )
function ConstTimeCarray32(a, b : UInt32 ) : UInt32; inline;
begin
     Result := (a xor ( (a xor b) or ((a - b) xor b))) shr 31;
end;


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

     FH := @fPoly1305State[0];
     FR := @fPoly1305State[sizeof(THarr)];

     // for future use -> here is a good place to add sse AVX functions
     fPadAndFinalizeFunc := PadAndFinalizePAS;
     fPolyBlkFunc := UpdatePoly;
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

procedure TPoly1305.UpdateWithEncDecBuf(buf: PUInt8Array; Size: Integer);
begin
     UpdatePoly(PByteArray(buf), size);
end;

end.
