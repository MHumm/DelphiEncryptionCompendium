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
unit DECCipherModesGCM;

interface

{$INCLUDE DECOptions.inc}

uses
  {$IFDEF FPC}
  SysUtils,
  {$ELSE}
  System.SysUtils,
  {$ENDIF}
  DECTypes,
  DECAuthenticatedCipherModesBase;

type
  /// <summary>
  ///   128 bit unsigned integer
  /// </summary>
  T128 = array[0..1] of UInt64;
  /// <summary>
  ///   pointer to an 128 bit unsigned integer
  /// </summary>
  P128 = ^T128;

  /// <summary>
  ///   Array of 16 bytes
  /// </summary>
  T16ByteArray = array[0..15] of Byte;
  /// <summary>
  ///   Pointer to an array of 16 bytes
  /// </summary>
  P16ByteArray = ^T16ByteArray;

  /// <summary>
  ///   Galois Counter Mode specific methods
  /// </summary>
  TGCM = class(TAuthenticatedCipherModesBase)
  strict private
    /// <summary>
    ///   Empty value?
    /// </summary>
    nullbytes : T128;
    /// <summary>
    ///   Table with precalculated values
    /// </summary>
    FM        : array[0..15,0..255] of T128;

    /// <summary>
    ///   Required for creating the table and encryption at least
    /// </summary>
    FH        : T128;
    /// <summary>
    ///   Calculated in initialization
    /// </summary>
    FY        : T128;
    /// <summary>
    ///   Calculated in initialization
    /// </summary>
    FE_K_Y0   : T128;

    /// <summary>
    ///   Running GHASH state (NIST "X"). Allows multi-call Encode/Decode.
    ///   Tag is finalized only in Done — see Cleanup-Roadmap §3.1 (Option A).
    /// </summary>
    FX                    : T128;
    /// <summary>
    ///   Incomplete 16-byte GHASH block carried across Encode/Decode calls
    /// </summary>
    FGHASHPartial         : array[0..15] of Byte;
    /// <summary>
    ///   Number of valid bytes in FGHASHPartial (0..15)
    /// </summary>
    FGHASHPartialLen      : Integer;
    /// <summary>
    ///   Total ciphertext bytes processed since Init (for length block)
    /// </summary>
    FTotalCiphertextBytes : UInt64;
    /// <summary>
    ///   True after AAD has been absorbed into FX (and padded to 16 bytes)
    /// </summary>
    FAuthDataHashed       : Boolean;
    /// <summary>
    ///   Leftover keystream from an incomplete CTR block (multi-call Encode/Decode)
    /// </summary>
    FKeystreamLeftover    : T128;
    /// <summary>
    ///   Number of unused bytes remaining in FKeystream (0..15)
    /// </summary>
    FKeystreamRemainLen   : Integer;
    /// <summary>
    ///   True after Done has materialized the authentication tag.
    ///   Prevents double-finalization and post-Done GHASH/CTR updates.
    /// </summary>
    FFinalized            : Boolean;

    /// <summary>
    ///   XOR implementation for unsigned 128 bit numbers
    /// </summary>
    /// <param name="x">
    ///   First number to xor
    /// </param>
    /// <param name="y">
    ///   Second number to xor the first with
    /// </param>
    /// <returns>
    ///   x xor y
    /// </returns>
    function XOR_T128(const x, y: T128): T128; inline;
    /// <summary>
    ///   XOR implementation for a pointer and an unsigned 128 bit number
    /// </summary>
    /// <param name="x">
    ///   Pointer on a T128 typed number to xor with y
    /// </param>
    /// <param name="y">
    ///   Second number to xor the first with
    /// </param>
    /// <returns>
    ///   x xor y
    /// </returns>
    function XOR_PointerWithT128(const x: Pointer; y: T128 ): T128; inline;
    /// <summary>
    ///   XORs the bytes given in a byte array with a T128 number given
    /// </summary>
    /// <param name="x">
    ///   Bytes which shall be XORed with the T128 number
    /// </param>
    /// <param name="XIndex">
    ///   Starting index within x from which onwards to XOR
    /// </param>
    /// <param name="Count">
    ///   Number of bytes from x beginning at XIndex to XOR
    /// </param>
    /// <param name="y">
    ///   Value to XOR the bytes from y with. XOR is done bytewise for each
    ///   byte of y
    /// </param>
    /// <param name="Result">
    ///   Result of the XOR operation
    /// </param>
    procedure XOR_ArrayWithT128(x: PUInt8Array; XIndex, Count: UInt64; y: T128; Result: PUInt8Array); inline;

    /// <summary>
    ///   XORs all elements of the precalculated matrix with the value passed
    /// </summary>
    /// <param name="hx">
    ///   Value who's two parts shall be XORed with the two parts of the
    ///   matrix each.
    /// </param>
    /// <returns>
    ///   result of the XOR Operation
    /// </returns>
    function poly_mult_H(const hx: T128) : T128; inline;

    /// <summary>
    ///   Encodes the 64 bit lengths of DataToAuthenticate and of the cipher
    ///   text into a T128 value, swapping the bytes in the process.
    /// </summary>
    /// <param name="x">
    ///   Result of the operation
    /// </param>
    /// <param name="AuthDataLength">
    ///   Length of the data to authenticate in byte
    /// </param>
    /// <param name="CipherTextLength">
    ///   Length of the ciphertext in byte
    /// </param>
    procedure SetAuthenticationCipherLength(var x : T128;
                                            AuthDataLength, CipherTextLength : UInt64); inline;

    /// <summary>
    ///   Calculates a table with precalculated values which speeds up
    ///   operations later. The initialized table is the FM field.
    /// </summary>
    /// <param name="H">
    ///   Start value for the precalculation
    /// </param>
    procedure GenerateTableM8Bit(const H: T128); //inline;
    /// <summary>
    ///   Performs a right shift of 1 of all bytes in an 128 bit variable
    /// </summary>
    /// <param name="rx">
    ///   Variable on which the right shift is being performed
    /// </param>
    procedure ShiftRight(var rx: T128); //inline;

    /// <summary>
    ///   Incremepts the last 4 bytes of the index 0 part
    /// </summary>
    /// <param name="Y">
    ///   Value to increment, this is the return value as well.
    /// </param>
    procedure INCR(var Y : T128);

    /// <summary>
    ///   Calculates the hash value
    /// </summary>
    /// <param name="AuthenticatedData">
    ///   Specifys the data for which an authentication value shall be
    ///   calculated. It is allowed to be nil.
    /// </param>
    /// <param name="AuthLen">
    ///   Length of the data to authenticate in byte
    /// </param>
    /// <param name="Ciphertext">
    ///   Encrypted data used in the calculation
    /// </param>
    /// <param name="CiphertextSize">
    ///   Length of the ciphertext in bytes. Use when reading part of array.
    /// </param>
    /// <returns>
    ///   Calculated raw hash value which will later get returned as AuthenticatedTag
    /// </returns>
    function CalcGaloisHash(AuthenticatedData : PUInt8Array;
                            AuthLen           : Integer;
                            Ciphertext        : PUInt8Array;
                            CiphertextSize    : Integer): T128;

    /// <summary>
    ///   Feeds data into the running GHASH state FX (supports partial blocks).
    /// </summary>
    procedure GHASHUpdate(Data: PUInt8Array; DataSize: Integer);
    /// <summary>
    ///   Pads any incomplete GHASH block with zeros and multiplies into FX.
    /// </summary>
    procedure GHASHPadPartial;
    /// <summary>
    ///   Ensures AAD has been GHASH'd and padded once before processidng ciphertext bytes.
    /// </summary>
    procedure EnsureAuthDataHashed;
    /// <summary>
    ///   Completes GHASH (length block) and writes CalculatedAuthenticationTag.
    /// </summary>
    procedure FinalizeAuthenticationTag;
    /// <summary>
    ///   GCM-CTR keystream XOR with multi-call partial-block carry.
    /// </summary>
    procedure ApplyCTR(Source, Dest: PUInt8Array; Size: Integer);

    /// <summary>
    ///   Encrypts a T128 value using the encryption method specified on init
    /// </summary>
    /// <param name="Value">
    ///   Value to be encrypted
    /// </param>
    /// <returns>
    ///   Encrypted value
    /// </returns>
    function EncodeT128(Value: T128): T128;
  strict protected
    /// <summary>
    ///   Defines the length of the resulting authentication value in bit.
    /// </summary>
    /// <param name="Value">
    ///   Sets the length of Authenticaton_tag in bit, values as per specification
    ///   are: 128, 120, 112, 104, or 96 bit. For certain applications, they
    ///   may be 64 or 32 as well, but the use of these two tag lengths
    ///   constrains the length of the input data and the lifetime of the key.
    /// </param>
    procedure SetAuthenticationTagLength(const Value: UInt32); override;
  public
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
    ///   Encodes a block of data using the supplied cipher
    /// </summary>
    /// <param name="Source">
    ///   Plain text to encrypt
    /// </param>
    /// <param name="Dest">
    ///   Ciphertext after encryption
    /// </param>
    /// <param name="Size">
    ///   Number of bytes to encrypt
    /// </param>
    procedure Encode(Source,
                     Dest   : PUInt8Array;
                     Size   : Integer); override;
    /// <summary>
    ///   Decodes a block of data using the supplied cipher
    /// </summary>
    /// <param name="Source">
    ///   Encrypted ciphertext to decrypt
    /// </param>
    /// <param name="Dest">
    ///   Plaintext after decryption
    /// </param>
    /// <param name="Size">
    ///   Number of bytes to decrypt
    /// </param>
    procedure Decode(Source,
                     Dest   : PUInt8Array;
                     Size   : Integer); override;

    /// <summary>
    ///   Finishes GHASH and materializes CalculatedAuthenticationTag.
    ///   Must be called after the last Encode/Decode (cipher Done does this).
    ///   Idempotent: a second call leaves the tag unchanged.
    ///   After finalization, Encode/Decode raise until Init is called again.
    /// </summary>
    procedure Done;

    /// <summary>
    ///   Returns a list of authentication tag lengths explicitely specified by
    ///   the official specification of the standard.
    /// </summary>
    /// <returns>
    ///   List of bit lengths
    /// </returns>
    function GetStandardAuthenticationTagBitLengths:TStandardBitLengths; override;
  end;

implementation

resourcestring
  sGCMAlreadyFinalized =
    'GCM authentication already finalized; call Init before further Encode/Decode';

function TGCM.XOR_T128(const x, y : T128): T128;
begin
  Result[0] := x[0] xor y[0];
  Result[1] := x[1] xor y[1];
end;

function TGCM.XOR_PointerWithT128(const x : Pointer; y : T128): T128;
begin
  Result[0] := P128(x)^[0] xor y[0];
  Result[1] := P128(x)^[1] xor y[1];
end;

procedure TGCM.XOR_ArrayWithT128(x: PUInt8Array; XIndex, Count: UInt64; y: T128; Result: PUInt8Array);
var
  i  : integer;
  by : P16ByteArray;
begin
  by := @y[0];
  for i := 0 to Count-1 do
  begin
    Result^[XIndex] := x^[XIndex] xor by[i];
    inc(XIndex);
  end;
end;

function TGCM.poly_mult_H(const hx : T128): T128;
var
  i : integer;
  x : P16ByteArray;
begin
  x := @hx[0];
  Result := FM[0, x[0]];

  for i := 1 to 15 do
  begin
    Result[0] := Result[0] xor FM[i, x[i]][0];
    Result[1] := Result[1] xor FM[i, x[i]][1];
  end;
end;

procedure TGCM.SetAuthenticationCipherLength(var x : T128;
                                             AuthDataLength, CipherTextLength : UInt64);
var
  i  : integer;
  hx : P16ByteArray;
begin
  hx := @x[0];
  // al:
  x := nullbytes;
  i := 7;

  repeat
    hx[i] := AuthDataLength mod 256;
    AuthDataLength := AuthDataLength shr 8;
    dec(i);
  until AuthDataLength = 0;

  // cl:
  i := 15;

  repeat
    hx[i] := CipherTextLength mod 256;
    CipherTextLength := CipherTextLength shr 8;
    dec(i);
  until CipherTextLength = 0;
end;

procedure TGCM.GenerateTableM8Bit(const H : T128);
var
  hbit, hbyte, i, j : integer;
  HP : T128;
  bHP : P16ByteArray;
  mask : byte;
begin
  HP := H;
  bHP := @HP[0];
  for hbyte := 0 to 15 do
  begin
    mask := 128;
    for hbit := 0 to 7 do
    begin
      FM[hbyte, mask] := HP;

      if (bHP[15] and 1 = 0) then
        ShiftRight(HP)
      else
      begin
        ShiftRight(HP);
        bHP[0] := bHP[0] xor $e1;
      end;

      mask := mask shr 1;
    end;
  end;

  for hbyte := 0 to 15 do
  begin
    i := 2;

    while i <= 128 do
    begin
      for j := 1 to i-1 do
        FM[hbyte, i+j] := XOR_T128(FM[hbyte, i], FM[hbyte, j]);
      i := i*2;
    end;

    FM[hbyte, 0] := nullbytes;
  end;
end;

procedure TGCM.ShiftRight(var rx : T128);
var
  x : P16ByteArray;
  i : integer;
begin
  x := @rx[0];

  for i := 15 downto 1 do
    x[i] := (x[i] shr 1) or ((x[i-1] and 1) shl 7);

  x[0] := x[0] shr 1;
end;

procedure TGCM.SetAuthenticationTagLength(const Value: UInt32);
begin
  FCalcAuthenticationTagLength := Value shr 3;
  SetLength(FCalcAuthenticationTag, FCalcAuthenticationTagLength);
end;

procedure TGCM.INCR(var Y : T128);
var
  bY : P16ByteArray;
begin
  bY := @Y[0];

  {$IFOPT Q+}{$DEFINE RESTORE_OVERFLOWCHECKS}{$Q-}{$ENDIF}
  {$Q-}
  inc(bY[15]);
  if bY[15] = 0 then
  begin
    inc(bY[14]);

    if bY[14] = 0 then
    begin
      inc(bY[13]);

      if bY[13] = 0 then
        inc(bY[12]);
    end;
  end;
  {$IFDEF RESTORE_OVERFLOWCHECKS}{$Q+}{$ENDIF}
end;

procedure TGCM.Init(EncryptionMethod : TEncodeDecodeMethod;
                    InitVector       : TBytes);
var
  b    : ^Byte;
  OldH : T128;
begin
  inherited;

  Nullbytes[0] := 0;
  Nullbytes[1] := 0;

  // Streaming GHASH + CTR state for multi-call Encode/Decode (Option A)
  FillChar(FGHASHPartial[0], SizeOf(FGHASHPartial), 0);
  FX[0]                 := 0;
  FX[1]                 := 0;
  FGHASHPartialLen      := 0;
  FTotalCiphertextBytes := 0;
  FAuthDataHashed       := False;
  FKeystreamRemainLen   := 0;
  FKeystreamLeftover[0] := 0;
  FKeystreamLeftover[1] := 0;
  FFinalized            := False;

  OldH := FH;
  EncryptionMethod(@Nullbytes[0], @FH[0], 16);

  // Only generate the table when not already generated
  if (OldH[0] <> FH[0]) or (OldH[1] <> FH[1]) then
    GenerateTableM8Bit(FH);

  if length(InitVector) = 12 then
  begin
     FY[1] := 0;
     Move(InitVector[0], FY[0], 12);
     b := @FY[0];
     inc(b, 15);
     b^ := 1;
  end
  else
     // One-shot GHASH over IV only (does not use streaming FX)
     FY := CalcGaloisHash(nil, 0, @InitVector[0], length(InitVector));

  FEncryptionMethod(@FY[0], @FE_K_Y0[0], 16);
end;

procedure TGCM.GHASHUpdate(Data: PUInt8Array; DataSize: Integer);
var
  Offset, Take : Integer;
begin
  if (DataSize <= 0) or (Data = nil) then
    Exit;

  Offset := 0;

  if FGHASHPartialLen > 0 then
  begin
    Take := 16 - FGHASHPartialLen;
    if Take > DataSize then
      Take := DataSize;
    Move(Data^[Offset], FGHASHPartial[FGHASHPartialLen], Take);
    Inc(FGHASHPartialLen, Take);
    Inc(Offset, Take);
    if FGHASHPartialLen = 16 then
    begin
      FX := poly_mult_H(XOR_PointerWithT128(@FGHASHPartial[0], FX));
      FGHASHPartialLen := 0;
    end;
  end;

  while Offset + 16 <= DataSize do
  begin
    FX := poly_mult_H(XOR_PointerWithT128(@Data^[Offset], FX));
    Inc(Offset, 16);
  end;

  if Offset < DataSize then
  begin
    FGHASHPartialLen := DataSize - Offset;
    Move(Data^[Offset], FGHASHPartial[0], FGHASHPartialLen);
  end;
end;

procedure TGCM.GHASHPadPartial;
var
  Block : T128;
begin
  if FGHASHPartialLen > 0 then
  begin
    Block := nullbytes;
    Move(FGHASHPartial[0], Block[0], FGHASHPartialLen);
    FX := poly_mult_H(XOR_T128(Block, FX));
    FGHASHPartialLen := 0;
  end;
end;

procedure TGCM.EnsureAuthDataHashed;
begin
  if FAuthDataHashed then
    Exit;

  if Length(DataToAuthenticate) > 0 then
    GHASHUpdate(@DataToAuthenticate[0], Length(DataToAuthenticate));
  // Pad AAD to 16-byte boundary before ciphertext (NIST GHASH layout)
  GHASHPadPartial;
  FAuthDataHashed := True;
end;

procedure TGCM.Done;
begin
  if FFinalized then
    Exit;
  FinalizeAuthenticationTag;
  FFinalized := True;
end;

procedure TGCM.FinalizeAuthenticationTag;
var
  AuthTag            : T128;
  AuthCipherLength   : T128;
  AuthLen            : Integer;
begin
  EnsureAuthDataHashed;
  // Pad incomplete ciphertext block
  GHASHPadPartial;

  AuthLen := Length(DataToAuthenticate);
  SetAuthenticationCipherLength(AuthCipherLength,
                                UInt64(AuthLen) shl 3,
                                FTotalCiphertextBytes shl 3);
  FX := poly_mult_H(XOR_T128(AuthCipherLength, FX));
  AuthTag := XOR_T128(FX, FE_K_Y0);

  SetLength(FCalcAuthenticationTag, FCalcAuthenticationTagLength);
  if (FCalcAuthenticationTagLength > 0) then
    Move(AuthTag[0], FCalcAuthenticationTag[0], FCalcAuthenticationTagLength);
end;

function TGCM.CalcGaloisHash(AuthenticatedData : PUInt8Array; AuthLen : integer; Ciphertext : PUInt8Array;
  CiphertextSize: Integer): T128;
var
  AuthCipherLength : T128;
  x : T128;
  n : Uint64;

  procedure encode(data : PUInt8Array; dataSize: Integer);
  var
    i, mod_d, div_d, len_d : UInt64;
    hdata : T128;
  begin
    len_d := dataSize;
    if (len_d > 0) then
    begin
      n := 0;
      div_d := len_d div 16;
      if div_d > 0 then
      begin
        for i := 0 to div_d-1 do
        begin
          x := poly_mult_H(XOR_PointerWithT128(@data^[n], x ));
          inc(n, 16);
        end;
      end;

      mod_d := len_d mod 16;
      if mod_d > 0 then
      begin
        hdata := nullbytes;
        Move(data^[n], hdata[0], mod_d);
        x := poly_mult_H(XOR_T128(hdata, x));
      end;
    end;
  end;

begin
  x := nullbytes;
  if AuthLen > 0 then
     encode(@AuthenticatedData[0], AuthLen);
  //Assert(length(Ciphertext) >= CiphertextSize);
  encode(Ciphertext, CiphertextSize);
  SetAuthenticationCipherLength(AuthCipherLength, AuthLen shl 3, CiphertextSize shl 3);

  Result := poly_mult_H(XOR_T128(AuthCipherLength, x));
end;

procedure TGCM.ApplyCTR(Source, Dest: PUInt8Array; Size: Integer);
var
  i, Take : Integer;
  KSBytes : P16ByteArray;
begin
  if Size <= 0 then
    Exit;

  i := 0;
  // Drain leftover keystream from a previous partial block
  if (FKeystreamRemainLen > 0) then
  begin
    KSBytes := @FKeystreamLeftover[0];
    Take := FKeystreamRemainLen;
    if Take > Size then
      Take := Size;
    XOR_ArrayWithT128(Source, i, Take, FKeystreamLeftover, Dest);
    // Shift remaining keystream left so index 0 is next unused byte
    if (Take < FKeystreamRemainLen) then
      Move(KSBytes^[Take], KSBytes^[0], FKeystreamRemainLen - Take);
    Dec(FKeystreamRemainLen, Take);
    Inc(i, Take);
  end;

  while i + 16 <= Size do
  begin
    INCR(FY);
    P128(@Dest^[i])^ := XOR_PointerWithT128(@Source^[i], EncodeT128(FY));
    Inc(i, 16);
  end;

  if i < Size then
  begin
    INCR(FY);
    FKeystreamLeftover := EncodeT128(FY);
    Take := Size - i;
    XOR_ArrayWithT128(Source, i, Take, FKeystreamLeftover, Dest);
    // Keep unused tail of this keystream block for the next call
    Move(P16ByteArray(@FKeystreamLeftover[0])^[Take],
         P16ByteArray(@FKeystreamLeftover[0])^[0],
         16 - Take);
    // Clear used prefix is unnecessary; only FKeystreamRemain matters
    FKeystreamRemainLen := 16 - Take;
  end;
end;

procedure TGCM.Decode(Source, Dest: PUInt8Array; Size: Integer);
begin
  if FFinalized then
    raise EDECCipherException.CreateRes(@sGCMAlreadyFinalized);

  // AAD into GHASH once; tag finalized in Done (supports multi-call streams)
  EnsureAuthDataHashed;

  if Size < 0 then
    Size := 0;

  // GHASH over ciphertext before CTR (Source is ciphertext)
  if Size > 0 then
  begin
    GHASHUpdate(Source, Size);
    Inc(FTotalCiphertextBytes, UInt64(Size));
  end;

  ApplyCTR(Source, Dest, Size);
end;

procedure TGCM.Encode(Source, Dest: PUInt8Array; Size: Integer);
begin
  if FFinalized then
    raise EDECCipherException.CreateRes(@sGCMAlreadyFinalized);

  // AAD into GHASH once; tag finalized in Done (supports multi-call streams)
  EnsureAuthDataHashed;

  if Size < 0 then
    Size := 0;

  ApplyCTR(Source, Dest, Size);

  // GHASH over ciphertext produced in Dest
  if Size > 0 then
  begin
    GHASHUpdate(Dest, Size);
    Inc(FTotalCiphertextBytes, UInt64(Size));
  end;
end;

function TGCM.EncodeT128(Value: T128): T128;
begin
  FEncryptionMethod(@Value[0], @Result[0], 16);
end;

function TGCM.GetStandardAuthenticationTagBitLengths: TStandardBitLengths;
begin
  SetLength(Result, 5);
  Result := [96, 104, 112, 120, 128];
end;

//
//function decrypt( const key, IV : TBytes; out plaintext : TBytes; const authenticated_data,
//ciphertext : TBytes; len_auth_tag : integer; const authenticaton_tag : TBytes ) : boolean;
//var
//    i, j, div_len_ciph, len_ciph : Uint64;
//    a_tag, E_K_Y0, Y, H : T128;
//    bY : array[0..15] of byte absolute Y[0];
//    ba_Tag : TBytes;
//
//    function equal( const a, b : TBytes ):boolean;
//    begin
//      if length(a) <> length(b) then Result := false
//      else
//      Result := CompareMem( @a[0], @b[0], length(a) );
//    end;
//
//begin
//    len_auth_tag := len_auth_tag shr 3;
//
//    E_Init( key );
//    H := E_Cipher( nullbytes );
//    Table_M_8Bit(H);
//
//    len_ciph := length( ciphertext );
//    SetLength( plaintext, len_ciph );
//
//    if length(IV) = 12 then
//    begin
//       Y[1] := 0;
//       Move( IV[0], Y[0], 12 );
//       bY[15] := 1;
//    end
//    else
//       Y := CalcGaloisHash( H, nil, IV );
//
//    E_K_Y0 := E_Cipher( y );
//
//    i := 0;
//    div_len_ciph := len_ciph div 16;
//    for j := 1 to div_len_ciph do
//    begin
//      INCR( Y );
//      P128(@plaintext[i])^ := XOR_128_n( @ciphertext[i], E_cipher( Y ) );
//      inc(i,16);
//    end;
//
//    if i < len_ciph then
//    begin
//      INCR( Y );
//      XOR_128_n_l( ciphertext, i, len_ciph-i, E_cipher( Y ), plaintext );
//    end;
//
//    a_tag := XOR_128( CalcGaloisHash( H, authenticated_data, ciphertext ), E_K_Y0 );
//
//    Setlength( ba_tag, len_auth_tag );
//    Move( a_tag[0], ba_tag[0], len_auth_tag );
//
//    Result := equal( authenticaton_tag, ba_tag );
//    if not Result then SetLength( plaintext, 0 ); // NIST FAIL => pt=''
//end;
//

end.
