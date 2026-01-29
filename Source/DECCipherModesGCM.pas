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
    const cGCMBlkSize = 16;
  strict private
    /// <summary>
    ///   Empty value?
    /// </summary>
    nullbytes : T128;

    /// <summary>
    ///   if flag is set no more encoding is allowed
    /// </summary>
    fIsLastBlock : boolean;

    /// <summary>
    ///   One reserve buffer for the GCM intermediate blocks
    /// </summary>
    FData : Array[0..cGCMBlkSize-1] of Byte;

    /// <summary>
    ///   Current index of non encoded fdata bytes
    /// </summary>
    FDataIdx : integer;

    /// <summary>
    ///   Table with precalculated values
    /// </summary>
    FM        : array[0..15,0..255] of T128;

    /// <summary>
    FGHash : T128;
    
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
    // ###########################################
    // #### blocked version of GaloisHash functions
    // ###########################################

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
    function CalcGaloisHash(AuthenticatedData: PUInt8Array; AuthLen: integer;
      Ciphertext: PUInt8Array; CiphertextSize: Integer): T128;



    /// <summary>
    ///   Finalizes the Hash using the Authdata length and accumulated CipherText length.
    /// </summary>
    /// <returns>
    ///   Calculated raw hash value which will later get returned as AuthenticatedTag
    /// </returns>


    /// <summary>
    ///   Encrypts a T128 value using the encryption method specified on init
    /// </summary>
    /// <param name="Value">
    ///   Value to be encrypted
    /// </param>
    /// <returns>
    ///   Encrypted value
    /// </returns>
    function EncodeT128(Value: T128): T128; inline;
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


    /// <summary>
    ///   Finalizes the Poly1305 calculation
    ///   The last block is padded and one additional block containing
    ///   the processed length + the legnth processed AuthenticationBytes
    ///   is created and fed into the polynom.
    ///   After this call the MAC is valid.
    /// </summary>
    procedure FinalizeMAC( authLen, encDecBufLen : int64); override;

    /// <summary>
    ///   Initializes the Galois Hash function internal data and starts
    ///   with the DataToAuthenticate field.
    /// </summary>
    procedure InitAuth; override;

    /// <summary>
    ///   Updates the hash with a given cipher text. Internally the ciphertext length
    ///   field is also updated
    /// </summary>
    /// <param name="buf">
    ///   Pointer the data that updates the hash.
    /// </param>
    /// <param name="size">
    ///   Length of the buffer
    /// </param>
    procedure UpdateWithEncDecBuf(buf : PUInt8Array; Size   : Integer); override;

    /// <summary>
    ///   Encoding/Decoding routine - For some methods it is sufficient to just call
    ///   the given encoding routine (poly1305, chacha handles that internally) - some need to update the cipher (e.g. aes gcm)
    /// </summary>
    /// <param name="Source">
    ///   Pointer the data that updates the hash.
    /// </param>
    /// <param name="Dest">
    ///   Pointer the data that updates the hash.
    /// </param>
    /// <param name="size">
    ///   Length of the buffer
    /// </param>
    procedure LocEncodeDecode(Source, Dest: Pointer; Size: Integer); override;


    procedure Burn; override;
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
    ///   Returns a list of authentication tag lengths explicitely specified by
    ///   the official specification of the standard.
    /// </summary>
    /// <returns>
    ///   List of bit lengths
    /// </returns>
    function GetStandardAuthenticationTagBitLengths:TStandardBitLengths; override;
  end;

implementation

uses Math;

function TGCM.EncodeT128(Value: T128): T128;
begin
  FEncryptionMethod(@Value[0], @Result[0], 16);
end;


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

  FEncryptionMethod := EncryptionMethod;

  Nullbytes[0] := 0;
  Nullbytes[1] := 0;

  OldH := FH;
  FEncryptionMethod(@Nullbytes[0], @FH[0], 16);

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
     FY := CalcGaloisHash(nil, 0, @InitVector[0], length(InitVector));

  FEncryptionMethod(@FY[0], @FE_K_Y0[0], 16);
end;

procedure TGCM.InitAuth;
var authLen : integer;
begin
     inherited;

     FillChar(fData, sizeof(fData), 0);
     FDataIdx := 0;

     FGHash := nullbytes;
     if Length(FDataToAuthenticate) > 0 then
     begin
          authLen := Length(FDataToAuthenticate);
          UpdateWithEncDecBuf(@FDataToAuthenticate[0], authLen);
          // this block needs to be padded if the authentication buffer is not a multiple of 16
          authLen := 16 - (authLen mod 16);
          if authLen <> 16 then
             UpdateWithEncDecBuf(@nullbytes, authLen);
     end;

     fIsLastBlock := False;
end;

procedure TGCM.LocEncodeDecode(Source, Dest: Pointer; Size: Integer);
var i, j : integer;
    div_len_plain : integer;

begin
     if fIsLastBlock then
        raise Exception.Create('Already last block processed. Call the encode only with a blocksize of 16 bytes');
     i := 0;
     div_len_plain := Size div 16;

     for j := 1 to div_len_plain do
     begin
          INCR(FY);

          P128(@PUInt8Array(Dest)^[i])^ := XOR_PointerWithT128(@PUInt8Array(Source)^[i], EncodeT128(FY));

          inc(i,16);
     end;

     // is it the last block?
     if i < Size then
     begin
          fIsLastBlock := True;
          INCR(FY);
          XOR_ArrayWithT128(Source, i, Size - i, EncodeT128(FY), Dest);
    end;
end;

procedure TGCM.FinalizeMAC(authLen, encDecBufLen: int64);
var res : T128;
    AuthCipherLength : T128;
    x : T128;
begin
     // last block:::
     if FDataIdx > 0 then
     begin
          x := nullbytes;
          Move(fData[0], x, FDataIdx);
          FGHash := poly_mult_H(XOR_T128(x, FGHash));
          fDataIdx := 0;
     end;

     // update hash with the lengths...
     SetAuthenticationCipherLength(AuthCipherLength, authLen shl 3, encDecBufLen shl 3);
     res := XOR_T128(poly_mult_H(XOR_T128(AuthCipherLength, FGHash)), FE_K_Y0);

     // copy and burn
     if Length(FCalcAuthenticationTag) > 0 then
        Move(res, FCalcAuthenticationTag[0], Min(sizeof(res), length(FCalcAuthenticationTag)));
     res := nullbytes;
     FillChar(FData, sizeof(fData), 0);
end;

procedure TGCM.UpdateWithEncDecBuf(buf: PUInt8Array; Size: Integer);
var i, div_d, len_d : integer;
    n : integer;
begin
     n := 0;
     if FDataIdx > 0 then
     begin
          if cGCMBlkSize - fDataIdx > Size then
          begin
               Move(buf^[0], fData[FDataIdx], size);
               inc(FDataIdx, size);
               exit;
          end
          else
          begin
               // encode one block
               n := cGCMBlkSize - fDataIdx;
               Move( buf^[0], fData[fDataIdx], n);
               FGHash := poly_mult_H(XOR_PointerWithT128(@fData[0], FGHash ));
               FDataIdx := 0;
          end;

     end;

     len_d := size - n;
     if (len_d >= cGCMBlkSize) then
     begin
          div_d := len_d div cGCMBlkSize;
          for i := 0 to div_d - 1 do
          begin
               FGHash := poly_mult_H(XOR_PointerWithT128(@buf^[n], FGHash ));
               inc(n, cGCMBlkSize);
          end;
     end;

     if n < size then
     begin
          Move(buf^[n], fData[fDataIdx], size - n);
          inc(FDataIdx, size - n);
     end;
end;

(*
procedure TGCM.Encode(Source, Dest: PUInt8Array; Size: Integer);
var
  i, j, div_len_plain : UInt64;
  AuthTag : T128;
  pDataToAuth : PUInt8Array;
begin
  i := 0;
  div_len_plain := Size div 16;

  for j := 1 to div_len_plain do
  begin
    INCR(FY);

    P128(@Dest^[i])^ := XOR_PointerWithT128(@Source^[i], EncodeT128(FY));

    inc(i,16);
  end;

  if i < Size then
  begin
    INCR(FY);
    XOR_ArrayWithT128(Source, i, UInt64(Size)-i, EncodeT128(FY), Dest);
  end;

  pDataToAuth := nil;
  if Length(DataToAuthenticate) > 0 then
     pDataToAuth := @DataToAuthenticate[0];
  AuthTag := XOR_T128(CalcGaloisHash(pDataToAuth, Length(DataToAuthenticate), @Dest[0], Size), FE_K_Y0);
  Setlength(FCalcAuthenticationTag, FCalcAuthenticationTagLength);
  if (FCalcAuthenticationTagLength > 0) then
  	Move(AuthTag[0], FCalcAuthenticationTag[0], FCalcAuthenticationTagLength);
end;

*)

(*
procedure TGCM.EncodeGCMBlk(Ciphertext, Dest  : PUInt8Array;
                            CiphertextSize    : Integer;
                            lastBlock: boolean);
var
  i, j, div_len_plain : integer;
  AuthTag : T128;
begin
  // len = 0 -> first block. Init the hash
  if FCipherLen = 0 then
     BeginCalcGaloisHash;

  if not lastBlock and (CiphertextSize mod 16 <> 0) then
     raise Exception.Create('Only multiple of 16bytes are allowed in block mode');

  i := 0;
  div_len_plain := CiphertextSize div 16;

  for j := 1 to div_len_plain do
  begin
    INCR(FY);

    P128(@Dest^[i])^ := XOR_PointerWithT128(@Ciphertext^[i], EncodeT128(FY));

    inc(i,16);
  end;

  if lastBlock then
  begin
    if i < CiphertextSize then
    begin
      INCR(FY);
      XOR_ArrayWithT128(Ciphertext, i, CiphertextSize-i, EncodeT128(FY), Dest);
    end;

    UpdateGaloisHash(Dest, CiphertextSize);

    //AuthTag := XOR_T128(CalcGaloisHash(DataToAuthenticate, Dest, Size), FE_K_Y0);
    AuthTag := XOR_T128(FinishGaloisHash, FE_K_Y0);
    Setlength(FCalcAuthenticationTag, FCalcAuthenticationTagLength);
    if (FCalcAuthenticationTagLength > 0) then
      Move(AuthTag[0], FCalcAuthenticationTag[0], FCalcAuthenticationTagLength);
  end
  else
  begin
       UpdateGaloisHash(Dest, CiphertextSize);
  end;
end;

*)

function TGCM.GetStandardAuthenticationTagBitLengths: TStandardBitLengths;
begin
  SetLength(Result, 5);
  Result := [96, 104, 112, 120, 128];
end;

procedure TGCM.Burn;
begin
     inherited;

     FH := nullbytes;
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

end.
