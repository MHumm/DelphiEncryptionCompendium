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

// Based on: aes_ccm.pas from Wolfgang Erhard
unit DECCipherModesCCM;

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

resourcestring
  sWrongNonceLength         = 'Wrong nonce/IV length. Must be between 7 and 13';
  sWrongNonceLengthDetailed = 'Nonce longer than 15 byte. Act. length: %0:d';
  sWrongCCMAuthLength       = 'CCM authentication tag needs to have a length of ' +
                              '4, 6, 8, 10, 12, 14 or 16 byte';

type
  /// <summary>
  ///   Counter with CBC-MAC Mode specific methods
  /// </summary>
  TCCM = class(TAuthenticatedCipherModesBase)
  strict private
    /// <summary>
    ///   Unmodified initialization vector
    /// </summary>
    FOrigInitVector              : TBytes;
    /// <summary>
    ///   Init vector which is modified during processing
    /// </summary>
    FInitVector                  : TBlock16Byte;

    /// <summary>
    ///   Encodes or decodes a block of data using the supplied cipher
    /// </summary>
    /// <param name="Source">
    ///   Plain text to encrypt or decrypt, depending on encode parameter
    /// </param>
    /// <param name="Dest">
    ///   Ciphertext or plaintext after encryption or decryption, depending on
    ///   encode parameter
    /// </param>
    /// <param name="Size">
    ///   Number of bytes to encrypt or decrypt
    /// </param>
    /// <param name="Encode">
    ///   When true it is encrypting data, else it is descrypting data
    /// </param>
    procedure EncodeDecode(Source, Dest: PUInt8Array; Size: Integer; Encode: Boolean);
  strict protected
    /// <summary>
    ///   Defines the length of the resulting authentication value in bit.
    /// </summary>
    /// <param name="Value">
    ///   Sets the length of Authenticaton_tag in bit, values as per specification
    ///   are: 32, 48, 64, 80, 96, 112, 128
    /// </param>
    procedure SetAuthenticationTagLength(const Value: UInt32); override;
  public
    /// <summary>
    ///   Savely clear any buffers
    /// </summary>
    destructor Destroy; override;
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
    ///   Returns a list of authentication tag lengths explicitely specified by
    ///   the official specification of the standard.
    /// </summary>
    /// <returns>
    ///   List of bit lengths
    /// </returns>
    function GetStandardAuthenticationTagBitLengths:TStandardBitLengths; override;
  end;

implementation

uses
  DECUtil;

const
  /// <summary>
  ///   Size of one block to be processed in byte
  /// </summary>
  cBlockSize = SizeOf(TBlock16Byte);

resourcestring
  /// <summary>
  ///   Exception raised when a size but no source data pointer was passed
  /// </summary>
  sInvalidSourcePointer = 'No source data pointer passed';

procedure TCCM.Decode(Source, Dest: PUInt8Array; Size: Integer);
begin
  EncodeDecode(Source, Dest, Size, false);
end;

destructor TCCM.Destroy;
begin
  if (Length(FOrigInitVector) > 0) then
    ProtectBytes(FOrigInitVector);

  ProtectBuffer(FInitVector,                   SizeOf(FInitVector));
  ProtectBytes(FCalcAuthenticationTag);
  ProtectBytes(FExpectedAuthenticationTag);

  inherited;
end;

procedure TCCM.Encode(Source, Dest: PUInt8Array; Size: Integer);
begin
  EncodeDecode(Source, Dest, Size, true);
end;

procedure TCCM.EncodeDecode(Source, Dest: PUInt8Array;
                            Size: Integer;
                            Encode: Boolean);
var
  ecc         : TBlock16Byte; // encrypted counter
  FixedTagBuf : TBlock16Byte; // during calculation buffer of authentication tag
                              // might need to be bigger than then one specified
                              // by the user
  len         : Int32;
  k, L        : UInt16;
  b           : UInt8;
  pb          : PByte;
  AuthDataLen : Integer; // Length of data to authenticate in bytes
  InitVectLen : Integer; // Length of the init vector in bytes

  Buf         : TBlock16Byte;

  // Increment CTR[15]..CTR[16-L]
  procedure IncCTR(var CTR: TBlock16Byte);
  var
    j: integer;
  begin
    for j := 15 downto 16-L do
    begin
      if (CTR[j] = $FF) then
        CTR[j] := 0
      else
      begin
        inc(CTR[j]);
        exit;
      end;
    end;
  end;

begin
  if (Size > 0) and
     ((not Assigned(Source)) or (not Assigned(Dest))) then
    raise EDECCipherException.Create(sInvalidSourcePointer);

  AuthDataLen := Length(FDataToAuthenticate);
  InitVectLen := Length(FOrigInitVector);

  // calculate L value = max(number of bytes needed for sLen, 15-nLen)
  len := Size;
  L := 0;
  while (len > 0) do
  begin
    inc(L);
    len := len shr 8;
  end;

  // Length of nonce (= init vector) is InitVectLen
  if (InitVectLen + L > 15) then
    raise EDECNonceLengthException.CreateFmt(sWrongNonceLengthDetailed,
                                             [InitVectLen + L]);

  // Force Length(FInitVector) + L = 15. Since nLen <= 13, L is at least 2
  L := 15 - InitVectLen;

  // compose B_0 = Flags | Nonce N | l(m)
  // octet 0: Flags = 64*HdrPresent | 8*((tLen-2) div 2 | (L-1)

  if (AuthDataLen > 0) then
    b := 64
  else
    b := 0;

  // Typecast for L-1 possible, since L is at least 2, see comment above
  Buf[0] := b or ((FCalcAuthenticationTagLength-2) shl 2) or UInt16(L-1);
  // octets 1..15-L is nonce
  pb := @FOrigInitvector[0];
  for k := 1 to 15-L do
  begin
    Buf[k] := pb^;
    inc(pb);
  end;

  // octets 16-L .. 15: l(m)
  len := Size;
  for k := 1 to L do
  begin
    Buf[16-k] := len and $FF;
    len := len shr 8;
  end;

  FEncryptionMethod(@Buf[0], @Buf[0], Length(Buf));

  // process header
  if (AuthDataLen > 0) then
  begin
    // octets 0..1: encoding of hLen. Note: since we allow max $FEFF bytes
    // only these two octets are used. Generally up to 10 octets are needed.
    Buf[0] := Buf[0] xor (AuthDataLen shr 8);
    Buf[1] := Buf[1] xor (AuthDataLen and $FF);
    // now append the hdr data
    len := 2;
    pb  := @FDataToAuthenticate[0];
    for k:= 1 to AuthDataLen do
    begin
      if (len = 16) then
      begin
        FEncryptionMethod(@Buf[0], @Buf[0], Length(Buf));
        len := 0;
      end;
      Buf[len] := Buf[len] xor pb^;
      inc(len);
      inc(pb);
    end;

    if (len <> 0) then
      FEncryptionMethod(@Buf[0], @Buf[0], Length(Buf));
  end;

  // setup the counter for source text processing
  pb := @FOrigInitVector[0];
  FInitVector[0] := (L-1) and $FF;
  for k := 1 to 15 do
  begin
    if (k < 16-L) then
    begin
      FInitVector[k] := pb^;
      inc(pb);
    end
    else
      FInitVector[k] := 0;
  end;

  // process full source text blocks
  while (Size >= 16) do
  begin
    IncCTR(FInitVector);
    FEncryptionMethod(@FInitVector[0], @ecc[0], Length(FInitVector));

    if Encode then
    begin
      XORBuffers(Source[0], Buf[0], 16, Buf[0]);
      XORBuffers(Source[0], ecc[0], 16, Dest[0]);
    end
    else
    begin
      XORBuffers(Source[0], ecc[0], 16, Dest[0]);
      XORBuffers(Dest[0],   Buf[0], 16, Buf[0]);
    end;

    FEncryptionMethod(@Buf[0], @Buf[0], Length(Buf));

    inc(PByte(Source), cBlockSize);
    inc(PByte(Dest),   cBlockSize);
    dec(Size, cBlockSize);
  end;

  if (Size > 0) then
  begin
    // handle remaining bytes of source text
    IncCTR(FInitVector);

    FEncryptionMethod(@FInitVector[0], @ecc[0], Length(ecc));

    for k := 0 to UInt16(Size - 1) do
    begin
      if Encode then
      begin
        b := PByte(Source)^;
        PByte(Dest)^ := b xor ecc[k];
      end
      else
      begin
        b := PByte(Source)^ xor ecc[k];
        PByte(Dest)^ := b;
      end;
      Buf[k] := Buf[k] xor b;
      inc(PByte(Source));
      inc(PByte(Dest));
    end;

    FEncryptionMethod(@Buf[0], @Buf[0], Length(Buf));
  end;

  // setup counter for the tag (zero the count)
  for k := 15 downto 16-L do
    FInitVector[k] := 0;

  FEncryptionMethod(@FInitVector[0], @ecc[0], Length(ecc));

  // store the TAG/Authentication result value
  XORBuffers(Buf[0], ecc[0],  16, FixedTagBuf);
  Move(FixedTagBuf[0], FCalcAuthenticationTag[0], length(FCalcAuthenticationTag));

  ProtectBuffer(Buf, SizeOf(Buf));
end;

function TCCM.GetStandardAuthenticationTagBitLengths: TStandardBitLengths;
begin
  SetLength(Result, 7);
  Result := [32, 48, 64, 80, 96, 112, 128];
end;

procedure TCCM.SetAuthenticationTagLength(const Value: UInt32);
begin
  if not (Value in [32, 48, 64, 80, 96, 112, 128]) then
    raise EDECAuthLengthException.Create(sWrongCCMAuthLength);

  FCalcAuthenticationTagLength := Value shr 3;

  SetLength(FCalcAuthenticationTag, FCalcAuthenticationTagLength);
end;

procedure TCCM.Init(EncryptionMethod : TEncodeDecodeMethod;
                    InitVector       : TBytes);
begin
  Assert(Length(InitVector) > 0,     'No init vector specified');

  if (Length(InitVector) < 7) or (Length(InitVector) > 13) then
    raise EDECNonceLengthException.Create(sWrongNonceLength);

  inherited;

  FOrigInitVector := InitVector;
end;

end.
