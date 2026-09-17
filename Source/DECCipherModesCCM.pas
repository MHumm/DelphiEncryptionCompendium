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
    ///   CBC-MAC state; the authentication tag is derived from this in Done
    /// </summary>
    FMacBlock                   : TBlock16Byte;
    /// <summary>
    ///   Number of payload bytes already XORed into FMacBlock since the last AES
    /// </summary>
    FMacFill                    : Integer;
    /// <summary>
    ///   Leftover CTR keystream for unaligned multi-chunk Encode/Decode
    /// </summary>
    FKeystream                  : TBlock16Byte;
    /// <summary>
    ///   Next unused index in FKeystream
    /// </summary>
    FKeystreamOffset             : Integer;
    /// <summary>
    ///   Unused leftover keystream bytes (0..15)
    /// </summary>
    FKeystreamRemain             : Integer;
    /// <summary>
    ///   L parameter (octets of the length field) used to restore CTR_0 in Done
    /// </summary>
    FLengthFieldOctets          : UInt16;
    /// <summary>
    ///   Total payload length in bytes (known before B_0 is formatted)
    /// </summary>
    FExpectedPayloadLength       : UInt64;
    /// <summary>
    ///   Payload bytes processed since Start
    /// </summary>
    FPayloadProcessed            : UInt64;
    /// <summary>
    ///   True after DeclarePayloadLength or after the first Encode/Decode
    ///   has taken Size as the total (one-shot)
    /// </summary>
    FPayloadLengthDeclared       : Boolean;
    /// <summary>
    ///   True after B_0, AAD and CTR have been set up
    /// </summary>
    FStarted                    : Boolean;

    /// <summary>
    ///   Increments the CCM counter in the last L octets of CTR
    /// </summary>
    /// <param name="ACTR">
    ///   Counter block to increment in place
    /// </param>
    procedure IncCTR(var ACTR: TBlock16Byte);
    /// <summary>
    ///   Formats B_0 and AAD, then sets up CTR. Total payload length must
    ///   already be known (declared or taken from the first call's Size).
    /// </summary>
    /// <param name="ATotalLength">
    ///   Total payload length l(m) encoded in B_0
    /// </param>
    procedure Start(const ATotalLength: UInt64);
    /// <summary>
    ///   Starts processing on the first Encode/Decode if not already started
    /// </summary>
    /// <param name="AChunkSize">
    ///   Size of this Encode/Decode call; used as the total when no length
    ///   was declared
    /// </param>
    procedure EnsureStarted(AChunkSize: Integer);
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
    /// <summary>
    ///   Derives CalculatedAuthenticationTag from FMacBlock (S_0 XOR T).
    ///   Called from Done after Encode/Decode have finished the CBC-MAC.
    /// </summary>
    procedure FinalizeAuthenticationTag;
  strict protected
    /// <summary>
    ///   Defines the length of the resulting authentication value in bit.
    /// </summary>
    /// <param name="Value">
    ///   Sets the length of Authenticaton_tag in bit, values as per specification
    ///   are: 32, 48, 64, 80, 96, 112, 128
    /// </param>
    procedure SetAuthenticationTagLength(const Value: UInt32); override;
    /// <summary>
    ///   Rejects AAD assignment after Encode/Decode has started or after Done
    /// </summary>
    /// <param name="Value">
    ///   Additional authenticated data
    /// </param>
    procedure SetDataToAuthenticate(const Value: TBytes); override;
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
    ///   Materializes CalculatedAuthenticationTag from the CBC-MAC state.
    ///   Must be called after the last Encode/Decode (cipher Done does this).
    ///   Idempotent: a second call leaves the tag unchanged.
    ///   After finalization, Encode/Decode raise until Init is called again.
    /// </summary>
    procedure Done; override;

    /// <summary>
    ///   Returns a list of authentication tag lengths explicitely specified by
    ///   the official specification of the standard.
    /// </summary>
    /// <returns>
    ///   List of bit lengths
    /// </returns>
    function GetStandardAuthenticationTagBitLengths:TStandardBitLengths; override;

    /// <summary>
    ///   CCM can process several Encode/Decode chunks when the total payload
    ///   length is known (DeclarePayloadLength or one-shot Size). CCM is not
    ///   an online AEAD: B_0 encodes l(m). See RFC 3610 §1 / NIST SP 800-38C.
    /// </summary>
    /// <returns>
    ///   True
    /// </returns>
    function SupportsMultiChunk: Boolean; override;
    /// <summary>
    ///   Declares the total payload length in bytes before the first
    ///   Encode/Decode. Ignored if a length is already set or processing started.
    /// </summary>
    /// <param name="AByteLength">
    ///   Total plaintext/ciphertext length in bytes
    /// </param>
    procedure DeclarePayloadLength(const AByteLength: UInt64); override;
    /// <summary>
    ///   Returns the payload length declared for this CCM instance
    /// </summary>
    /// <returns>
    ///   Declared payload length in bytes
    /// </returns>
    function GetDeclaredPayloadLength: UInt64; override;
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
  sCCMPayloadTooLong =
    'CCM payload exceeds the declared length';
  sCCMIncompletePayload =
    'CCM payload is shorter than the declared length';
  sCCMAADLocked =
    'CCM DataToAuthenticate cannot be changed after Encode/Decode has started or after Done';

procedure TCCM.Decode(Source, Dest: PUInt8Array; Size: Integer);
begin
  EncodeDecode(Source, Dest, Size, false);
end;

destructor TCCM.Destroy;
begin
  if (Length(FOrigInitVector) > 0) then
    ProtectBytes(FOrigInitVector);

  ProtectBuffer(FInitVector, SizeOf(FInitVector));
  ProtectBuffer(FMacBlock, SizeOf(FMacBlock));
  ProtectBuffer(FKeystream, SizeOf(FKeystream));
  ProtectBytes(FCalcAuthenticationTag);
  ProtectBytes(FExpectedAuthenticationTag);

  inherited;
end;

procedure TCCM.Encode(Source, Dest: PUInt8Array; Size: Integer);
begin
  EncodeDecode(Source, Dest, Size, true);
end;

procedure TCCM.IncCTR(var ACTR: TBlock16Byte);
var
  j: Integer;
begin
  for j := 15 downto 16 - FLengthFieldOctets do
  begin
    if (ACTR[j] = $FF) then
      ACTR[j] := 0
    else
    begin
      Inc(ACTR[j]);
      Exit;
    end;
  end;
end;

procedure TCCM.DeclarePayloadLength(const AByteLength: UInt64);
begin
  CheckNotFinalized;

  if FStarted or FPayloadLengthDeclared then
    Exit;

  FExpectedPayloadLength := AByteLength;
  FPayloadLengthDeclared := True;
end;

function TCCM.SupportsMultiChunk: Boolean;
begin
  Result := True;
end;

function TCCM.GetDeclaredPayloadLength: UInt64;
begin
  Result := FExpectedPayloadLength;
end;

procedure TCCM.SetDataToAuthenticate(const Value: TBytes);
begin
  if FStarted or FFinalized then
    raise EDECCipherException.CreateRes(@sCCMAADLocked);

  inherited SetDataToAuthenticate(Value);
end;

procedure TCCM.Start(const ATotalLength: UInt64);
var
  len         : UInt64;
  AADPos      : Integer;
  k, L        : UInt16;
  b           : UInt8;
  pb          : PByte;
  AuthDataLen : Integer;
  InitVectLen : Integer;
  Buf         : TBlock16Byte;
begin
  AuthDataLen := Length(FDataToAuthenticate);
  InitVectLen := Length(FOrigInitVector);

  // L = bytes needed for l(m), then force nLen + L = 15 (RFC 3610 §2.1)
  len := ATotalLength;
  L := 0;
  while (len > 0) do
  begin
    Inc(L);
    len := len shr 8;
  end;

  if (InitVectLen + L > 15) then
    raise EDECNonceLengthException.CreateFmt(sWrongNonceLengthDetailed,
                                           [InitVectLen + L]);

  L := 15 - InitVectLen;
  FLengthFieldOctets := L;

  if (AuthDataLen > 0) then
    b := 64
  else
    b := 0;

  Buf[0] := b or ((FCalcAuthenticationTagLength - 2) shl 2) or UInt16(L - 1);
  pb := @FOrigInitVector[0];
  for k := 1 to 15 - L do
  begin
    Buf[k] := pb^;
    Inc(pb);
  end;

  len := ATotalLength;
  for k := 1 to L do
  begin
    Buf[16 - k] := len and $FF;
    len := len shr 8;
  end;

  FEncryptionMethod(@Buf[0], @Buf[0], Length(Buf));

  if (AuthDataLen > 0) then
  begin
    Buf[0] := Buf[0] xor (AuthDataLen shr 8);
    Buf[1] := Buf[1] xor (AuthDataLen and $FF);
    AADPos := 2;
    pb := @FDataToAuthenticate[0];
    for k := 1 to AuthDataLen do
    begin
      if (AADPos = 16) then
      begin
        FEncryptionMethod(@Buf[0], @Buf[0], Length(Buf));
        AADPos := 0;
      end;
      Buf[AADPos] := Buf[AADPos] xor pb^;
      Inc(AADPos);
      Inc(pb);
    end;

    if (AADPos <> 0) then
      FEncryptionMethod(@Buf[0], @Buf[0], Length(Buf));
  end;

  pb := @FOrigInitVector[0];
  FInitVector[0] := (L - 1) and $FF;
  for k := 1 to 15 do
  begin
    if (k < 16 - L) then
    begin
      FInitVector[k] := pb^;
      Inc(pb);
    end
    else
      FInitVector[k] := 0;
  end;

  Move(Buf[0], FMacBlock[0], SizeOf(FMacBlock));
  FMacFill := 0;
  FKeystreamRemain := 0;
  FKeystreamOffset := 0;
  FPayloadProcessed := 0;
  FStarted := True;

  ProtectBuffer(Buf, SizeOf(Buf));
end;

procedure TCCM.EnsureStarted(AChunkSize: Integer);
var
  TotalLen: UInt64;
begin
  if FStarted then
    Exit;

  if FPayloadLengthDeclared then
    TotalLen := FExpectedPayloadLength
  else
  begin
    if AChunkSize < 0 then
      TotalLen := 0
    else
      TotalLen := UInt64(AChunkSize);
    FExpectedPayloadLength := TotalLen;
    FPayloadLengthDeclared := True;
  end;

  Start(TotalLen);
end;

procedure TCCM.EncodeDecode(Source, Dest: PUInt8Array;
                            Size: Integer;
                            Encode: Boolean);
var
  ecc   : TBlock16Byte;
  b     : UInt8;
  pSrc  : PByte;
  pDst  : PByte;

  procedure AbsorbMacByte(const APlain: UInt8);
  begin
    FMacBlock[FMacFill] := FMacBlock[FMacFill] xor APlain;
    Inc(FMacFill);
    if FMacFill = 16 then
    begin
      FEncryptionMethod(@FMacBlock[0], @FMacBlock[0], SizeOf(FMacBlock));
      FMacFill := 0;
    end;
  end;

  function NextKeystreamByte: UInt8;
  begin
    if FKeystreamRemain = 0 then
    begin
      IncCTR(FInitVector);
      FEncryptionMethod(@FInitVector[0], @FKeystream[0], SizeOf(FKeystream));
      FKeystreamOffset := 0;
      FKeystreamRemain := 16;
    end;
    Result := FKeystream[FKeystreamOffset];
    Inc(FKeystreamOffset);
    Dec(FKeystreamRemain);
  end;
begin
  CheckNotFinalized;

  if Size < 0 then
  begin
    Size := 0;
  end;

  if (Size > 0) and
     ((not Assigned(Source)) or (not Assigned(Dest))) then
    raise EDECCipherException.Create(sInvalidSourcePointer);

  EnsureStarted(Size);

  if (UInt64(Size) + FPayloadProcessed) > FExpectedPayloadLength then
    raise EDECCipherException.CreateRes(@sCCMPayloadTooLong);

  // Fast path: 16-byte aligned blocks with no leftover MAC/keystream
  while (Size >= 16) and (FMacFill = 0) and (FKeystreamRemain = 0) do
  begin
    IncCTR(FInitVector);
    FEncryptionMethod(@FInitVector[0], @ecc[0], SizeOf(ecc));

    if Encode then
    begin
      XORBuffers(Source[0], FMacBlock[0], 16, FMacBlock[0]);
      XORBuffers(Source[0], ecc[0], 16, Dest[0]);
    end
    else
    begin
      XORBuffers(Source[0], ecc[0], 16, Dest[0]);
      XORBuffers(Dest[0], FMacBlock[0], 16, FMacBlock[0]);
    end;

    FEncryptionMethod(@FMacBlock[0], @FMacBlock[0], SizeOf(FMacBlock));

    Inc(PByte(Source), cBlockSize);
    Inc(PByte(Dest), cBlockSize);
    Dec(Size, cBlockSize);
    Inc(FPayloadProcessed, 16);
  end;

  pSrc := PByte(Source);
  pDst := PByte(Dest);

  while Size > 0 do
  begin
    if Encode then
    begin
      b := pSrc^;
      pDst^ := b xor NextKeystreamByte;
      AbsorbMacByte(b);
    end
    else
    begin
      b := pSrc^ xor NextKeystreamByte;
      pDst^ := b;
      AbsorbMacByte(b);
    end;
    Inc(pSrc);
    Inc(pDst);
    Dec(Size);
    Inc(FPayloadProcessed);
  end;
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
  FStarted := False;
  FPayloadLengthDeclared := False;
  FExpectedPayloadLength := 0;
  FPayloadProcessed := 0;
  FLengthFieldOctets := 0;
  FMacFill := 0;
  FKeystreamRemain := 0;
  FKeystreamOffset := 0;
end;

procedure TCCM.FinalizeAuthenticationTag;
var
  ecc         : TBlock16Byte;
  FixedTagBuf : TBlock16Byte;
  k           : UInt16;
begin
  // Restore CTR_0 (zero the count) and encrypt to get S_0, then tag = T XOR S_0.
  // See RFC 3610 §2.6 / NIST SP 800-38C: authentication tag is not part of Encode.
  for k := 15 downto 16 - FLengthFieldOctets do
  begin
    FInitVector[k] := 0;
  end;

  FEncryptionMethod(@FInitVector[0], @ecc[0], Length(ecc));

  XORBuffers(FMacBlock[0], ecc[0], 16, FixedTagBuf);
  if (Length(FCalcAuthenticationTag) > 0) then
  begin
    Move(FixedTagBuf[0], FCalcAuthenticationTag[0], Length(FCalcAuthenticationTag));
  end;

  ProtectBuffer(ecc, SizeOf(ecc));
  ProtectBuffer(FixedTagBuf, SizeOf(FixedTagBuf));
end;

procedure TCCM.Done;
begin
  if FFinalized then
    Exit;

  if not FStarted then
  begin
    // Empty payload / AAD-only: format B_0 with l(m)=0 and process AAD.
    EnsureStarted(0);
  end;

  if FPayloadProcessed < FExpectedPayloadLength then
    raise EDECCipherException.CreateRes(@sCCMIncompletePayload);

  // Last partial CBC-MAC block is padded with implicit zeros (already in
  // the un-xored tail of FMacBlock) and encrypted here, not at chunk boundaries.
  if FMacFill > 0 then
  begin
    FEncryptionMethod(@FMacBlock[0], @FMacBlock[0], SizeOf(FMacBlock));
    FMacFill := 0;
  end;

  FinalizeAuthenticationTag;
  inherited;
end;

end.
