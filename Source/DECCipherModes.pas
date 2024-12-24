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
unit DECCipherModes;
{$INCLUDE DECOptions.inc}

interface


uses
  {$IFDEF FPC}
  SysUtils,
  {$ELSE}
  System.SysUtils,
  {$ENDIF}
  DECTypes, DECCipherBase, DECCipherModesGCM, DECCipherInterface;

type
  /// <summary>
  ///   Class type of the cipher base class implementing all block
  ///   concatenation modes.
  /// </summary>
  TDECCipherModesClass = class of TDECCipherModes;

  /// <summary>
  ///   Most ciphers are block oriented and thus work on blocks of a fixed size.
  ///   In order to not encrypt each block separately without any link to his
  ///   predecessor and sucessor, which would make attacks on the encrypted data
  ///   easier, each block should be linked with his predecessor (or the
  ///   initialization vector). This class implements the various supported
  ///   algorithms for linking blocks.
  /// </summary>
  TDECCipherModes = class(TDECCipher, IDECAuthenticatedCipher)
  strict private
    /// <summary>
    ///   Returns the data which shall get authenticated when using a cipher
    ///   mode which provides authentication support as well.
    /// </summary>
    /// <returns>
    ///   Data to be authenticated. Raises an EDECCipherException if this is
    ///   called for a cipher mode not supporting authentication.
    /// </returns>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if called for a cipher mode not supporting
    ///   authentication.
    /// </exception>
    function  GetDataToAuthenticate: TBytes;
    /// <summary>
    ///   Returns the length of the resulting authentication value if a
    ///   cipher mode which provides authentication support as well is used.
    /// </summary>
    /// <returns>
    ///   Length of the authentication result in bit. Raises an
    ///   EDECCipherException if this is called for a cipher mode not supporting
    ///   authentication.
    /// </returns>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if called for a cipher mode not supporting
    ///   authentication.
    /// </exception>
    function  GetAuthenticationResultBitLength: Integer;
    /// <summary>
    ///   Returns the value calculated over the data to be authenticated if a
    ///   cipher mode which provides authentication support as well is used.
    ///   The value will be returned even if decryption resulted in a wrong value.
    ///   A wrong authentication result on decryption is signalled via exception.
    /// </summary>
    /// <returns>
    ///   Result of the authentication. Raises an EDECCipherException if this is
    ///   called for a cipher mode not supporting authentication.
    /// </returns>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if called for a cipher mode not supporting
    ///   authentication.
    /// </exception>
    function  GetCalcAuthenticatonResult: TBytes;
    /// <summary>
    ///   Defines the data which shall get authenticated when using a cipher
    ///   mode which provides authentication support as well.
    /// </summary>
    /// <param name="Value">
    ///   Data to be authenticated. Raises an EDECCipherException if this is
    ///   called for a cipher mode not supporting authentication.
    /// </param>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if called for a cipher mode not supporting
    ///   authentication.
    /// </exception>
    procedure SetDataToAuthenticate(const Value: TBytes);
    /// <summary>
    ///   Sets the length of the resulting authentication value if a
    ///   cipher mode which provides authentication support as well is used.
    /// </summary>
    /// <param name="Value">
    ///   Length of the authentication result in bit. Raises an
    ///   EDECCipherException if this is called for a cipher mode not supporting
    ///   authentication.
    /// </param>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if called for a cipher mode not supporting
    ///   authentication.
    /// </exception>
    procedure SetAuthenticationResultBitLength(const Value: Integer);
    /// <summary>
    ///   Returns the value set as expected authenthication value for ciphers
    ///   providing authehtication features as well. Raises an
    ///   EDECCipherException if this is called for a cipher mode not supporting
    ///   authentication.
    /// </summary>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if called for a cipher mode not supporting
    ///   authentication.
    /// </exception>
    function GetExpectedAuthenticationResult: TBytes;
    /// <summary>
    ///   Sets the value used as expected authenthication value when decrypting
    ///   and a cipher providing authehtication features is being used. Raises an
    ///   EDECCipherException if this is called for a cipher mode not supporting
    ///   authentication.
    /// </summary>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if called for a cipher mode not supporting
    ///   authentication.
    /// </exception>
    procedure SetExpectedAuthenticationResult(const Value: TBytes);
  strict protected
    /// <summary>
    ///   Implementation of the Galois counter mode. Only created when gmGCM is
    ///   set as mode.
    /// </summary>
    FGCM : TGCM;
    /// <summary>
    ///   Raises an EDECCipherException exception and provides the correct value
    ///   for block size in that message
    /// </summary>
    /// <exception cref="EDECCipherException">
    ///   Exception raised unconditionally.
    /// </exception>
    procedure ReportInvalidMessageLength(Cipher: TDECCipher);
    /// <summary>
    ///   Allows to run code after the initialization vector has been initialized
    ///   inside the Init call, which is after DoInit has been called.
    /// </summary>
    /// <param name="OriginalInitVector">
    ///   Value of the init vector as originally passed to the Init call without
    ///   any initialization steps done to/on it
    /// </param>
    procedure OnAfterInitVectorInitialization(const OriginalInitVector: TBytes); override;
    /// <summary>
    ///   Electronic Code Book
    ///   Mode cmECBx needs message padding to be a multiple of Cipher.BlockSize
    ///   and should be used only in 1-byte Streamciphers.
    ///   This one works on Blocks of Cipher.BufferSize bytes, when using a
    ///   Blockcipher that's equal to Cipher.BlockSize.
    /// </summary>
    /// <remarks>
    ///   This mode should not be used in practice, as it makes the encrypted
    ///   message vulnerable to certain attacks without knowing the encryption key
    /// </remarks>
    procedure EncodeECBx(Source, Dest: PUInt8Array; Size: Integer); virtual;
    /// <summary>
    ///   8bit Output Feedback mode, needs no padding
    /// </summary>
    procedure EncodeOFB8(Source, Dest: PUInt8Array; Size: Integer); virtual;
    /// <summary>
    ///   8 bit Cipher Feedback mode, needs no padding and works on 8 bit
    ///   Feedback Shift Registers.
    /// </summary>
    procedure EncodeCFB8(Source, Dest: PUInt8Array; Size: Integer); virtual;
    /// <summary>
    ///   8Bit CFS, double Cipher Feedback mode (CFB), needs no padding and
    ///   works on 8 bit Feedback Shift Registers.
    ///   This one is a proprietary mode developed by Hagen Reddmann. This mode
    ///   works as cmCBCx, cmCFBx, cmCFB8 but with double XOR'ing of the
    ///   inputstream into Feedback register.
    /// </summary>
    procedure EncodeCFS8(Source, Dest: PUInt8Array; Size: Integer); virtual;
    /// <summary>
    ///   Cipher Feedback mode (CFB) on Blocksize of Cipher, needs no padding
    ///   This one works on Blocks of Cipher.BufferSize bytes, when using a
    ///   Blockcipher that's equal to Cipher.BlockSize.
    /// </summary>
    procedure EncodeCFBx(Source, Dest: PUInt8Array; Size: Integer); virtual;
    /// <summary>
    ///   Output Feedback mode on Blocksize of Cipher, needs no padding and
    ///   works on 8 bit Feedback Shift Registers.
    ///   This one works on Blocks of Cipher.BufferSize bytes, when using a
    ///   Blockcipher that's equal to Cipher.BlockSize.
    /// </summary>
    procedure EncodeOFBx(Source, Dest: PUInt8Array; Size: Integer); virtual;
    /// <summary>
    ///   double Cipher Feedback mode (CFB) on Blocksize of Cipher, needs no padding.
    ///   This one works on Blocks of Cipher.BufferSize bytes, when using a
    ///   Blockcipher that's equal to Cipher.BlockSize.
    ///   This one is a proprietary mode developed by Hagen Reddmann. This mode
    ///   works as cmCBCx, cmCFBx, cmCFB8 but with double XOR'ing of the
    ///   inputstream into Feedback register.
    /// </summary>
    procedure EncodeCFSx(Source, Dest: PUInt8Array; Size: Integer); virtual;
    /// <summary>
    ///   Cipher Block Chaining, with CFB8 padding of truncated final block
    ///   It needs no external padding, because internally the last
    ///   truncated block is padded by cmCFS8 or cmCFB8. After padding these Modes
    ///   cannot be used to process any more data. If needed to process chunks of
    ///   data then each chunk must be aligned to Cipher.BufferSize bytes.
    ///   This one works on Blocks of Cipher.BufferSize bytes, when using a
    ///   Blockcipher that's equal to Cipher.BlockSize.
    /// </summary>
    procedure EncodeCBCx(Source, Dest: PUInt8Array; Size: Integer); virtual;
    /// <summary>
    ///   double CBC, with CFS8 padding of truncated final block
    ///   It needs no external padding, because internally the last
    ///   truncated block is padded by cmCFS8 or cmCFB8. After padding these Modes
    ///   cannot be used to process any more data. If needed to process chunks of
    ///   data then each chunk must be aligned to Cipher.BufferSize bytes.
    ///   This one works on Blocks of Cipher.BufferSize bytes, when using a
    ///   Blockcipher that's equal to Cipher.BlockSize.
    ///   This one is a proprietary mode developed by Hagen Reddmann. This mode
    ///   works as cmCBCx, cmCFBx, cmCFB8 but with double XOR'ing of the
    ///   inputstream into Feedback register.
    /// </summary>
    procedure EncodeCTSx(Source, Dest: PUInt8Array; Size: Integer); virtual;
    /// <summary>
    ///   Galois Counter Mode: encryption with addtional optional authentication.
    ///   Implemented in its own unit, but needed here to be callable even if
    ///   source length is 0.
    /// </summary>
    procedure EncodeGCM(Source, Dest: PUInt8Array; Size: Integer); virtual;
    {$IFDEF DEC3_CMCTS}
    /// <summary>
    ///   double CBC, with
    ///   for DEC 3.0 compatibility only
    ///   This is a proprietary mode developed by Frederik Winkelsdorf. It
    ///   replaces the CFS8 padding of the truncated final block with a CFSx padding.
    ///   Useful when converting projects that previously used the old DEC v3.0. It
    ///   has the same restrictions for external padding and chunk processing as
    ///   cmCTSx has. It has a less secure padding of the truncated final block.
    ///   (to enable it see DECOptions.inc)
    /// </summary>
    procedure EncodeCTS3(Source, Dest: PUInt8Array; Size: Integer); virtual;
    {$ENDIF}
    /// <summary>
    ///   Electronic Code Book
    ///   Mode cmECBx needs message padding to be a multiple of Cipher.BlockSize
    ///   and should be used only in 1-byte Streamciphers.
    ///   This one works on blocks of Cipher.BufferSize bytes, when using a
    ///   blockcipher that's equal to Cipher.BlockSize.
    /// </summary>
    procedure DecodeECBx(Source, Dest: PUInt8Array; Size: Integer); virtual;
    /// <summary>
    ///   8 bit Output Feedback mode, needs no padding
    /// </summary>
    procedure DecodeOFB8(Source, Dest: PUInt8Array; Size: Integer); virtual;
    /// <summary>
    ///   8 bit Cipher Feedback mode, needs no padding and works on 8 bit
    ///   Feedback Shift Registers.
    /// </summary>
    procedure DecodeCFB8(Source, Dest: PUInt8Array; Size: Integer); virtual;
    /// <summary>
    ///   8 Bit CFS, double Cipher Feedback mode (CFB), needs no padding and
    ///   works on 8 bit Feedback Shift Registers.
    ///   This one is a proprietary mode developed by Hagen Reddmann. This mode
    ///   works as cmCBCx, cmCFBx, cmCFB8 but with double XOR'ing of the
    ///   inputstream into Feedback register.
    /// </summary>
    procedure DecodeCFS8(Source, Dest: PUInt8Array; Size: Integer); virtual;
    /// <summary>
    ///   Cipher Feedback mode (CFB) on Blocksize of Cipher, needs no padding
    ///   This one works on blocks of Cipher.BufferSize bytes, when using a
    ///   blockcipher that's equal to Cipher.BlockSize.
    /// </summary>
    procedure DecodeCFBx(Source, Dest: PUInt8Array; Size: Integer); virtual;
    /// <summary>
    ///   Output Feedback mode on Blocksize of Cipher, needs no padding and
    ///   works on 8 bit Feedback Shift Registers.
    ///   This one works on blocks of Cipher.BufferSize bytes, when using a
    ///   blockcipher that's equal to Cipher.BlockSize.
    /// </summary>
    procedure DecodeOFBx(Source, Dest: PUInt8Array; Size: Integer); virtual;
    /// <summary>
    ///   double Cipher Feedback mode (CFB) on Blocksize of Cipher, needs no padding.
    ///   This one works on blocks of Cipher.BufferSize bytes, when using a
    ///   blockcipher that's equal to Cipher.BlockSize.
    ///   This one is a proprietary mode developed by Hagen Reddmann. This mode
    ///   works as cmCBCx, cmCFBx, cmCFB8 but with double XOR'ing of the
    ///   inputstream into Feedback register.
    /// </summary>
    procedure DecodeCFSx(Source, Dest: PUInt8Array; Size: Integer); virtual;
    /// <summary>
    ///   Cipher Block Chaining, with CFB8 padding of truncated final block.
    ///   It needs no external padding, because internally the last
    ///   truncated block is padded by cmCFS8 or cmCFB8. After padding these modes
    ///   cannot be used to process any more data. If needed to process chunks of
    ///   data then each chunk must be algined to Cipher.BufferSize bytes.
    ///   This one works on blocks of Cipher.BufferSize bytes, when using a
    ///   blockcipher that's equal to Cipher.BlockSize.
    /// </summary>
    procedure DecodeCBCx(Source, Dest: PUInt8Array; Size: Integer); virtual;
    /// <summary>
    ///   double CBC, with CFS8 padding of truncated final block
    ///   It needs no external padding, because internally the last
    ///   truncated block is padded by cmCFS8 or cmCFB8. After padding these Modes
    ///   cannot be used to process any more data. If needed to process chunks of
    ///   data then each chunk must be algined to Cipher.BufferSize bytes.
    ///   This one works on blocks of Cipher.BufferSize bytes, when using a
    ///   blockcipher that's equal to Cipher.BlockSize.
    ///   This one is a proprietary mode developed by Hagen Reddmann. This mode
    ///   works as cmCBCx, cmCFBx, cmCFB8 but with double XOR'ing of the
    ///   inputstream into feedback register.
    /// </summary>
    procedure DecodeCTSx(Source, Dest: PUInt8Array; Size: Integer); virtual;
    /// <summary>
    ///   Galois Counter Mode, details are implemented in DECCipherModesGCM
    /// </summary>
    procedure DecodeGCM(Source, Dest: PUInt8Array; Size: Integer); virtual;
    {$IFDEF DEC3_CMCTS}
    /// <summary>
    ///   double CBC
    ///   This is a proprietary mode developed by Frederik Winkelsdorf. It
    ///   replaces the CFS8 padding of the truncated final block with a CFSx padding.
    ///   Useful when converting projects that previously used the old DEC v3.0. It
    ///   has the same restrictions for external padding and chunk processing as
    ///   cmCTSx has. It has a less secure padding of the truncated final block.
    ///   (to enable it see DECOptions.inc)
    /// </summary>
    /// <remarks>
    ///   For DEC 3.0 compatibility only
    /// </remarks>
    procedure DecodeCTS3(Source, Dest: PUInt8Array; Size: Integer); virtual;
    {$ENDIF}
    /// <summary>
    ///   When setting mode to GCM the GCM implementing class instance needs to
    ///   be created
    /// </summary>
    procedure InitMode; override;
  public
    /// <summary>
    ///   Frees, if necessary, internal objects
    /// </summary>
    destructor Destroy; override;
    /// <summary>
    ///   Encrypts a given block of data
    /// </summary>
    /// <param name="Source">
    ///   Data to be encrypted
    /// </param>
    /// <param name="Dest">
    ///   Data after encryption
    /// </param>
    /// <param name="DataSize">
    ///   Size of the data the Source parameter points to in byte
    /// </param>
    procedure Encode(const Source; var Dest; DataSize: Integer);
    /// <summary>
    ///   Decrypts a given block of data
    /// </summary>
    /// <param name="Source">
    ///   Data to be Decrypted
    /// </param>
    /// <param name="Dest">
    ///   Data after decryption
    /// </param>
    /// <param name="DataSize">
    ///   Size of the data the Source parameter points to in byte
    /// </param>
    procedure Decode(const Source; var Dest; DataSize: Integer);

    /// <summary>
    ///   Properly finishes the cryptographic operation. It needs to be called
    ///   at the end of encrypting or decrypting data, otherwise the last block
    ///   or last byte of the data will not be properly processed.
    /// </summary>
    procedure Done; override;

    /// <summary>
    ///   Returns a list of CalculatedAuthenticationResult lengths explicitely
    ///   specified by the official specification of the standard.
    /// </summary>
    /// <returns>
    ///   List of bit lengths. If the cipher mode used is not an authenticated
    ///   one, the array will just contain a single value of 0.
    /// </returns>
    function GetStandardAuthenticationTagBitLengths:TStandardBitLengths;

    /// <summary>
    ///   Some block chaining modes have the ability to authenticate the message
    ///   in addition to encrypting it. This property contains the data which
    ///   shall be authenticated in parallel to the encryption. Some authenticated
    ///   modes still generate an authentication result even if no additional
    ///   data is supplied via this property, e.g. cmGCM is one of those.
    /// </summary>
    property DataToAuthenticate : TBytes
      read   GetDataToAuthenticate
      write  SetDataToAuthenticate;

    /// <summary>
    ///   Some block chaining modes have the ability to authenticate the message
    ///   in addition to encrypting it.
    ///   Represents the length of CalculatedAuthenticationResult in bit, values
    ///   as per specification are: 128, 120, 112, 104, or 96 bit. For certain
    ///   applications, they may be 64 or 32 as well, but the use of these two
    ///   tag lengths constrains the length of the input data and the lifetime
    ///   of the key.
    /// </summary>
    property AuthenticationResultBitLength : Integer
      read   GetAuthenticationResultBitLength
      write  SetAuthenticationResultBitLength;
    /// <summary>
    ///   Some block chaining modes have the ability to authenticate the message
    ///   in addition to encrypting it. This property contains the generated
    ///   authentication tag. Raises an EDECCipherException if this is
    ///   called for a cipher mode not supporting authentication.
    /// </summary>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if called for a cipher mode not supporting
    ///   authentication.
    /// </exception>
    property CalculatedAuthenticationResult  : TBytes
      read   GetCalcAuthenticatonResult;

    /// <summary>
    ///   Expected CalculatedAuthenticationResult value, will be compared with
    ///   actual value when decryption finished. Raises an EDECCipherException
    ///   if this is called for a cipher mode not supporting authentication.
    /// </summary>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if called for a cipher mode not supporting
    ///   authentication.
    /// </exception>
    property ExpectedAuthenticationResult : TBytes
      read   GetExpectedAuthenticationResult
      write  SetExpectedAuthenticationResult;
  end;

implementation

uses
  {$IFDEF FPC}
  TypInfo,
  {$ELSE}
  System.TypInfo,
  {$ENDIF}
  DECUtil;

resourcestring
  sInvalidMessageLength = 'Message length for mode %0:s must be a multiple of %1:d bytes';
  sInvalidBlockSize     = 'Block size must be %0:d bit for selected mode %1:s';
  sInvalidModeForMethod = 'Invalid mode for this method. Mode must be %0:s';

  /// <summary>
  ///   Exception message when calculated authentication value does not match
  ///   given expected one
  /// </summary>
  sInvalidAuthenticationValue = 'Calculated authentication value does not match '+
                                'given expected value';

procedure TDECCipherModes.ReportInvalidMessageLength(Cipher: TDECCipher);
begin
  raise EDECCipherException.CreateResFmt(@sInvalidMessageLength,
                                         [GetEnumName(TypeInfo(TCipherMode),
                                         Integer(Cipher.Mode)),
                                         Cipher.Context.BlockSize]);
end;

procedure TDECCipherModes.SetDataToAuthenticate(const Value: TBytes);
begin
  if (FMode = cmGCM) then
    FGCM.DataToAuthenticate := Value
  else
    raise EDECCipherException.CreateResFmt(@sInvalidModeForMethod, ['cmGCM']);
end;

procedure TDECCipherModes.SetExpectedAuthenticationResult(const Value: TBytes);
begin
  if (FMode = cmGCM) then
    FGCM.ExpectedAuthenticationTag := Value
  else
    raise EDECCipherException.CreateResFmt(@sInvalidModeForMethod, ['cmGCM']);
end;

procedure TDECCipherModes.SetAuthenticationResultBitLength(
  const Value: Integer);
begin
  if (FMode = cmGCM) then
    FGCM.AuthenticationTagBitLength := Value
  else
    raise EDECCipherException.CreateResFmt(@sInvalidModeForMethod, ['cmGCM']);
end;

procedure TDECCipherModes.Encode(const Source; var Dest; DataSize: Integer);
begin
  CheckState([csInitialized, csEncode, csDone]);

  case FMode of
    cmECBx:   EncodeECBx(@Source, @Dest, DataSize);
    cmCBCx:   EncodeCBCx(@Source, @Dest, DataSize);
    cmCTSx:   EncodeCTSx(@Source, @Dest, DataSize);
    {$IFDEF DEC3_CMCTS}
    cmCTS3:   EncodeCTS3(@Source, @Dest, DataSize);
    {$ENDIF DEC3_CMCTS}
    cmCFB8:   EncodeCFB8(@Source, @Dest, DataSize);
    cmCFBx:   EncodeCFBx(@Source, @Dest, DataSize);
    cmOFB8:   EncodeOFB8(@Source, @Dest, DataSize);
    cmOFBx:   EncodeOFBx(@Source, @Dest, DataSize);
    cmCFS8:   EncodeCFS8(@Source, @Dest, DataSize);
    cmCFSx:   EncodeCFSx(@Source, @Dest, DataSize);
    cmGCM :   EncodeGCM(@Source, @Dest, DataSize);
  end;
end;

procedure TDECCipherModes.EncodeECBx(Source, Dest: PUInt8Array; Size: Integer);
var
  I: Integer;
begin
  if Context.BlockSize = 1 then
  begin
    DoEncode(Source, Dest, Size);
    FState := csEncode;
  end
  else
  begin
    Dec(Size, FBufferSize);
    I := 0;
    while I <= Size do
    begin
      DoEncode(@Source[I], @Dest[I], FBufferSize);
      Inc(I, FBufferSize);
    end;
    Dec(Size, I - FBufferSize);
    if Size > 0 then
    begin
      if Size mod Context.BlockSize = 0 then
      begin
        DoEncode(@Source[I], @Dest[I], Size);
        FState := csEncode;
      end
      else
      begin
        FState := csPadded;
        ReportInvalidMessageLength(Self);
      end;
    end;
  end;
end;

procedure TDECCipherModes.EncodeOFB8(Source, Dest: PUInt8Array; Size: Integer);
var
  I: Integer;
begin
  I := 0;
  while I < Size do
  begin
    DoEncode(FFeedback, FBuffer, FBufferSize);
    Move(FFeedback[1], FFeedback[0], FBufferSize - 1);
    FFeedback[FBufferSize - 1] := FBuffer[0];
    Dest[I] := Source[I] xor FBuffer[0];
    Inc(I);
  end;
  FState := csEncode;
end;

procedure TDECCipherModes.EncodeCFB8(Source, Dest: PUInt8Array; Size: Integer);
// CFB-8
var
  I: Integer;
begin
  I := 0;
  while I < Size do
  begin
    DoEncode(FFeedback, FBuffer, FBufferSize);
    Move(FFeedback[1], FFeedback[0], FBufferSize - 1);
    Dest[I] := Source[I] xor FBuffer[0];
    FFeedback[FBufferSize - 1] := Dest[I];
    Inc(I);
  end;
  FState := csEncode;
end;

procedure TDECCipherModes.EncodeCFS8(Source, Dest: PUInt8Array; Size: Integer);
// CFS-8, CTS as CFB
var
  I: Integer;
begin
  I := 0;
  while I < Size do
  begin
    DoEncode(FFeedback, FBuffer, FBufferSize);
    Dest[I] := Source[I] xor FBuffer[0];
    Move(FFeedback[1], FFeedback[0], FBufferSize - 1);
    FFeedback[FBufferSize - 1] := FFeedback[FBufferSize - 1] xor Dest[I];
    Inc(I);
  end;
  FState := csEncode;
end;

procedure TDECCipherModes.EncodeCFBx(Source, Dest: PUInt8Array; Size: Integer);
// CFB-BlockSize
var
  I: Integer;
  F: PUInt8Array;
begin
  FState := csEncode;
  if FBufferIndex > 0 then
  begin
    I := FBufferSize - FBufferIndex;
    if I > Size then
      I := Size;
    XORBuffers(Source[0], FBuffer[FBufferIndex], I, Dest[0]);
    Move(Dest[0], FFeedback[FBufferIndex], I);
    Inc(FBufferIndex, I);
    if FBufferIndex < FBufferSize then
      Exit;
    Dec(Size, I);
    Source := @Source[I];
    Dest := @Dest[I];
    FBufferIndex := 0
  end;
  Dec(Size, FBufferSize);
  F := FFeedback;
  I := 0;
  while I < Size do
  begin
    DoEncode(F, FBuffer, FBufferSize);
    XORBuffers(Source[I], FBuffer[0], FBufferSize, Dest[I]);
    F := @Dest[I];
    Inc(I, FBufferSize);
  end;
  if F <> FFeedback then
    Move(F^, FFeedback^, FBufferSize);
  Dec(Size, I - FBufferSize);
  if Size > 0 then
  begin
    DoEncode(FFeedback, FBuffer, FBufferSize);
    XORBuffers(Source[I], FBuffer[0], Size, Dest[I]);
    Move(Dest[I], FFeedback[0], Size);
    FBufferIndex := Size;
  end;
end;

procedure TDECCipherModes.EncodeOFBx(Source, Dest: PUInt8Array; Size: Integer);
// OFB-BlockSize
var
  I: Integer;
begin
  FState := csEncode;
  if FBufferIndex > 0 then
  begin
    I := FBufferSize - FBufferIndex;
    if I > Size then
      I := Size;
    XORBuffers(Source[0], FFeedback[FBufferIndex], I, Dest[0]);
    Inc(FBufferIndex, I);
    if FBufferIndex < FBufferSize then
      Exit;
    Dec(Size, I);
    Source := @Source[I];
    Dest := @Dest[I];
    FBufferIndex := 0
  end;
  Dec(Size, FBufferSize);
  I := 0;
  while I < Size do
  begin
    DoEncode(FFeedback, FFeedback, FBufferSize);
    XORBuffers(Source[I], FFeedback[0], FBufferSize, Dest[I]);
    Inc(I, FBufferSize);
  end;
  Dec(Size, I - FBufferSize);
  if Size > 0 then
  begin
    DoEncode(FFeedback, FFeedback, FBufferSize);
    XORBuffers(Source[I], FFeedback[0], Size, Dest[I]);
    FBufferIndex := Size;
  end;
end;

function TDECCipherModes.GetDataToAuthenticate: TBytes;
begin
  if (FMode = cmGCM) then
    Result := FGCM.DataToAuthenticate
  else
    raise EDECCipherException.CreateResFmt(@sInvalidModeForMethod, ['cmGCM']);
end;

function TDECCipherModes.GetExpectedAuthenticationResult: TBytes;
begin
  if (FMode = cmGCM) then
    Result := FGCM.ExpectedAuthenticationTag
  else
    raise EDECCipherException.CreateResFmt(@sInvalidModeForMethod, ['cmGCM']);
end;

function TDECCipherModes.GetStandardAuthenticationTagBitLengths: TStandardBitLengths;
begin
  case FMode of
    cmGCM: Result := FGCM.GetStandardAuthenticationTagBitLengths;
    else
    begin
      SetLength(Result, 1);
      Result[0] := 0;
    end;
  end;
end;

function TDECCipherModes.GetAuthenticationResultBitLength: Integer;
begin
  if (FMode = cmGCM) then
    Result := FGCM.AuthenticationTagBitLength
  else
    raise EDECCipherException.CreateResFmt(@sInvalidModeForMethod, ['cmGCM']);
end;

function TDECCipherModes.GetCalcAuthenticatonResult: TBytes;
begin
  if (FMode = cmGCM) then
    Result := FGCM.CalculatedAuthenticationTag
  else
    raise EDECCipherException.CreateResFmt(@sInvalidModeForMethod, ['cmGCM']);
end;

procedure TDECCipherModes.InitMode;
begin
  if FMode = TCipherMode.cmGCM then
  begin
    if Context.BlockSize = 16 then
      FGCM := TGCM.Create
    else
      // GCM requires a cipher with 128 bit block size
      raise EDECCipherException.CreateResFmt(@sInvalidBlockSize,
                                             [128, GetEnumName(TypeInfo(TCipherMode),
                                             Integer(FMode))]);
  end
  else
    if Assigned(FGCM) then
      FreeAndNil(FGCM);
end;

procedure TDECCipherModes.EncodeCFSx(Source, Dest: PUInt8Array; Size: Integer);
// CFS-BlockSize
var
  I: Integer;
begin
  FState := csEncode;
  if FBufferIndex > 0 then
  begin
    I := FBufferSize - FBufferIndex;
    if I > Size then
      I := Size;
    XORBuffers(Source[0], FBuffer[FBufferIndex], I, Dest[0]);
    XORBuffers(Dest[0], FFeedback[FBufferIndex], I, FFeedback[FBufferIndex]);
    Inc(FBufferIndex, I);
    if FBufferIndex < FBufferSize then
      Exit;
    Dec(Size, I);
    Source := @Source[I];
    Dest := @Dest[I];
    FBufferIndex := 0
  end;
  Dec(Size, FBufferSize);
  I := 0;
  while I < Size do
  begin
    DoEncode(FFeedback, FBuffer, FBufferSize);
    XORBuffers(Source[I], FBuffer[0], FBufferSize, Dest[I]);
    XORBuffers(Dest[I], FFeedback[0], FBufferSize, FFeedback[0]);
    Inc(I, FBufferSize);
  end;
  Dec(Size, I - FBufferSize);
  if Size > 0 then
  begin
    DoEncode(FFeedback, FBuffer, FBufferSize);
    XORBuffers(Source[I], FBuffer[0], Size, Dest[I]);
    XORBuffers(Dest[I], FFeedback[0], Size, FFeedback[0]);
    FBufferIndex := Size;
  end;
end;

procedure TDECCipherModes.EncodeCBCx(Source, Dest: PUInt8Array; Size: Integer);
var
  F: PUInt8Array;
  I: Integer;
begin
  Dec(Size, FBufferSize);
  F := FFeedback;
  I := 0;
  while I <= Size do
  begin
    XORBuffers(Source[I], F[0], FBufferSize, Dest[I]);
    F := @Dest[I];
    DoEncode(F, F, FBufferSize);
    Inc(I, FBufferSize);
  end;
  if F <> FFeedback then
    Move(F[0], FFeedback[0], FBufferSize);
  Dec(Size, I - FBufferSize);
  if Size > 0 then
  begin  // padding
    EncodeCFB8(@Source[I], @Dest[I], Size);
    FState := csPadded;
  end
  else
    FState := csEncode;
end;

procedure TDECCipherModes.EncodeCTSx(Source, Dest: PUInt8Array; Size: Integer);
var
  I: Integer;
begin
  Dec(Size, FBufferSize);
  I := 0;
  while I <= Size do
  begin
    XORBuffers(Source[I], FFeedback[0], FBufferSize, Dest[I]);
    DoEncode(@Dest[I], @Dest[I], FBufferSize);
    XORBuffers(Dest[I], FFeedback[0], FBufferSize, FFeedback[0]);
    Inc(I, FBufferSize);
  end;
  Dec(Size, I - FBufferSize);
  if Size > 0 then
  begin // padding
    EncodeCFS8(@Source[I], @Dest[I], Size);
    FState := csPadded;
  end
  else
    FState := csEncode;
end;

procedure TDECCipherModes.EncodeGCM(Source, Dest: PUInt8Array; Size: Integer);
var
  PlainText,
  CipherText : TBytes;
begin
  if (Size > 0) then
  begin
    PlainText  := TBytes(@Source^);
    CipherText := TBytes(@Dest^);
  end
  else
  begin
    SetLength(PlainText, 0);
    SetLength(CipherText, 0);
  end;

  FGCM.EncodeGCM(PlainText, CipherText, Size);
end;

{$IFDEF DEC3_CMCTS}
procedure TDECCipherModes.EncodeCTS3(Source, Dest: PUInt8Array; Size: Integer);
var
  I: Integer;
begin
  Dec(Size, FBufferSize);
  I := 0;
  while I <= Size do
  begin
    XORBuffers(Source[I], FFeedback[0], FBufferSize, Dest[I]);
    DoEncode(@Dest[I], @Dest[I], FBufferSize);
    XORBuffers(Dest[I], FFeedback[0], FBufferSize, FFeedback[0]);
    Inc(I, FBufferSize);
  end;
  Dec(Size, I - FBufferSize);
  if Size > 0 then
  begin // padding
    EncodeCFSx(@Source[I], @Dest[I], Size); // use the padding implemented in CFSx
    FState := csPadded;
  end
  else
    FState := csEncode;
end;
{$ENDIF DEC3_CMCTS}

procedure TDECCipherModes.Decode(const Source; var Dest; DataSize: Integer);
begin
  CheckState([csInitialized, csDecode, csDone]);

  case FMode of
    cmECBx:   DecodeECBx(@Source, @Dest, DataSize);
    cmCBCx:   DecodeCBCx(@Source, @Dest, DataSize);
    cmCTSx:   DecodeCTSx(@Source, @Dest, DataSize);
    {$IFDEF DEC3_CMCTS}
    cmCTS3:   DecodeCTS3(@Source, @Dest, DataSize);
    {$ENDIF DEC3_CMCTS}
    cmCFB8:   DecodeCFB8(@Source, @Dest, DataSize);
    cmCFBx:   DecodeCFBx(@Source, @Dest, DataSize);
    cmOFB8:   DecodeOFB8(@Source, @Dest, DataSize);
    cmOFBx:   DecodeOFBx(@Source, @Dest, DataSize);
    cmCFS8:   DecodeCFS8(@Source, @Dest, DataSize);
    cmCFSx:   DecodeCFSx(@Source, @Dest, DataSize);
    cmGCM :   DecodeGCM(@Source, @Dest, DataSize);
  end;
end;

procedure TDECCipherModes.DecodeECBx(Source, Dest: PUInt8Array; Size: Integer);
var
  I: Integer;
begin
  if Context.BlockSize = 1 then
  begin
    DoDecode(Source, Dest, Size);
    FState := csDecode;
  end
  else
  begin
    Dec(Size, FBufferSize);
    I := 0;
    while I <= Size do
    begin
      DoDecode(@Source[I], @Dest[I], FBufferSize);
      Inc(I, FBufferSize);
    end;
    Dec(Size, I - FBufferSize);
    if Size > 0 then
    begin
      if Size mod Context.BlockSize = 0 then
      begin
        DoDecode(@Source[I], @Dest[I], Size);
        FState := csDecode;
      end
      else
      begin
        FState := csPadded;
        ReportInvalidMessageLength(Self);
      end;
    end;
  end;
end;

procedure TDECCipherModes.DecodeGCM(Source, Dest: PUInt8Array; Size: Integer);
var
  PlainText,
  CipherText : TBytes;
begin
  if (Size > 0) then
  begin
    PlainText  := TBytes(@Source^);
    CipherText := TBytes(@Dest^);
  end
  else
  begin
    SetLength(PlainText, 0);
    SetLength(CipherText, 0);
  end;

  FGCM.DecodeGCM(PlainText, CipherText, Size);
end;

procedure TDECCipherModes.DecodeCFB8(Source, Dest: PUInt8Array; Size: Integer);
// CFB-8
var
  I: Integer;
begin
  I := 0;
  while I < Size do
  begin
    DoEncode(FFeedback, FBuffer, FBufferSize);
    Move(FFeedback[1], FFeedback[0], FBufferSize - 1);
    FFeedback[FBufferSize - 1] := Source[I];
    Dest[I] := Source[I] xor FBuffer[0];
    Inc(I);
  end;
  FState := csDecode;
end;

procedure TDECCipherModes.DecodeOFB8(Source, Dest: PUInt8Array; Size: Integer);
// same as EncodeOFB
var
  I: Integer;
begin
  I := 0;
  while I < Size do
  begin
    DoEncode(FFeedback, FBuffer, FBufferSize);
    Move(FFeedback[1], FFeedback[0], FBufferSize - 1);
    FFeedback[FBufferSize - 1] := FBuffer[0];
    Dest[I] := Source[I] xor FBuffer[0];
    Inc(I);
  end;
  FState := csDecode;
end;

procedure TDECCipherModes.DecodeCFS8(Source, Dest: PUInt8Array; Size: Integer);
var
  I: Integer;
begin
  I := 0;
  while I < Size do
  begin
    DoEncode(FFeedback, FBuffer, FBufferSize);
    Move(FFeedback[1], FFeedback[0], FBufferSize - 1);
    FFeedback[FBufferSize - 1] := FFeedback[FBufferSize - 1] xor Source[I];
    Dest[I] := Source[I] xor FBuffer[0];
    Inc(I);
  end;
  FState := csDecode;
end;

procedure TDECCipherModes.DecodeCFBx(Source, Dest: PUInt8Array; Size: Integer);
// CFB-BlockSize
var
  I: Integer;
  F: PUInt8Array;
begin
  FState := csDecode;
  if FBufferIndex > 0 then
  begin // remaining bytes of last decode
    I := FBufferSize - FBufferIndex;
    if I > Size then
      I := Size;
    Move(Source[0], FFeedback[FBufferIndex], I);
    XORBuffers(Source[0], FBuffer[FBufferIndex], I, Dest[0]);
    Inc(FBufferIndex, I);
    if FBufferIndex < FBufferSize then
      Exit;
    Dec(Size, I);
    Source := @Source[I];
    Dest := @Dest[I];
    FBufferIndex := 0
  end;
  // process chunks of FBufferSize bytes
  Dec(Size, FBufferSize);
  I := 0;
  if Source <> Dest then
  begin
    F := FFeedback;
    while I < Size do
    begin
      DoEncode(F, FBuffer, FBufferSize);
      XORBuffers(Source[I], FBuffer[0], FBufferSize, Dest[I]);
      F := @Source[I];
      Inc(I, FBufferSize);
    end;
    if F <> FFeedback then
      Move(F^, FFeedback^, FBufferSize);
  end
  else
    while I < Size do
    begin
      DoEncode(FFeedback, FBuffer, FBufferSize);
      Move(Source[I], FFeedback[0], FBufferSize);
      XORBuffers(Source[I], FBuffer[0], FBufferSize, Dest[I]);
      Inc(I, FBufferSize);
    end;
  Dec(Size, I - FBufferSize);
  if Size > 0 then
  begin // remaining bytes
    DoEncode(FFeedback, FBuffer, FBufferSize);
    Move(Source[I], FFeedback[0], Size);
    XORBuffers(Source[I], FBuffer[0], Size, Dest[I]);
    FBufferIndex := Size;
  end;
end;

procedure TDECCipherModes.DecodeOFBx(Source, Dest: PUInt8Array; Size: Integer);
// OFB-BlockSize, same as EncodeOFBx
var
  I: Integer;
begin
  FState := csDecode;
  if FBufferIndex > 0 then
  begin
    I := FBufferSize - FBufferIndex;
    if I > Size then
      I := Size;
    XORBuffers(Source[0], FFeedback[FBufferIndex], I, Dest[0]);
    Inc(FBufferIndex, I);
    if FBufferIndex < FBufferSize then
      Exit;
    Dec(Size, I);
    Source := @Source[I];
    Dest := @Dest[I];
    FBufferIndex := 0
  end;
  Dec(Size, FBufferSize);
  I := 0;
  while I < Size do
  begin
    DoEncode(FFeedback, FFeedback, FBufferSize);
    XORBuffers(Source[I], FFeedback[0], FBufferSize, Dest[I]);
    Inc(I, FBufferSize);
  end;
  Dec(Size, I - FBufferSize);
  if Size > 0 then
  begin
    DoEncode(FFeedback, FFeedback, FBufferSize);
    XORBuffers(Source[I], FFeedback[0], Size, Dest[I]);
    FBufferIndex := Size;
  end;
end;

destructor TDECCipherModes.Destroy;
begin
  FGCM.Free;

  inherited;
end;

procedure TDECCipherModes.Done;
begin
  inherited;

  if (FMode = cmGCM) then
  begin
    if (length(FGCM.ExpectedAuthenticationTag) > 0) and
       (not IsEqual(FGCM.ExpectedAuthenticationTag, FGCM.CalculatedAuthenticationTag)) then
      raise EDECCipherAuthenticationException.Create(sInvalidAuthenticationValue);
  end;
end;

procedure TDECCipherModes.OnAfterInitVectorInitialization(const OriginalInitVector: TBytes);
begin
  inherited;

  if (FMode = cmGCM) then
    FGCM.Init(self.DoEncode, OriginalInitVector);
end;

procedure TDECCipherModes.DecodeCFSx(Source, Dest: PUInt8Array; Size: Integer);
// CFS-BlockSize
var
  I: Integer;
begin
  FState := csDecode;
  if FBufferIndex > 0 then
  begin // remaining bytes of last decode
    I := FBufferSize - FBufferIndex;
    if I > Size then
      I := Size;
    XORBuffers(Source[0], FFeedback[FBufferIndex], I, FFeedback[FBufferIndex]);
    XORBuffers(Source[0], FBuffer[FBufferIndex], I, Dest[0]);
    Inc(FBufferIndex, I);
    if FBufferIndex < FBufferSize then
      Exit;
    Dec(Size, I);
    Source := @Source[I];
    Dest := @Dest[I];
    FBufferIndex := 0
  end;
  // process chunks of FBufferSize bytes
  Dec(Size, FBufferSize);
  I := 0;
  while I < Size do
  begin
    DoEncode(FFeedback, FBuffer, FBufferSize);
    XORBuffers(Source[I], FFeedback[0], FBufferSize, FFeedback[0]);
    XORBuffers(Source[I], FBuffer[0], FBufferSize, Dest[I]);
    Inc(I, FBufferSize);
  end;
  Dec(Size, I - FBufferSize);
  if Size > 0 then
  begin // remaining bytes
    DoEncode(FFeedback, FBuffer, FBufferSize);
    XORBuffers(Source[I], FFeedback[0], Size, FFeedback[0]);
    XORBuffers(Source[I], FBuffer[0], Size, Dest[I]);
    FBufferIndex := Size;
  end;
end;

procedure TDECCipherModes.DecodeCBCx(Source, Dest: PUInt8Array; Size: Integer);
var
  I: Integer;
  F, B, T: PUInt8Array;
begin
  Dec(Size, FBufferSize);
  F := FFeedback;
  I := 0;
  if Source = Dest then
  begin
    B := FBuffer;
    while I <= Size do
    begin
      Move(Source[I], B[0], FBufferSize);
      DoDecode(@Source[I], @Source[I], FBufferSize);
      XORBuffers(Source[I], F[0], FBufferSize, Source[I]);
      T := F;
      F := B;
      B := T;
      Inc(I, FBufferSize);
    end;
  end
  else
  begin
    while I <= Size do
    begin
      DoDecode(@Source[I], @Dest[I], FBufferSize);
      XORBuffers(F[0], Dest[I], FBufferSize, Dest[I]);
      F := @Source[I];
      Inc(I, FBufferSize);
    end;
  end;
  if F <> FFeedback then
    Move(F[0], FFeedback[0], FBufferSize);
  Dec(Size, I - FBufferSize);
  if Size > 0 then
  begin
    DecodeCFB8(@Source[I], @Dest[I], Size);
    FState := csPadded;
  end
  else
    FState := csDecode;
end;

procedure TDECCipherModes.DecodeCTSx(Source, Dest: PUInt8Array; Size: Integer);
var
  I: Integer;
  F, B, T: PUInt8Array;
begin
  Dec(Size, FBufferSize);
  F := FFeedback;
  B := FBuffer;
  I := 0;
  while I <= Size do
  begin
    XORBuffers(Source[I], F[0], FBufferSize, B[0]);
    DoDecode(@Source[I], @Dest[I], FBufferSize);
    XORBuffers(Dest[I], F[0], FBufferSize, Dest[I]);
    T := B;
    B := F;
    F := T;
    Inc(I, FBufferSize);
  end;
  if F <> FFeedback then
    Move(F[0], FFeedback[0], FBufferSize);
  Dec(Size, I - FBufferSize);
  if Size > 0 then
  begin
    DecodeCFS8(@Source[I], @Dest[I], Size);
    FState := csPadded;
  end
  else
    FState := csDecode;
end;

{$IFDEF DEC3_CMCTS}
procedure TDECCipherModes.DecodeCTS3(Source, Dest: PUInt8Array; Size: Integer);
var
  I: Integer;
  F, B, T: PUInt8Array;
begin
  Dec(Size, FBufferSize);
  F := FFeedback;
  B := FBuffer;
  I := 0;
  while I <= Size do
  begin
    XORBuffers(Source[I], F[0], FBufferSize, B[0]);
    DoDecode(@Source[I], @Dest[I], FBufferSize);
    XORBuffers(Dest[I], F[0], FBufferSize, Dest[I]);
    T := B;
    B := F;
    F := T;
    Inc(I, FBufferSize);
  end;
  if F <> FFeedback then
    Move(F[0], FFeedback[0], FBufferSize);
  Dec(Size, I - FBufferSize);
  if Size > 0 then
  begin
    DecodeCFSx(@Source[I], @Dest[I], Size); // use the padding implemented in CFSx
    FState := csPadded;
  end
  else
    FState := csDecode;
end;
{$ENDIF DEC3_CMCTS}

end.
