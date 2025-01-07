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
unit DECCipherPaddings;
{$INCLUDE DECOptions.inc}

interface

uses
  {$IFDEF FPC}
  SysUtils,
  {$ELSE}
  System.SysUtils,
  {$ENDIF}
  DECTypes;

type
  /// <summary>
  ///   Base class for implementing block padding algorithms.
  /// </summary>
  /// <remarks>
  ///   Padding algorithms are used to fill data to a specific block size when the
  ///   data length is not an integer multiple of the block size.
  ///   This abstract class defines the basic interfaces for adding, validating,
  ///   and removing padding.
  /// </remarks>
  TPaddingBase = class abstract
    /// <summary>
    ///   Adds padding to the specified data to align it with the given block size.
    /// </summary>
    /// <param name="Data">
    ///   The data to be padded.
    /// </param>
    /// <param name="BlockSize">
    ///   The block size to align the data with.
    /// </param>
    /// <returns>
    ///   The padded data.
    /// </returns>
    /// <remarks>
    ///   The specific method of padding depends on the implementation of the subclass.
    /// </remarks>
    class function AddPadding(const Data : TBytes;
                              BlockSize  : Integer): TBytes; overload; virtual; abstract;

    // <summary>
    ///   Adds padding to a string.
    /// </summary>
    /// <param name="data">
    ///   The string to which padding should be added.
    /// </param>
    /// <param name="BlockSize">
    ///   The block size in byte to align the data with.
    /// </param>
    /// <returns>
    ///   A new byte string with padding applied.
    /// </returns>
    /// <remarks>
    ///   This method must be override by a concrete padding algorithm.
    /// <para>
    ///   Call this method before starting encryption.
    //  </para>
    /// </remarks>
    class function AddPadding(const Data : string;
                              BlockSize  : Integer): string; overload; virtual; abstract;
    // <summary>
    ///   Adds padding to a raw byte string.
    /// </summary>
    /// <param name="data">
    ///   The raw byte string to which padding should be added.
    /// </param>
    /// <param name="BlockSize">
    ///   The block size in byte to align the data with.
    /// </param>
    /// <returns>
    ///   A new byte raw byte string with padding applied.
    /// </returns>
    /// <remarks>
    ///   This method must be override by a concrete padding algorithm.
    /// <para>
    ///   Call this method before starting encryption.
    /// </para>
    /// </remarks>
    class function AddPadding(const Data : RawByteString;
                              BlockSize  : Integer): RawByteString; overload; virtual; abstract;
    /// <summary>
    ///   Checks if the specified data contains valid padding.
    /// </summary>
    /// <param name="Data">
    ///   The data to be checked.
    /// </param>
    /// <param name="BlockSize">
    ///   The expected block size.
    /// </param>
    /// <returns>
    ///   True if the padding is valid; otherwise, False.
    /// </returns>
    /// <remarks>
    ///   This method is used to ensure the integrity and consistency of the padding.
    /// </remarks>
    class function HasValidPadding(const Data : TBytes;
                                   BlockSize  : Integer): Boolean; virtual; abstract;
    /// <summary>
    ///   Removes padding from the specified data.
    /// </summary>
    /// <param name="Data">
    ///   The data from which padding will be removed.
    /// </param>
    /// <param name="BlockSize">
    ///   The block size in bytes used for padding.
    /// </param>
    /// <returns>
    ///   The original data without padding.
    /// </returns>
    /// <remarks>
    ///   This method assumes that the padding has already been validated.
    /// </remarks>
    class function RemovePadding(const Data : TBytes;
                                 BlockSize  : Integer): TBytes; overload; virtual; abstract;
    // <summary>
    ///   Removes padding from a raw byte string.
    /// </summary>
    /// <param name="data">
    ///   The padded byte raw byte string.
    /// </param>
    /// <param name="BlockSize">
    ///   The block size in bytes used for padding.
    /// </param>
    /// <returns>
    ///   A new raw byte string with the padding removed. Raises an exception
    ///   if the padding is invalid.
    /// </returns>
    /// <exception cref="EDECCipherException">
    ///   Raised if the padding is invalid or missing.
    /// </exception>
    /// <remarks>
    ///   This function checks for valid padding and raises an
    ///   `EDECCipherException` exception if the padding is incorrect.
    ///   <para>
    ///     Call this method after decryption.
    ///   </para>
    /// </remarks>
    class function RemovePadding(const Data : RawByteString;
                                 BlockSize  : Integer): RawByteString; overload; virtual; abstract;
    // <summary>
    ///   Removes padding from a string.
    /// </summary>
    /// <param name="data">
    ///   The padded byte raw byte string.
    /// </param>
    /// <param name="BlockSize">
    ///   The block size in bytes used for padding.
    /// </param>
    /// <returns>
    ///   A new raw byte string with the padding removed. Raises an exception
    ///   if the padding is invalid.
    /// </returns>
    /// <exception cref="EDECCipherException">
    ///   Raised if the padding is invalid or missing.
    /// </exception>
    /// <remarks>
    ///   This function expects a valid padding and raises an
    ///   `EDECCipherException` exception if the padding is incorrect.
    ///   <para>
    ///     Call this method after decryption.
    ///   </para>
    /// </remarks>
    class function RemovePadding(const Data : string;
                                 BlockSize  : Integer): string; overload; virtual; abstract;
  end;

  /// <summary>
  ///   Class type of the padding base class, relevant for the class registration
  ///   and simplified use in DECipherFormsts.
  /// </summary>
  TDECPaddingClass = class of TPaddingBase;

  /// <summary>
  ///   Base class for the PKCS7 and ANSI X.923 algorithms, as they are quite similar.
  /// </summary>
  /// <remarks>
  ///   PKCS7 padding is a standard algorithm used in symmetric cryptosystems like AES.
  ///   It appends the number of padding bytes as the value of the padding itself.
  /// </remarks>
  TFixedBytePadding = class abstract(TPaddingBase)
  strict protected
    /// <summary>
    ///   Check if block size is supported by the concerete padding algorithm.
    /// </summary>
    /// <param name="BlockSize">
    ///   The length of the block.
    /// </param>
    /// <returns>
    ///   True, if block size is expected otherwise false.
    /// </returns>
    class function IsBlockSizeValid(BlockSize: Integer): Boolean; virtual; abstract;

    /// <summary>
    ///   Calculates the length of the padding.
    /// </summary>
    /// <param name="DataSize">
    ///   The length of the data in bytes.
    /// </param>
    /// <param name="BlockSize">
    ///   The length of the block in bytes.
    /// </param>
    /// <returns>
    ///   Length of the padding in bytes. Can not be zero. When the DataSize
    ///   is a multiply of the BlockSize the method returns the sum of DataSize and
    ///   BlockSize.
    /// </returns>
    class function GetPadLength(DataSize, BlockSize: Integer): Integer; virtual;

    /// <summary>
    ///   Retrieves the padding character used to fill up the last block(s).
    /// </summary>
    /// <param name="PaddingLength">
    ///   The length of the padding in byte.
    /// </param>
    /// <param name="IsLastPaddingByte">
    ///   True if the last padding byte is filled
    /// </param>
    /// <returns>
    ///   The byte value used as padding
    /// </returns>
    class function GetPaddingByte(PaddingLength     : Integer;
                                  IsLastPaddingByte : Boolean): UInt8; virtual; abstract;
  public
    /// <summary>
    ///   Adds padding to the specified data, depending on the padding byte
    ///   returned by GetPaddingByte.
    /// </summary>
    /// <param name="Data">
    ///   The data to be padded.
    /// </param>
    /// <param name="BlockSize">
    ///   The block size in byte to align the data with.
    /// </param>
    /// <returns>
    ///   The padded data following the algorithm implemented by the derrived class.
    /// </returns>
    class function AddPadding(const Data : TBytes;
                              BlockSize  : Integer): TBytes; override;

    // <summary>
    ///   Adds padding to the specified string, depending on the padding byte
    ///   returned by GetPaddingByte.
    /// </summary>
    /// <param name="data">
    ///   The string to which padding should be added.
    /// </param>
    /// <param name="BlockSize">
    ///   The block size in byte to align the data with.
    /// </param>
    /// <returns>
    ///   A new byte string with padding applied following the algorithm
    ///   implemented by the derrived class.
    /// </returns>
    /// <remarks>
    ///   Call this method before starting encryption.
    /// </remarks>
    class function AddPadding(const Data : string;
                              BlockSize  : Integer): string; override;

    // <summary>
    ///   Adds padding to the specified raw byte string, depending on the padding
    ///   byte returned by GetPaddingByte.
    /// </summary>
    /// <param name="data">
    ///   The raw byte string to which padding should be added.
    /// </param>
    /// <param name="BlockSize">
    ///   The block size in byte to align the data with.
    /// </param>
    /// <returns>
    ///   A new raw byte string with padding applied following the algorithm
    ///   implemented by the derrived class.
    /// </returns>
    /// <remarks>
    ///   Call this method before starting encryption.
    /// </remarks>
    class function AddPadding(const Data : RawByteString;
                              BlockSize  : Integer): RawByteString; override;

    /// <summary>
    ///   Validates if the specified data contains valid padding as defined by
    ///   GetPaddingByte.
    /// </summary>
    /// <param name="Data">
    ///   The data to be checked.
    /// </param>
    /// <param name="BlockSize">
    ///   The expected block size.
    /// </param>
    /// <returns>
    ///   True if the padding is valid; otherwise, False.
    /// </returns>
    class function HasValidPadding(const Data : TBytes;
                                   BlockSize  : Integer): Boolean; override;

    /// <summary>
    ///   Removes a fixed byte padding from the specified data.
    /// </summary>
    /// <param name="Data">
    ///   The data from which padding will be removed.
    /// </param>
    /// <param name="BlockSize">
    ///   The block size used for padding.
    /// </param>
    /// <exception cref="EDECCipherException">
    ///   Raised if the padding is invalid or missing.
    /// </exception>
    /// <returns>
    ///   The original data without padding.
    /// </returns>
    class function RemovePadding(const Data : TBytes;
                                 BlockSize  : Integer): TBytes; override;
    // <summary>
    ///   Removes a fixed byte padding from a raw byte string.
    /// </summary>
    /// <param name="data">
    ///   The padded byte raw byte string.
    /// </param>
    /// <param name="BlockSize">
    ///   The block size in bytes used for padding.
    /// </param>
    /// <returns>
    ///   A new raw byte string with the padding removed. Raises an exception
    ///   if the padding is invalid.
    /// </returns>
    /// <exception cref="EDECCipherException">
    ///   Raised if the padding is invalid or missing.
    /// </exception>
    /// <remarks>
    ///   This function checks for valid a fixed byte padding (depending on the
    ///   derrived class) and raises an `EDECCipherException` exception if the
    ///   padding is incorrect. This includes cases where the final bytes do not
    ///   match the pad count or if the pad count is greater than the block size.
    ///   <para>
    ///     Call this method after decryption.
    ///   </para>
    /// </remarks>
    class function RemovePadding(const Data : RawByteString;
                                 BlockSize  : Integer): RawByteString; override;
    // <summary>
    ///   Removes a fixed byte padding from a string.
    /// </summary>
    /// <param name="data">
    ///   The padded byte raw byte string.
    /// </param>
    /// <param name="BlockSize">
    ///   The block size in bytes used for padding.
    /// </param>
    /// <returns>
    ///   A new raw byte string with the padding removed. Raises an exception
    ///   if the padding is invalid.
    /// </returns>
    /// <exception cref="EDECCipherException">
    ///   Raised if the padding is invalid or missing.
    /// </exception>
    /// <remarks>
    ///   This function checks for valid a fixed byte padding (depending on the
    ///   derrived class) and raises an `EDECCipherException` exception if the
    ///   padding is incorrect. This includes cases where the final bytes do not
    ///   match the pad count or if the pad count is greater than the block size.
    ///   <para>
    ///     Call this method after decryption.
    ///   </para>
    /// </remarks>
    class function RemovePadding(const Data : string;
                                 BlockSize  : Integer): string; override;
  end;

  /// <summary>
  ///   Implementation of the PKCS7 padding algorithm.
  /// </summary>
  /// <remarks>
  ///   PKCS7 padding is a standard algorithm used in symmetric cryptosystems
  ///   like AES.
  ///   PKCS#7 padding, as defined in RFC 5652 (which updates RFC 2315), adds
  ///   bytes to the end of the data so that the total length is a multiple of
  ///   the block size. Each padding byte contains the number of padding bytes
  ///   added. For example, if 5 bytes of padding are needed, each of the 5
  ///   padding bytes will have the value $5.
  /// </remarks>
  TPKCS7Padding = class(TFixedBytePadding)
  strict protected
    /// <summary>
    ///   Check if block size is supported by the concerete padding algorithm.
    /// </summary>
    /// <param name="BlockSize">
    ///   The length of the block size for PKCS#7 must be in the range of 1..255.
    /// </param>
    /// <returns>
    ///   True, if block size is in expected range of 1..255, otherwise false.
    /// </returns>
    class function IsBlockSizeValid(BlockSize: Integer): Boolean; override;

    /// <summary>
    ///   Retrieves the padding character used to fill up the last block(s).
    /// </summary>
    /// <param name="PaddingLength">
    ///   The length of the padding in byte.
    /// </param>
    /// <param name="IsLastPaddingByte">
    ///   True if the last padding byte is filled
    /// </param>
    /// <returns>
    ///   The byte value used as padding
    /// </returns>
    class function GetPaddingByte(PaddingLength     : Integer;
                                  IsLastPaddingByte : Boolean): UInt8; override;
  end;

  /// <summary>
  ///   PKCS#5 is a subset of the PKCS#7 padding algorithm for block size of
  ///   8 bytes. Better use PKCS#7 where possible.
  /// </summary>
  TPKCS5Padding = class(TPKCS7Padding)
  strict protected
    /// <summary>
    ///   Check if block size is supported by the concerete padding algorithm.
    /// </summary>
    /// <param name="BlockSize">
    ///   The length of the block size for PKCS#5 must be 8.
    /// </param>
    /// <returns>
    ///   True, if block size is 8, otherwise false.
    /// </returns>
    class function IsBlockSizeValid(BlockSize: Integer): Boolean; override;
  end;

  /// <summary>
  ///   Implementation of the ANSI X9.23 padding algorithm.
  /// </summary>
  /// <remarks>
  ///   ANSI X9.23 padding is a standard algorithm used in symmetric cryptosystems
  ///   like AES and is a close relative to PKCS#7.
  ///   ANSI X9.23 padding ads #0 (instead as #PadLength like PKCS#7) for all
  ///   padding positions except the last which contains #PadLength identically
  ///   to PKCS#7.
  /// </remarks>
  TANSI_X9_23_Padding = class(TFixedBytePadding)
  strict protected
    /// <summary>
    ///   Check if block size is supported by the concerete padding algorithm.
    /// </summary>
    /// <param name="BlockSize">
    ///   The length of the block size must be 1 or higher.
    /// </param>
    /// <returns>
    ///   True, if block size is > 0, otherwise false.
    /// </returns>
    class function IsBlockSizeValid(BlockSize: Integer): Boolean; override;
    /// <summary>
    ///   Retrieves the padding character used to fill up the last block(s).
    /// </summary>
    /// <param name="PaddingLength">
    ///   The length of the padding in byte.
    /// </param>
    /// <param name="IsLastPaddingByte">
    ///   True if the last padding byte is filled
    /// </param>
    /// <returns>
    ///   The byte value used as padding
    /// </returns>
    class function GetPaddingByte(PaddingLength     : Integer;
                                  IsLastPaddingByte : Boolean): UInt8; override;
  public
    /// <summary>
    ///   Validates if the specified data contains valid padding as defined by
    ///   GetPaddingByte.
    /// </summary>
    /// <param name="Data">
    ///   The data to be checked.
    /// </param>
    /// <param name="BlockSize">
    ///   The expected block size.
    /// </param>
    /// <returns>
    ///   True if the padding is valid; otherwise, False.
    /// </returns>
    /// <remarks>
    ///   ANSI X9.23 padding standard algorithm does not specify padding bytes
    ///   values except the last byte. That is why only the last byte is checked
    ///   here.
    /// </returns>
    class function HasValidPadding(const Data : TBytes;
                                   BlockSize  : Integer): Boolean; override;
  end;

  /// <summary>
  ///   ISO 10126 is smilar to ANSI X9.23 padding, but it uses a random padding
  ///   instead #0. This can provide some security advantages because the clear
  ///   text of the pad is less predictable than using #0.
  /// </summary>
  TISO10126Padding = class(TANSI_X9_23_Padding)
  strict protected
    /// <summary>
    ///   Retrieves the padding character used to fill up the last block(s).
    /// </summary>
    /// <param name="PaddingLength">
    ///   The length of the padding in byte.
    /// </param>
    /// <param name="IsLastPaddingByte">
    ///   True if the last padding byte is filled
    /// </param>    /// <returns>
    ///   The byte value used as padding
    /// </returns>
    class function GetPaddingByte(PaddingLength     : Integer;
                                  IsLastPaddingByte : Boolean): UInt8; override;
  end;

  /// <summary>
  ///   This padding algorithm variant (defined in a series of standards for
  ///   chip cards) marks the end of the data with #80 and fills the necessary
  ///   padding with #0
  /// </summary>
  TISO7816Padding = class(TFixedBytePadding)
  strict protected
    /// <summary>
    ///   Check if block size is supported by the concerete padding algorithm.
    /// </summary>
    /// <param name="BlockSize">
    ///   The length of the block size must be 1 or higher.
    /// </param>
    /// <returns>
    ///   True, if block size is > 0, otherwise false.
    /// </returns>
    class function IsBlockSizeValid(BlockSize: Integer): Boolean; override;
  public
    /// <summary>
    ///   Adds padding to the specified data, depending on the padding byte
    ///   returned by GetPaddingByte.
    /// </summary>
    /// <param name="Data">
    ///   The data to be padded.
    /// </param>
    /// <param name="BlockSize">
    ///   The block size in byte to align the data with.
    /// </param>
    /// <returns>
    ///   The padded data following the algorithm implemented by the derrived class.
    /// </returns>
    class function AddPadding(const Data : TBytes;
                              BlockSize  : Integer): TBytes; override;

    /// <summary>
    ///   Validates if the specified data contains valid padding as defined by
    ///   GetPaddingByte.
    /// </summary>
    /// <param name="Data">
    ///   The data to be checked.
    /// </param>
    /// <param name="BlockSize">
    ///   The expected block size.
    /// </param>
    /// <returns>
    ///   True if the padding is valid; otherwise, False.
    /// </returns>
    class function HasValidPadding(const Data : TBytes;
                                   BlockSize  : Integer): Boolean; override;

    /// <summary>
    ///   Removes a fixed byte padding from the specified data.
    /// </summary>
    /// <param name="Data">
    ///   The data from which padding will be removed.
    /// </param>
    /// <param name="BlockSize">
    ///   The block size used for padding.
    /// </param>
    /// <exception cref="EDECCipherException">
    ///   Raised if the padding is invalid or missing.
    /// </exception>
    /// <returns>
    ///   The original data without padding.
    /// </returns>
    class function RemovePadding(const Data : TBytes;
                                 BlockSize  : Integer): TBytes; override;
  end;

implementation

uses
  DECUtil, DECRandom;

resourcestring
  sInvalidPadding                 = 'Invalid %0:s padding';
  sUnsupportedBlockSizeForPadding = 'Unsupported block size of %1:d for %0:s padding';

{ TFixedBytePadding }

class function TFixedBytePadding.AddPadding(const Data : TBytes;
                                            BlockSize  : Integer): TBytes;
var
  PadLength : Integer;
  I         : Integer;
begin
  if not IsBlockSizeValid(BlockSize) then
    raise EDECCipherException.CreateResFmt(@sUnsupportedBlockSizeForPadding,
      [ClassName, BlockSize]);

  PadLength := GetPadLength(Length(Data), BlockSize);

  SetLength(Result, Length(Data) + PadLength);
  if Length(Data) > 0 then
    Move(Data[0], Result[0], Length(Data));

  for I := Length(Data) to High(Result) do
    Result[I] := GetPaddingByte(PadLength, I = High(Result));
end;

class function TFixedBytePadding.AddPadding(const Data : string;
                                            BlockSize  : Integer): string;
var
  Buf: TBytes;
begin
  Buf    := AddPadding(StringToBytes(Data), BlockSize);
  Result := BytesToString(Buf);
  ProtectBytes(Buf);
end;

class function TFixedBytePadding.AddPadding(const Data : RawByteString;
                                            BlockSize  : Integer): RawByteString;
var
  Buf: TBytes;
begin
  Buf    := AddPadding(RawStringToBytes(Data), BlockSize);
  Result := BytesToRawString(Buf);
  ProtectBytes(Buf);
end;

class function TFixedBytePadding.GetPadLength(DataSize, BlockSize: Integer): Integer;
begin
  Result := BlockSize - (DataSize mod BlockSize);
end;

class function TFixedBytePadding.HasValidPadding(const Data : TBytes;
                                                 BlockSize  : Integer): Boolean;
var
  PadLength : Integer;
  I         : Integer;
begin
  if Length(Data) = 0 then
    exit(false);

  if not IsBlockSizeValid(BlockSize) then
    exit(false);

  if Length(Data) mod BlockSize <> 0 then
    exit(false);

  PadLength := Data[High(Data)];
  if (PadLength <= 0) or (PadLength > BlockSize) then
    exit(false);

  for I := Length(Data) - PadLength to High(Data) do
    if (Data[I] <> GetPaddingByte(PadLength, I = High(Data))) then
      exit(false);

  Result := true;
end;

class function TFixedBytePadding.RemovePadding(const Data : TBytes;
                                               BlockSize  : Integer): TBytes;
var
  PadLength: Integer;
begin
  if not HasValidPadding(Data, BlockSize) then
    raise EDECCipherException.CreateResFmt(@sInvalidPadding, [ClassName]);

  PadLength := Data[High(Data)];
  SetLength(Result, Length(Data) - PadLength);
  if length(Result) > 0 then
    Move(Data[0], Result[0], Length(Result));
end;

class function TFixedBytePadding.RemovePadding(const Data : RawByteString;
                                               BlockSize  : Integer): RawByteString;
var
  Buf: TBytes;
begin
  Buf    := RemovePadding(RawStringToBytes(Data), BlockSize);
  Result := BytesToRawString(Buf);
  ProtectBytes(Buf);
end;

class function TFixedBytePadding.RemovePadding(const Data : string;
                                               BlockSize  : Integer): string;
var
  Buf: TBytes;
begin
  Buf    := RemovePadding(StringToBytes(Data), BlockSize);
  Result := BytesToString(Buf);
  ProtectBytes(Buf);
end;

{ TPKCS7Padding }

class function TPKCS7Padding.IsBlockSizeValid(BlockSize: Integer): Boolean;
begin
  Result := (BlockSize > 0) and (BlockSize < 256);
end;

class function TPKCS7Padding.GetPaddingByte(PaddingLength     : Integer;
                                            IsLastPaddingByte : Boolean): UInt8;
begin
  Result := Byte(PaddingLength);
end;

{ TPKCS5Padding }

class function TPKCS5Padding.IsBlockSizeValid(BlockSize: Integer): Boolean;
begin
  Result := BlockSize = 8;
end;

{ TANSI_X9_23_Padding }

class function TANSI_X9_23_Padding.IsBlockSizeValid(BlockSize: Integer): Boolean;
begin
  Result := BlockSize > 0;
end;

class function TANSI_X9_23_Padding.GetPaddingByte(PaddingLength     : Integer;
                                                  IsLastPaddingByte : Boolean): UInt8;
begin
  if IsLastPaddingByte then
    Result := Byte(PaddingLength)
  else
    Result := 0;
end;

class function TANSI_X9_23_Padding.HasValidPadding(const Data : TBytes;
                                                   BlockSize  : Integer): Boolean;
var
  PadLength : Integer;
begin
  if Length(Data) = 0 then
    exit(false);

  if not IsBlockSizeValid(BlockSize) then
    exit(false);

  if Length(Data) mod BlockSize <> 0 then
    exit(false);

  PadLength := Data[High(Data)];
  if (PadLength <= 0) or (PadLength > BlockSize) then
    exit(false);

  // Padding bytes cannot be tested as the content is not defined and does
  // not necessarily have to be zero!
  Result := true;
end;

{ TISO10126Padding }

class function TISO10126Padding.GetPaddingByte(PaddingLength     : Integer;
                                               IsLastPaddingByte : Boolean): UInt8;
begin
  if IsLastPaddingByte then
    Result := Byte(PaddingLength)
  else
    Result := RandomBytes(1)[0];
end;

{ TISO7816Padding }

class function TISO7816Padding.IsBlockSizeValid(BlockSize: Integer): Boolean;
begin
  Result := BlockSize > 0;
end;

class function TISO7816Padding.AddPadding(const Data: TBytes;
  BlockSize: Integer): TBytes;
var
  PadLength : Integer;
  I         : Integer;
begin
  if not IsBlockSizeValid(BlockSize) then
    raise EDECCipherException.CreateResFmt(@sUnsupportedBlockSizeForPadding,
      [ClassName, BlockSize]);

  PadLength := GetPadLength(Length(Data), BlockSize);

  SetLength(Result, Length(Data) + PadLength);
  if Length(Data) > 0 then
    Move(Data[0], Result[0], Length(Data));

  I := Length(Data);
  Result[I] := $80;
  for I := succ(Length(Data)) to High(Result) do
    Result[I] := 0;
end;

class function TISO7816Padding.HasValidPadding(const Data : TBytes;
                                               BlockSize  : Integer): Boolean;
var
  I: Integer;
begin
  if Length(Data) = 0 then
    exit(false);

  if not IsBlockSizeValid(BlockSize) then
    exit(false);

  if Length(Data) mod BlockSize <> 0 then
    exit(false);

  I := High(Data);
  while (I > 0) and (Data[I] = 0) do
    dec(I);

  if Data[I] <> $80 then
    exit(false);

  Result := true;
end;

class function TISO7816Padding.RemovePadding(const Data : TBytes;
                                             BlockSize  : Integer): TBytes;
var
  I: Integer;
begin
  if not HasValidPadding(Data, BlockSize) then
    raise EDECCipherException.CreateResFmt(@sInvalidPadding, [ClassName]);

  I := High(Data);
  while (I > 0) and (Data[I] = 0) do
    dec(I);
  if Data[I] <> $80 then
    raise EDECCipherException.CreateResFmt(@sInvalidPadding, [ClassName]);

  SetLength(Result, I);
  if length(Result) > 0 then
    Move(Data[0], Result[0], Length(Result));
end;

end.
