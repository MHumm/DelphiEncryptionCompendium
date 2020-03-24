{*****************************************************************************
  The DEC team (see file NOTICE.txt) licenses this file
  to you under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  A copy of this licence is found in the root directory of
  this project in the file LICENCE.txt or alternatively at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
*****************************************************************************}

{$M+} // DUnitX would add it anyway
unit TestDECCipherFormats;

// Needs to be included before any other statements
{$I defines.inc}

interface

uses
  {$IFNDEF DUnitX}
  TestFramework,
  {$ENDIF}
  {$IFDEF DUnitX}
  DUnitX.TestFramework,DUnitX.DUnitCompatibility,
  {$ENDIF}

  Classes, SysUtils, DECCipherBase, DECCiphers, DECCipherFormats;

type
  /// <summary>
  ///   All known testvectors use the same filler byte and the same cmCTSx mode
  /// </summary>
  TCipherTestData = record
    PlainTextData     : RawByteString;
    EncryptedTextData : RawByteString;

    Key               : RawByteString;
    InitVector        : RawByteString;
    Filler            : Byte;
    Mode              : TCipherMode;
  end;

  // Test methods for class TDECClassList
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTDECCipherFormats = class(TTestCase)
  strict private
    FCipherTwoFish : TDECFormattedCipher;

    /// <summary>
    ///   Array with the test data
    /// </summary>
    FTestData      : array of TCipherTestData;

    /// <summary>
    ///   Ensures that a given key is not longer then the KeySize passed
    /// </summary>
    /// <param name="Key">
    ///   Key to be checked. if it is longer than KeySize it will be cut off.
    /// </param>
    /// <param name="KeySize">
    ///   Maximum size of a key for the given cipher algorithm
    /// </param>
    procedure LimitKeyLength(var Key:RawByteString; KeySize: Integer);
    /// <summary>
    ///   Initialization routine which sets the properties of the crypto object
    ///   as specified in the test data record with the given index.
    /// </summary>
    /// <param name="Index">
    ///   Index of the test data record to be used for this test run initialization
    /// </param>
    procedure Init(Index: Integer);
  public
    procedure SetUp; override;
    procedure TearDown; override;

    /// <summary>
    ///   Callback used by stream oriented Cipher and Hash functions for reporting
    ///   the progress of the operation
    /// </summary>
    procedure Process(const Min, Max, Pos: Int64); stdcall;
  published
    procedure TestEncodeBytes;
    procedure TestDecodeBytes;

    procedure TestEncodeStream;
    procedure TestDecodeStream;

// Currently commented out because it would require a file as external dependency
//    procedure TestEncodeFile(const SourceFileName, DestFileName: string;
//                             const Progress: IDECProgress = nil);
//    procedure TestDecodeFile(const SourceFileName, DestFileName: string;
//                             const Progress: IDECProgress = nil);

    procedure TestEncodeStringToBytes;
    procedure TestEncodeRawByteStringToBytes;

    procedure TestEncodeStringToString;
    procedure TestEncodeRawByteStringToString;

    procedure TestDecodeStringToBytes;
    procedure TestDecodeRawByteStringToBytes;

    procedure TestDecodeStringToString;
    procedure TestDecodeRawByteStringToString;

{$IFNDEF NEXTGEN}
    procedure TestEncodeAnsiStringToBytes;
    procedure TestEncodeAnsiStringToString;

    procedure TestDecodeAnsiStringToBytes;
    procedure TestDecodeAnsiStringToString;

    procedure TestEncodeWideStringToBytes;
    procedure TestEncodeWideStringToString;

    procedure TestDecodeWideStringToBytes;
    procedure TestDecodeWideStringToString;
{$ENDIF}
  end;

implementation

uses
  DECBaseClass, DECFormat;

{ TestTDECCipherFormats }

procedure TestTDECCipherFormats.LimitKeyLength(var Key: RawByteString;
  KeySize: Integer);
begin
  if Length(Key) > KeySize then
    Delete(Key, KeySize + 1, length(Key));
end;

procedure TestTDECCipherFormats.Process(const Min, Max, Pos: Int64);
begin
  // deliberately empty
end;

procedure TestTDECCipherFormats.TestDecodeRawByteStringToBytes;
var
  i      : Integer;
  result : TBytes;
begin
  for i := 0 to High(FTestData) do
  begin
    Init(i);

    result := FCipherTwoFish.EncodeStringToBytes(FTestData[i].PlainTextData);

    CheckEquals(TFormat_HexL.Decode(FTestData[i].EncryptedTextData),
                RawByteString(StringOf(result)),
                'Fehler in TestDecodeRawByteStringToBytes ' + i.ToString);
  end;
end;

procedure TestTDECCipherFormats.TestDecodeStringToBytes;
//var
//  i      : Integer;
//  result : TBytes;
begin
//  for i := 0 to High(FTestData) do
//  begin
//    Init(i);
//
//    result := FCipherTwoFish.EncodeStringToBytes(string(FTestData[i].PlainTextData));
//
//    CheckEquals(TFormat_HexL.Decode(FTestData[i].EncryptedTextData),
//                StringOf(result),
//                'Fehler in TestDecodeStringToBytesBytes ' + i.ToString);
//  end;
end;

procedure TestTDECCipherFormats.Init(Index: Integer);
begin
  LimitKeyLength(FTestData[Index].Key, FCipherTwoFish.Context.KeySize);

  FCipherTwoFish.Mode := FTestData[Index].Mode;
  FCipherTwoFish.Init(BytesOf(FTestData[Index].Key),
                      BytesOf(FTestData[Index].InitVector),
                      FTestData[Index].Filler);
end;

procedure TestTDECCipherFormats.SetUp;
begin
  FCipherTwoFish := TCipher_Twofish.Create;

  SetLength(FTestData, 1);

  FTestData[0].EncryptedTextData  := 'e81674f9bc69442188c949bb52e1e47874171177e99dbbe9880875094f8dfe21';
  FTestData[0].PlainTextData   := TFormat_ESCAPE.Decode('\x30\x44\xED\x6E\x45\xA4' +
                                                    '\x96\xF5\xF6\x35\xA2\xEB' +
                                                    '\x3D\x1A\x5D\xD6\xCB\x1D' +
                                                    '\x09\x82\x2D\xBD\xF5\x60' +
                                                    '\xC2\xB8\x58\xA1\x91\xF9' +
                                                    '\x81\xB1');

  FTestData[0].Key        := 'TCipher_Twofish';
  FTestData[0].InitVector := '';
  FTestData[0].Filler     := $FF;
  FTestData[0].Mode       := cmCTSx;
end;

procedure TestTDECCipherFormats.TearDown;
begin
  FCipherTwoFish.Free;
end;

procedure TestTDECCipherFormats.TestDecodeAnsiStringToBytes;
begin

end;

procedure TestTDECCipherFormats.TestDecodeAnsiStringToString;
begin

end;

procedure TestTDECCipherFormats.TestDecodeBytes;
var
  i      : Integer;
  result : TBytes;
begin
  for i := 0 to High(FTestData) do
  begin
    Init(i);

    result := FCipherTwoFish.DecodeBytes(
                BytesOf(TFormat_HexL.Decode(FTestData[i].EncryptedTextData)));

    CheckEquals(FTestData[i].PlainTextData,
                RawByteString(StringOf(result)),
                'Fehler in TestDecodeBytes ' + i.ToString);
  end;
end;

procedure TestTDECCipherFormats.TestDecodeRawByteStringToString;
begin

end;

procedure TestTDECCipherFormats.TestDecodeStream;
var
  Src, Dest : TMemoryStream;
  SrcBuf    : TBytes;
  i         : Integer;
  result    : TBytes;
begin
  Src := TMemoryStream.Create;
  try

    Dest := TMemoryStream.Create;
    try

      for i := 0 to High(FTestData) do
      begin
        Init(i);

        SrcBuf := BytesOf(TFormat_HexL.Decode(FTestData[i].EncryptedTextData));

        Src.Clear;
        Src.WriteData(SrcBuf, length(SrcBuf));
        Src.Seek(0, TSeekOrigin.soBeginning);

        FCipherTwoFish.DecodeStream(Src, Dest, Src.Size, nil);

        Dest.Seek(0, TSeekOrigin.soBeginning);
        SetLength(result, Dest.Size);
        Dest.Read(result, 0, Dest.Size);

        CheckEquals(FTestData[i].PlainTextData,
                    RawByteString(StringOf(result)),
                    'Fehler in TestDecodeStream ' + i.ToString);
      end;

    finally
      Dest.Free;
    end;

  finally
    Src.Free;
  end;
end;

procedure TestTDECCipherFormats.TestDecodeStringToString;
begin

end;

procedure TestTDECCipherFormats.TestDecodeWideStringToBytes;
begin

end;

procedure TestTDECCipherFormats.TestDecodeWideStringToString;
begin

end;

procedure TestTDECCipherFormats.TestEncodeAnsiStringToBytes;
begin

end;

procedure TestTDECCipherFormats.TestEncodeAnsiStringToString;
begin

end;

procedure TestTDECCipherFormats.TestEncodeBytes;
var
  i      : Integer;
  result : TBytes;
begin
  for i := 0 to High(FTestData) do
  begin
    Init(i);

    result := FCipherTwoFish.EncodeBytes(BytesOf(FTestData[i].PlainTextData));

    CheckEquals(FTestData[i].EncryptedTextData,
                RawByteString(StringOf(TFormat_HexL.Encode(result))),
                'Fehler in TestEncodeBytes ' + i.ToString);
  end;
end;

procedure TestTDECCipherFormats.TestEncodeRawByteStringToBytes;
var
  i      : Integer;
  result : TBytes;
begin
  for i := 0 to High(FTestData) do
  begin
    Init(i);

    result := FCipherTwoFish.EncodeStringToBytes(FTestData[i].PlainTextData);

    CheckEquals(FTestData[i].EncryptedTextData,
                RawByteString(StringOf(TFormat_HexL.Encode(result))),
                'Fehler in TestEncodeRawByteStringToBytes ' + i.ToString);
  end;
end;

procedure TestTDECCipherFormats.TestEncodeRawByteStringToString;
begin

end;

procedure TestTDECCipherFormats.TestEncodeStream;
var
  Src, Dest : TMemoryStream;
  SrcBuf    : TBytes;
  i         : Integer;
  result    : TBytes;
begin
  Src := TMemoryStream.Create;
  try

    Dest := TMemoryStream.Create;
    try

      for i := 0 to High(FTestData) do
      begin
        Init(i);

        SrcBuf := BytesOf(FTestData[i].PlainTextData);

        Src.Clear;
        Src.WriteData(SrcBuf, length(SrcBuf));
        Src.Seek(0, TSeekOrigin.soBeginning);

        FCipherTwoFish.EncodeStream(Src, Dest, Src.Size, nil);

        Dest.Seek(0, TSeekOrigin.soBeginning);
        SetLength(result, Dest.Size);
        Dest.Read(result, 0, Dest.Size);

        CheckEquals(FTestData[i].EncryptedTextData,
                    RawByteString(StringOf(TFormat_HexL.Encode(result))),
                    'Fehler in TestEncodeStream ' + i.ToString);
      end;

    finally
      Dest.Free;
    end;

  finally
    Src.Free;
  end;
end;

procedure TestTDECCipherFormats.TestEncodeStringToBytes;
//var
//  i      : Integer;
//  result : TBytes;
//  s      : string;
begin
{ TODO :
Result of this test will be a different one because input for encryption
is an UTF16 string which will lead to insertion of 0's between each
RawByteString char from the plain text. We need to figure out what the really
expected data is by feeding such a string to the TBytes based test! }

//  for i := 0 to High(FTestData) do
//  begin
//    Init(i);
//
//    s := string(string(FTestData[i].PlainTextData));
//    result := FCipherTwoFish.EncodeStringToBytes(s);
//
//    CheckEquals(string(FTestData[i].EncryptedTextData),
//                StringOf(TFormat_HexL.Encode(result)),
//                'Fehler in TestEncodeStringToBytes ' + i.ToString);
//  end;
end;

procedure TestTDECCipherFormats.TestEncodeStringToString;
begin

end;

procedure TestTDECCipherFormats.TestEncodeWideStringToBytes;
begin

end;

procedure TestTDECCipherFormats.TestEncodeWideStringToString;
begin

end;

initialization
  // Register any test cases with the test runner
  {$IFNDEF DUnitX}
  RegisterTest(TestTDECCipherFormats.Suite);
  {$ELSE}
  TDUnitX.RegisterTestFixture(TestTDECCipherFormats);
  {$ENDIF}
end.
