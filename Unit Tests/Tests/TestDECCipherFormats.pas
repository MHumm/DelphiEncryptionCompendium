{*****************************************************************************
  The DEC team (see file NOTICE.txt) licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License. A copy of this licence is found in the root directory of
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

  Classes, SysUtils, DECCipherBase, DECCiphers;

type
  /// <summary>
  ///   All known testvectors use the same filler byte and the same cmCTSx mode
  /// </summary>
  TCipherTestData = record
    PlainTextData     : RawByteString;
    ExcryptedTextData : RawByteString;

    Key               : RawByteString;
    InitVector        : RawByteString;
    Filler            : Byte;
    Mode              : TCipherMode;
  end;

  // Test methods for class TDECClassList
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTDECCipherFormats = class(TTestCase)
  strict private
    FCipherTwoFish : TCipher_Twofish;

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
  strict protected
    procedure Init(Index: Integer);
  public
    procedure SetUp; override;
    procedure TearDown; override;
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

procedure TestTDECCipherFormats.TestDecodeRawByteStringToBytes;
begin

end;

procedure TestTDECCipherFormats.TestDecodeStringToBytes;
begin

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

  FTestData[0].ExcryptedTextData  := 'e81674f9bc69442188c949bb52e1e47874171177e99dbbe9880875094f8dfe21';
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
                BytesOf(TFormat_HexL.Decode(FTestData[i].ExcryptedTextData)));

    CheckEquals(FTestData[i].PlainTextData,
                RawByteString(StringOf(result)),
                'Fehler in TestDecodeBytes ' + i.ToString);
  end;
end;

procedure TestTDECCipherFormats.TestDecodeRawByteStringToString;
begin

end;

procedure TestTDECCipherFormats.TestDecodeStream;
begin

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

    CheckEquals(FTestData[i].ExcryptedTextData,
                RawByteString(StringOf(TFormat_HexL.Encode(result))),
                'Fehler in TestEncodeBytes ' + i.ToString);
  end;
end;

procedure TestTDECCipherFormats.TestEncodeRawByteStringToBytes;
begin

end;

procedure TestTDECCipherFormats.TestEncodeRawByteStringToString;
begin

end;

procedure TestTDECCipherFormats.TestEncodeStream;
begin

end;

procedure TestTDECCipherFormats.TestEncodeStringToBytes;
begin

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
