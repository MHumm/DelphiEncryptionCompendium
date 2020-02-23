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
    InputData  : RawByteString;
    OutputData : RawByteString;

    Key        : RawByteString;
    InitVector : RawByteString;
    Filler     : Byte;
    Mode       : TCipherMode;
  end;

  TInitProc = procedure(TestData: TCipherTestData) of Object;

  /// <summary>
  ///   base class for all cipher mode tests to make them more independent of
  ///   the actually tested algorithm
  /// </summary>
  TestTDECCipherFormatsBase = class(TTestCase)
  strict protected
    FCipher        : TDECCipher;
    FTestData      : array of TCipherTestData;

    /// <summary>
    ///   Initialize the cipher alrorithm with the initial values for a
    ///   single test
    /// </summary>
    /// <param name="Cipher">
    ///   Instance which shall be initialized with the test data given
    /// </param>
    /// <param name="TestData">
    ///   Data used to initialize the instance
    /// </param>
    procedure Init(Cipher: TDECCipher; TestData: TCipherTestData);
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

    procedure DoTestEncodeBytes(Cipher: TDECCipher; InitProc: TInitProc);
  end;

  // Test methods for class TDECClassList
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTDECCipherFormats = class(TestTDECCipherFormatsBase)
  strict private
    FCipherTwoFish : TCipher_Twofish;

//    procedure Init(TestData: TCipherTestData);
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

procedure TestTDECCipherFormatsBase.DoTestEncodeBytes(Cipher: TDECCipher; InitProc: TInitProc);
var
  i      : Integer;
  result : TBytes;
begin
  for i := 0 to High(FTestData) do
  begin
    InitProc(FTestData[i]);

    result := Cipher.EncodeBytes(BytesOf(FTestData[i].InputData));

    CheckEquals(FTestData[i].OutputData,
                StringOf(TFormat_HexL.Encode(result)),
                'Fehler in TestEncodeBytes ' + i.ToString);
  end;

end;

procedure TestTDECCipherFormatsBase.Init(Cipher: TDECCipher; TestData: TCipherTestData);
begin
  LimitKeyLength(TestData.Key, Cipher.Context.KeySize);

  Cipher.Mode := TestData.Mode;
  Cipher.Init(BytesOf(TestData.Key),
                      BytesOf(TestData.InitVector),
                      TestData.Filler);
end;

procedure TestTDECCipherFormatsBase.LimitKeyLength(var Key: RawByteString;
  KeySize: Integer);
begin
  if Length(Key) > KeySize then
    Delete(Key, KeySize + 1, length(Key));
end;

{ TestTDECCipherFormats }

procedure TestTDECCipherFormats.TestDecodeRawByteStringToBytes;
begin

end;

procedure TestTDECCipherFormats.TestDecodeStringToBytes;
begin

end;

//procedure TestTDECCipherFormats.Init(TestData: TCipherTestData);
//begin
//  LimitKeyLength(TestData.Key, FCipherTwoFish.Context.KeySize);
//
//  FCipherTwoFish.Mode := TestData.Mode;
//  FCipherTwoFish.Init(BytesOf(TestData.Key),
//                      BytesOf(TestData.InitVector),
//                      TestData.Filler);
//end;

procedure TestTDECCipherFormats.SetUp;
begin
  FCipherTwoFish := TCipher_Twofish.Create;

  SetLength(FTestData, 1);

  FTestData[0].OutputData  := 'e81674f9bc69442188c949bb52e1e47874171177e99dbbe9880875094f8dfe21';
  FTestData[0].InputData   := TFormat_ESCAPE.Decode('\x30\x44\xED\x6E\x45\xA4' +
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
begin

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
//  DoTestEncodeBytes(FCipherTwoFish, Init);

  for i := 0 to High(FTestData) do
  begin
    Init(FCipherTwoFish, FTestData[i]);

    result := FCipherTwoFish.EncodeBytes(BytesOf(FTestData[i].InputData));

    CheckEquals(FTestData[i].OutputData,
                StringOf(TFormat_HexL.Encode(result)),
                'Fehler in TestEncodeBytes ' + i.ToString);
  end;

{ TODO :
Change to use DoTestEncodeBytes but that needs to be
passed an init method as calling that one on the TDECCipher
level leads to an assertion later on }
//begin
//  DoTestEncodeBytes(FCipherTwoFish);
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
