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
unit TestDECCipherModesGCM;

interface

// Needs to be included before any other statements
{$INCLUDE TestDefines.inc}

uses
  {$IFDEF DUnitX}
  DUnitX.TestFramework,DUnitX.DUnitCompatibility,
  {$ELSE}
  TestFramework,
  {$ENDIF}
  System.SysUtils, Generics.Collections,
  DECCipherBase, DECCipherModes, DECCipherFormats, DECCiphers;

type
  /// <summary>
  ///   Test data for one single GCM test, all in HexL
  /// </summary>
  TGCMSingleTestData = record
    /// <summary>
    ///   Encryption/decryption key
    /// </summary>
    CryptKey   : RawByteString;
    /// <summary>
    ///   Initialization vecotr
    /// </summary>
    InitVector : RawByteString;
    /// <summary>
    ///   Plain Text: text to be encrypted, given in HexL
    /// </summary>
    PT         : RawByteString;
    /// <summary>
    ///   Additional Authehticated Data: the data which shall be authenticated
    ///   but not encrypted.
    /// </summary>
    AAD        : RawByteString;
    /// <summary>
    ///   Cipher Text: encrypted text, given in HexL
    /// </summary>
    CT         : RawByteString;
    /// <summary>
    ///   Calculated authenticated "tag" value
    /// </summary>
    TagResult  : RawByteString;

    /// <summary>
    ///   Sets all fields and array entries to default values
    /// </summary>
    procedure Clear;
  end;

  /// <summary>
  ///   Test data for one single GCM test
  /// </summary>
  TGCMTestSetEntry = record
    /// <summary>
    ///   Length of the encryption/decryption key in bit, determines the
    ///   algorithm used in case of AES (AES128, AES192, AES256)
    /// </summary>
    Keylen : UInt16;
    /// <summary>
    ///   Length of the initialization vector in bit
    /// </summary>
    IVlen  : UInt16;
    /// <summary>
    ///   Length of the ? in bit
    /// </summary>
    PTlen  : UInt16;
    /// <summary>
    ///   Length of the ? in bit
    /// </summary>
    AADlen : UInt16;
    /// <summary>
    ///   Length of the "tag" resulting from the authentication part in bit
    /// </summary>
    Taglen : UInt16;

    /// <summary>
    ///   The test data files provided contain 14 tests for the meta data
    ///   specified above. This array holds the test data.
    /// </summary>
    TestData : array[0..14] of TGCMSingleTestData;

    /// <summary>
    ///   Sets all fields and array entries to default values
    /// </summary>
    procedure Clear;
  end;

  /// <summary>
  ///   List of loaded GCM test vectors
  /// </summary>
  TGCMTestDataList = TList<TGCMTestSetEntry>;

  /// <summary>
  ///   Class for loading a GCM style test data file
  /// </summary>
  TGCMTestDataLoader = class(TObject)
  strict private
    /// <summary>
    ///   Extracts the number from a definition string like [Keylen = 128]
    /// </summary>
    /// <param name="Line">
    ///   String to extract the number from
    /// </param>
    /// <returns>
    ///   Extracted number
    /// </returns>
    function ExtractNumber(const Line: string):UInt16;
    /// <summary>
    ///   Extracts the hex string part from a data string like Key = bad604967..
    /// </summary>
    /// <param name="Line">
    ///   String to extract the hex string from
    /// </param>
    /// <returns>
    ///   Extracted hex string
    /// </returns>
    function ExtractHexString(const Line: string): RawByteString;

    /// <summary>
    ///   Tries to interpret a given line as part of a block's meta data and if
    ///   it is the corresponding field of that meta data is filled.
    /// </summary>
    /// <param name="Line">
    ///   Line read from the file which shall be interpreted
    /// </param>
    /// <param name="TestData">
    ///   List to which the passed entry is added to if the line is the start
    ///   of a new block.
    /// </param>
    /// <param name="Entry">
    ///   Data of the currently processed block
    /// </param>
    /// <param name="Index">
    ///   Index of the data entry within a block. It will just be set to 0 if
    ///   the start of a new block has been detected in the method.
    /// </param>
    procedure ReadBlockMetaDataLine(const Line : string;
                                    TestData   : TGCMTestDataList;
                                    var Entry  : TGCMTestSetEntry;
                                    var Index  : Byte);

    /// <summary>
    ///   Tries to interpret a given line as part of a set of test data and
    ///   it is the corresponding field of that test data is set
    /// </summary>
    /// <param name="Line">
    ///   Line read from the file which shall be interpreted
    /// </param>
    /// <param name="Entry">
    ///   Data of the currently processed block
    /// </param>
    /// <param name="Index">
    ///   Index of the data entry within a block. It will just be incremented
    ///   when the last index has been read. If the index is bigger than the
    ///   fixed space reserved (based on the original data file format), the
    ///   line will be ignored.
    /// </param>
    procedure ReadDataLine(const Line : string;
                           var Entry  : TGCMTestSetEntry;
                           var Index  : Byte);
  public
    /// <summary>
    ///   Loads the data from the file specified
    /// </summary>
    /// <param name="FileName">
    ///   Path and name of the file to be loaded
    /// </param>
    /// <param name="TestData">
    ///   List in which to store the test data loaded. The list must exist but
    ///   will not be cleared, so newly loaded data will be appended.
    /// </param>
    procedure LoadFile(const FileName: string; TestData : TGCMTestDataList);
  end;

  // Testmethods for class TDECCipher
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTDECGCM = class(TTestCase)
  strict private
    FTestDataLoader : TGCMTestDataLoader;
    FTestDataList   : TGCMTestDataList;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncode;
//    procedure TestDecode;
  end;


implementation

uses
  System.Classes,
  DECFormat;

{ TGCMTestSetEntry }

procedure TGCMTestSetEntry.Clear;
var
  i : Integer;
begin
  Keylen := 0;
  IVlen  := 0;
  PTlen  := 0;
  AADlen := 0;
  Taglen := 0;

  for i := Low(TestData) to High(TestData) do
    TestData[i].Clear;
end;

{ TGCMSingleTestData }

procedure TGCMSingleTestData.Clear;
begin
  CryptKey   := '';
  InitVector := '';
  PT         := '';
  AAD        := '';
  CT         := '';
  TagResult  := '';
end;

{ TGCMTestDataLoader }

function TGCMTestDataLoader.ExtractHexString(const Line: string): RawByteString;
var
  s : string;
begin
  s := Line;
  Delete(s, 1, Pos('=', Line));
  Result := RawByteString(Trim(s));
end;

function TGCMTestDataLoader.ExtractNumber(const Line: string): UInt16;
var
  s : string;
  i : Integer;
begin
  s := Line;
  Delete(s, 1, Pos('=', s));

  i := 1;
  while i <= Length(s) do
  begin
    if CharInSet(s[i], ['0'..'9']) then
      Inc(i)
    else
      delete(s, i, 1);
  end;

  Result := StrToInt(s);
end;

procedure TGCMTestDataLoader.LoadFile(const FileName: string; TestData : TGCMTestDataList);
var
  Reader : TStreamReader;
  Line   : string;
  Entry  : TGCMTestSetEntry;
  Index  : Byte;
begin
  Assert(FileName <> '', 'No file to load specified');
  Assert(Assigned(TestData), 'Unassigned test data list given');

  Entry.Clear;
  Index := 0;
  Reader := TStreamReader.Create(FileName, TEncoding.UTF8);

  try
    while not Reader.EndOfStream do
    begin
      Line := Reader.ReadLine;

      // Skip empty lines and comments
      if (Line = '') or (Pos('#', Line) > 0) then
        Continue;

      // We assume this format:
      // [Keylen = 128]
      // [IVlen = 96]
      // [PTlen = 128]
      // [AADlen = 128]
      // [Taglen = 112]
      //
      // Count = 0
      // Key = bad6049678bf75c9087b3e3ae7e72c13
      // IV = a0a017b83a67d8f1b883e561
      // PT = a1be93012f05a1958440f74a5311f4a1
      // AAD = f7c27b51d5367161dc2ff1e9e3edc6f2
      // CT = 36f032f7e3dc3275ca22aedcdc68436b
      // Tag = 99a2227f8bb69d45ea5d8842cd08

      Line := LowerCase(Line).Replace(' ', '', [rfReplaceAll]);
      ReadBlockMetaDataLine(Line, TestData, Entry, Index);
      ReadDataLine(Line, Entry, Index);
    end;

    // Remove first test data entry, as this is empty
    TestData.Delete(0);

  finally
    Reader.Free;
  end;
end;

procedure TGCMTestDataLoader.ReadBlockMetaDataLine(const Line : string;
                                               TestData   : TGCMTestDataList;
                                               var Entry  : TGCMTestSetEntry;
                                               var Index  : Byte);
begin
  // Loading of the block metadata
  // Does a new block start?
  if (Pos('[keylen', Line) > 0) then
  begin
    TestData.Add(Entry);
    Entry.Clear;
    Index := 0;

    Entry.Keylen := ExtractNumber(Line);
  end
  else if (Pos('[ivlen', Line) > 0) then
    Entry.IVlen := ExtractNumber(Line)
  else if (Pos('[ptlen', Line) > 0) then
    Entry.PTlen := ExtractNumber(Line)
  else if (Pos('[aadlen', Line) > 0) then
    Entry.AADlen := ExtractNumber(Line)
  else if (Pos('[taglen', Line) > 0) then
    Entry.Taglen := ExtractNumber(Line);
end;

procedure TGCMTestDataLoader.ReadDataLine(const Line : string;
                                          var Entry  : TGCMTestSetEntry;
                                          var Index  : Byte);
begin
  // Data entries do not contain [
  if (Index <= Length(Entry.TestData)) and (Pos('[', Line) = 0) then
  begin
    // Count = 0
    // Key = bad6049678bf75c9087b3e3ae7e72c13
    // IV = a0a017b83a67d8f1b883e561
    // PT = a1be93012f05a1958440f74a5311f4a1
    // AAD = f7c27b51d5367161dc2ff1e9e3edc6f2
    // CT = 36f032f7e3dc3275ca22aedcdc68436b
    // Tag = 99a2227f8bb69d45ea5d8842cd08
    if (Pos('count=', Line) > 0) then
      Index := ExtractNumber(Line)
    else if (Pos('key=', Line) > 0) then
      Entry.TestData[Index].CryptKey := ExtractHexString(Line)
    else if (Pos('iv=', Line) > 0) then
      Entry.TestData[Index].InitVector := ExtractHexString(Line)
    else if (Pos('pt=', Line) > 0) then
      Entry.TestData[Index].PT := ExtractHexString(Line)
    else if (Pos('aad=', Line) > 0) then
      Entry.TestData[Index].AAD := ExtractHexString(Line)
    else if (Pos('ct=', Line) > 0) then
      Entry.TestData[Index].CT := ExtractHexString(Line)
    else if (Pos('tag=', Line) > 0) then
      Entry.TestData[Index].TagResult := ExtractHexString(Line);
  end;
end;

{ TestTDECGCM }

procedure TestTDECGCM.SetUp;
begin
  inherited;

  FTestDataLoader := TGCMTestDataLoader.Create;
  FTestDataList   := TGCMTestDataList.Create;
end;

procedure TestTDECGCM.TearDown;
begin
  inherited;

  FTestDataLoader.Free;
  FTestDataList.Free;
end;

procedure TestTDECGCM.TestEncode;
var
  Cipher      : TCipher_AES;
  TestDataSet : TGCMTestSetEntry;
  i           : Integer;
  EncryptData : TBytes;
  Key         : RawByteString;
  KeyBytes    : TBytes;
begin
  FTestDataLoader.LoadFile('..\..\Unit Tests\Data\gcmEncryptExtIV128.rsp', FTestDataList);

//  FTestDataLoader.LoadFile('..\..\Unit Tests\Data\gcmEncodeTest.rsp', FTestDataList);

//  TestDataSet.Keylen := 16*8;
//  TestDataSet.IVlen  := 12*8;
//  TestDataSet.PTlen  := 16*8;;
//  TestDataSet.AADlen := 16*8;
//  TestDataSet.Taglen := 14*8;
//  TestDataSet.TestData[0].CryptKey   := 'bad6049678bf75c9087b3e3ae7e72c13';
//  TestDataSet.TestData[0].InitVector := 'a0a017b83a67d8f1b883e561';
//  TestDataSet.TestData[0].PT         := 'a1be93012f05a1958440f74a5311f4a1';
//  TestDataSet.TestData[0].AAD        := 'f7c27b51d5367161dc2ff1e9e3edc6f2';
//  TestDataSet.TestData[0].CT         := '36f032f7e3dc3275ca22aedcdc68436b';
//  TestDataSet.TestData[0].TagResult  := '99a2227f8bb69d45ea5d8842cd08';
//
//  FTestDataList.Clear;
//  FTestDataList.Add(TestDataSet);
//
//  TestDataSet.Keylen := 16*8;
//  TestDataSet.IVlen  := 12*8;
//  TestDataSet.PTlen  := 0;
//  TestDataSet.AADlen := 384;
//  TestDataSet.Taglen := 128;
//  TestDataSet.TestData[0].CryptKey   := '99e3e8793e686e571d8285c564f75e2b';
//  TestDataSet.TestData[0].InitVector := 'c2dd0ab868da6aa8ad9c0d23';
//  TestDataSet.TestData[0].PT         := '';
//  TestDataSet.TestData[0].AAD        := 'b668e42d4e444ca8b23cfdd95a9fedd5178aa521144890b093733cf5cf22526c5917ee476541809ac6867a8c399309fc';
//  TestDataSet.TestData[0].CT         := '';
//  TestDataSet.TestData[0].TagResult  := '3f4fba100eaf1f34b0baadaae9995d85';
//
//  FTestDataList.Clear;
//  FTestDataList.Add(TestDataSet);

  Cipher := TCipher_AES.Create;
  try
    Cipher.Mode := TCipherMode.cmGCM;

    for TestDataSet in FTestDataList do
    begin
      for i := Low(TestDataSet.TestData) to High(TestDataSet.TestData) do
      begin
        KeyBytes := System.SysUtils.BytesOf(TFormat_HexL.Decode(TestDataSet.TestData[i].CryptKey));
        SetLength(Key,length(KeyBytes));

        if (Length(Key) > 0) then
          Move(KeyBytes[0], Key[1], length(Key));

        Cipher.Init(System.SysUtils.BytesOf(TFormat_HexL.Decode(TestDataSet.TestData[i].CryptKey)),
                    System.SysUtils.BytesOf(TFormat_HexL.Decode(TestDataSet.TestData[i].InitVector)),
                    $FF);

        Cipher.AuthenticationResultBitLength := TestDataSet.Taglen;
        Cipher.AuthenticatedData             := TFormat_HexL.Decode(
                                                  BytesOf(
                                                    TestDataSet.TestData[i].AAD));

        EncryptData := Cipher.EncodeBytes(
                         TFormat_HexL.Decode(
                           BytesOf(TestDataSet.TestData[i].PT)));

        CheckEquals(string(TestDataSet.TestData[i].CT),
                    StringOf(TFormat_HexL.Encode(EncryptData)),
                    'Cipher text wrong for Key ' +
                    string(TestDataSet.TestData[i].CryptKey) + ' IV ' +
                    string(TestDataSet.TestData[i].InitVector) + ' PT ' +
                    string(TestDataSet.TestData[i].PT) + ' AAD ' +
                    string(TestDataSet.TestData[i].AAD) + ' Exp.: ' +
                    string(TestDataSet.TestData[i].CT) + ' Act.: ' +
                    StringOf(TFormat_HexL.Encode(EncryptData)));

        // Additional Authentication Data prüfen
        CheckEquals(string(TestDataSet.TestData[i].TagResult),
                           StringOf(TFormat_HexL.Encode(Cipher.AuthenticatedData)),
                    'Authentication tag wrong for Key ' +
                    string(TestDataSet.TestData[i].CryptKey) + ' IV ' +
                    string(TestDataSet.TestData[i].InitVector) + ' PT ' +
                    string(TestDataSet.TestData[i].PT) + ' AAD ' +
                    string(TestDataSet.TestData[i].AAD) + ' Exp.: ' +
                    string(TestDataSet.TestData[i].TagResult) + ' Act.: ' +
                    StringOf(TFormat_HexL.Encode(Cipher.AuthenticatedData)));
//exit;
      end;
    end;
  finally
    Cipher.Free;
  end;
end;

initialization
  // Register all test cases to be run
  {$IFDEF DUnitX}
  TDUnitX.RegisterTestFixture(TestTDECGCM);
  {$ELSE}
  RegisterTest(TestTDECGCM.Suite);
  {$ENDIF}
end.
