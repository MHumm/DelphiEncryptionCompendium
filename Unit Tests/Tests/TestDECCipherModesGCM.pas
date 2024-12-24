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
  System.SysUtils, Generics.Collections, System.Math,
  DECBaseClass,
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
    ///   Additional Authenticated Data: the data which shall be authenticated
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
    ///   Used additional authenticated data for testing authentication failures.
    ///   Only filled when present in test data file.
    /// </summary>
    ModifiedAAD: RawByteString;
    /// <summary>
    ///   Used ciphertext data for testing authentication failures.
    ///   Only filled when present in test data file.
    /// </summary>
    ModifiedCT: RawByteString;

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
    ///   it is, the corresponding field of that meta data is filled.
    /// </summary>
    /// <param name="Line">
    ///   Line read from the file which shall be interpreted
    /// </param>
    /// <param name="Entry">
    ///   Data of the currently processed block
    /// </param>
    /// <param name="Index">
    ///   Index of the data entry within a block. It will just be set to 0 if
    ///   the start of a new block has been detected in the method.
    /// </param>
    procedure ReadBlockMetaDataLine(const Line : string;
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
    /// <param name="TestData">
    ///   List of all test data sets
    /// </param>
    /// <param name="Index">
    ///   Index of the data entry within a block. It will just be incremented
    ///   when the last index has been read. If the index is bigger than the
    ///   fixed space reserved (based on the original data file format), the
    ///   line will be ignored.
    /// </param>
    procedure ReadDataLine(const Line : string;
                           var Entry  : TGCMTestSetEntry;
                           TestData   : TGCMTestDataList;
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
    /// <param name="AllowIncompleteEntries">
    ///   Use when loading data set with incomplete entries.
    /// </param>
    procedure LoadFile(const FileName: string; TestData : TGCMTestDataList;
        AllowIncompleteEntries: Boolean = False);
  end;

  // Testmethods for class TDECCipher
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTDECGCM = class(TTestCase)
  strict private
    FTestDataLoader : TGCMTestDataLoader;
    FTestDataList   : TGCMTestDataList;
    FCipherAES      : TCipher_AES;

    // Needed for passing data to and from DoTestDecodeFailure
    FDecryptedData  : TBytes;
    FCipherText     : TBytes;
  private
    function IsEqual(const a, b: TBytes): Boolean;
    procedure DoTestDecodeFailure;
    procedure DoTestEncodeStream_LoadAndTestCAVSData(const aMaxChunkSize: Int64);
    procedure DoTestEncodeStream_TestSingleSet(const aSetIndex, aDataIndex:
        Integer; const aMaxChunkSize: Int64 = -1);
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncode;
    procedure TestDecode;
    procedure TestDecodeStream;
    procedure TestDecodeAuthenticationFailure;
    procedure TestEncodeStream;
    procedure TestEncodeLargeStream;
    procedure TestEncodeStreamChunked;
    procedure TestSetGetDataToAuthenticate;
    procedure TestSetGetAuthenticationBitLength;
    procedure TestGetStandardAuthenticationTagBitLengths;
    procedure TestGetExpectedAuthenticationResult;
    procedure TestSetExpectedAuthenticationResult;
  end;


implementation

uses
  System.Classes,
  DECTypes,
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
  CryptKey    := '';
  InitVector  := '';
  PT          := '';
  AAD         := '';
  CT          := '';
  TagResult   := '';
  ModifiedAAD := '';
  ModifiedCT  := '';
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

procedure TGCMTestDataLoader.LoadFile(const FileName: string;
  TestData : TGCMTestDataList; AllowIncompleteEntries: Boolean = False);
var
  Reader : TStreamReader;
  Line   : string;
  Entry  : TGCMTestSetEntry;
  Index  : Byte;
begin
  System.Assert(FileName <> '', 'No file to load specified');
  System.Assert(Assigned(TestData), 'Unassigned test data list given');

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
      if (Line <> '') then
      begin
        ReadBlockMetaDataLine(Line, Entry, Index);
        ReadDataLine(Line, Entry, TestData, Index);
      end;
    end;
  finally
    Reader.Free;
  end;

  if AllowIncompleteEntries and (Index < Length(Entry.TestData) - 1) then
    TestData.Add(Entry);
end;

procedure TGCMTestDataLoader.ReadBlockMetaDataLine(const Line : string;
                                                   var Entry  : TGCMTestSetEntry;
                                                   var Index  : Byte);
begin
  // Loading of the block metadata
  // Does a new block start?
  if (Pos('[keylen', Line) > 0) then
  begin
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
                                          TestData   : TGCMTestDataList;
                                          var Index  : Byte);
begin
  // Data entries do not contain [
  if (Index <= Length(Entry.TestData)) and (Pos('[', Line) = 0) then
  begin
    // Format example:
    // Count = 0
    // Key = bad6049678bf75c9087b3e3ae7e72c13
    // IV = a0a017b83a67d8f1b883e561
    // PT = a1be93012f05a1958440f74a5311f4a1
    // AAD = f7c27b51d5367161dc2ff1e9e3edc6f2
    // CT = 36f032f7e3dc3275ca22aedcdc68436b
    // Tag = 99a2227f8bb69d45ea5d8842cd08
    // And files with data for testing exceptions are raised do additionally
    // contain: ModAAD = f7c27b51d5367161dc2ff1e9e3edc6f3
    //          ModCt = 36f032f7e3dc3275ca22aedcdc68436c
    if (Pos('count=', Line) = 1) then
      Index := ExtractNumber(Line)
    else if (Pos('key=', Line) = 1) then
      Entry.TestData[Index].CryptKey := ExtractHexString(Line)
    else if (Pos('iv=', Line) = 1) then
      Entry.TestData[Index].InitVector := ExtractHexString(Line)
    else if (Pos('pt=', Line) = 1) then
      Entry.TestData[Index].PT := ExtractHexString(Line)
    else if (Pos('aad=', Line) = 1) then
      Entry.TestData[Index].AAD := ExtractHexString(Line)
    else if (Pos('ct=', Line) = 1) then
      Entry.TestData[Index].CT := ExtractHexString(Line)
    else if (Pos('modaad=', Line) = 1) then
      Entry.TestData[Index].ModifiedAAD := ExtractHexString(Line)
    else if (Pos('modct=', Line) = 1) then
      Entry.TestData[Index].ModifiedCT := ExtractHexString(Line)
    else if (Pos('tag=', Line) = 1) then
    begin
      Entry.TestData[Index].TagResult := ExtractHexString(Line);

      if (Index = Length(Entry.TestData) - 1) then
        TestData.Add(Entry);
    end;
  end;
end;

{ TestTDECGCM }

procedure TestTDECGCM.SetUp;
begin
  inherited;

  FTestDataLoader := TGCMTestDataLoader.Create;
  FTestDataList   := TGCMTestDataList.Create;

  FCipherAES      := TCipher_AES.Create;
  FCipherAES.Mode := TCipherMode.cmGCM;
end;

procedure TestTDECGCM.TearDown;
begin
  inherited;

  FCipherAES.Free;
  FTestDataLoader.Free;
  FTestDataList.Free;
end;

procedure TestTDECGCM.TestDecode;
var
  TestDataSet : TGCMTestSetEntry;
  i           : Integer;
  DecryptData : TBytes;
begin
  FTestDataLoader.LoadFile('..\..\Unit Tests\Data\gcmEncryptExtIV128.rsp', FTestDataList);
  FTestDataLoader.LoadFile('..\..\Unit Tests\Data\gcmEncryptExtIV192.rsp', FTestDataList);
  FTestDataLoader.LoadFile('..\..\Unit Tests\Data\gcmEncryptExtIV256.rsp', FTestDataList);

  for TestDataSet in FTestDataList do
  begin
    for i := Low(TestDataSet.TestData) to High(TestDataSet.TestData) do
    begin
      try
        FCipherAES.Init(BytesOf(TFormat_HexL.Decode(TestDataSet.TestData[i].CryptKey)),
                        BytesOf(TFormat_HexL.Decode(TestDataSet.TestData[i].InitVector)),
                        $FF);

        FCipherAES.AuthenticationResultBitLength := TestDataSet.Taglen;
        FCipherAES.DataToAuthenticate            := TFormat_HexL.Decode(
                                                      BytesOf(
                                                        TestDataSet.TestData[i].AAD));

        FCipherAES.ExpectedAuthenticationResult :=
          TFormat_HexL.Decode(BytesOf(TestDataSet.TestData[i].TagResult));

        DecryptData := FCipherAES.DecodeBytes(
                         TFormat_HexL.Decode(
                           BytesOf(TestDataSet.TestData[i].CT)));
        FCipherAES.Done;
      except
        on E: Exception do
          Status('CryptKey ' + string(TestDataSet.TestData[i].CryptKey) +
            ' ' + E.ClassName + ': ' + E.Message);
      end;

      CheckEquals(string(TestDataSet.TestData[i].PT),
                  StringOf(TFormat_HexL.Encode(DecryptData)),
                  'Plaintext wrong for key ' +
                  string(TestDataSet.TestData[i].CryptKey) + ' IV ' +
                  string(TestDataSet.TestData[i].InitVector) + ' PT ' +
                  string(TestDataSet.TestData[i].PT) + ' AAD ' +
                  string(TestDataSet.TestData[i].AAD) + ' Exp.: ' +
                  string(TestDataSet.TestData[i].CT) + ' Act.: ' +
                  StringOf(TFormat_HexL.Encode(DecryptData)));

      // Additional Authentication Data prüfen
      CheckEquals(string(TestDataSet.TestData[i].TagResult),
                         StringOf(TFormat_HexL.Encode(FCipherAES.CalculatedAuthenticationResult)),
                  'Authentication tag wrong for key ' +
                  string(TestDataSet.TestData[i].CryptKey) + ' IV ' +
                  string(TestDataSet.TestData[i].InitVector) + ' PT ' +
                  string(TestDataSet.TestData[i].PT) + ' AAD ' +
                  string(TestDataSet.TestData[i].AAD) + ' Exp.: ' +
                  string(TestDataSet.TestData[i].TagResult) + ' Act.: ' +
                  StringOf(TFormat_HexL.Encode(FCipherAES.DataToAuthenticate)));

    end;
  end;
end;

procedure TestTDECGCM.TestDecodeAuthenticationFailure;
var
  TestDataSet : TGCMTestSetEntry;
  i           : Integer;
begin
  FTestDataLoader.LoadFile('..\..\Unit Tests\Data\GCM128AuthenticationFailures.rsp', FTestDataList);
  FTestDataLoader.LoadFile('..\..\Unit Tests\Data\GCM192AuthenticationFailures.rsp', FTestDataList);
  FTestDataLoader.LoadFile('..\..\Unit Tests\Data\GCM256AuthenticationFailures.rsp', FTestDataList);

  for TestDataSet in FTestDataList do
  begin
    for i := Low(TestDataSet.TestData) to High(TestDataSet.TestData) do
    begin
      FCipherAES.Init(BytesOf(TFormat_HexL.Decode(TestDataSet.TestData[i].CryptKey)),
                      BytesOf(TFormat_HexL.Decode(TestDataSet.TestData[i].InitVector)),
                      $FF);

      FCipherAES.AuthenticationResultBitLength := TestDataSet.Taglen;
      FCipherAES.DataToAuthenticate            := TFormat_HexL.Decode(
                                                    BytesOf(
                                                      TestDataSet.TestData[i].ModifiedAAD));

      FCipherAES.ExpectedAuthenticationResult :=
        TFormat_HexL.Decode(BytesOf(TestDataSet.TestData[i].TagResult));

      FCipherText := TFormat_HexL.Decode(
                       BytesOf(TestDataSet.TestData[i].ModifiedCT));

      CheckException(DoTestDecodeFailure, EDECCipherAuthenticationException,
                     'i: ' + i.ToString + ' Key: ' + string(TestDataSet.TestData[0].CryptKey));

      CheckEquals(string(TestDataSet.TestData[i].PT),
                  StringOf(TFormat_HexL.Encode(FDecryptedData)),
                  'Plaintext wrong for key ' +
                  string(TestDataSet.TestData[i].CryptKey) + ' IV ' +
                  string(TestDataSet.TestData[i].InitVector) + ' PT ' +
                  string(TestDataSet.TestData[i].PT) + ' AAD ' +
                  string(TestDataSet.TestData[i].AAD) + ' CT: ' +
                  string(TestDataSet.TestData[i].CT) + ' Act.: ' +
                  StringOf(TFormat_HexL.Encode(FDecryptedData)));
    end;
  end;
end;

procedure TestTDECGCM.TestEncode;
var
  TestDataSet : TGCMTestSetEntry;
  i           : Integer;
  EncryptData : TBytes;
  EncrDataStr : string;
begin
  FTestDataLoader.LoadFile('..\..\Unit Tests\Data\gcmEncryptExtIV128.rsp', FTestDataList);
  FTestDataLoader.LoadFile('..\..\Unit Tests\Data\gcmEncryptExtIV192.rsp', FTestDataList);
  FTestDataLoader.LoadFile('..\..\Unit Tests\Data\gcmEncryptExtIV256.rsp', FTestDataList);

  for TestDataSet in FTestDataList do
  begin
    for i := Low(TestDataSet.TestData) to High(TestDataSet.TestData) do
    begin
      FCipherAES.Init(BytesOf(TFormat_HexL.Decode(TestDataSet.TestData[i].CryptKey)),
                      BytesOf(TFormat_HexL.Decode(TestDataSet.TestData[i].InitVector)),
                      $FF);

      FCipherAES.AuthenticationResultBitLength := TestDataSet.Taglen;
      FCipherAES.DataToAuthenticate            := TFormat_HexL.Decode(
                                                    BytesOf(
                                                      TestDataSet.TestData[i].AAD));

      EncryptData := FCipherAES.EncodeBytes(
                       TFormat_HexL.Decode(
                         BytesOf(TestDataSet.TestData[i].PT)));
      FCipherAES.Done;

      EncrDataStr := StringOf(TFormat_HexL.Encode(EncryptData));
      CheckEquals(string(TestDataSet.TestData[i].CT),
                  EncrDataStr,
                  'Cipher text wrong for Key ' +
                  string(TestDataSet.TestData[i].CryptKey) + ' IV ' +
                  string(TestDataSet.TestData[i].InitVector) + ' PT ' +
                  string(TestDataSet.TestData[i].PT) + ' AAD ' +
                  string(TestDataSet.TestData[i].AAD) + ' Exp.: ' +
                  string(TestDataSet.TestData[i].CT) + ' Act.: ' +
                  EncrDataStr);

      // Additional Authentication Data prüfen
      CheckEquals(string(TestDataSet.TestData[i].TagResult),
                         StringOf(TFormat_HexL.Encode(FCipherAES.CalculatedAuthenticationResult)),
                  'Authentication tag wrong for Key ' +
                  string(TestDataSet.TestData[i].CryptKey) + ' IV ' +
                  string(TestDataSet.TestData[i].InitVector) + ' PT ' +
                  string(TestDataSet.TestData[i].PT) + ' AAD ' +
                  string(TestDataSet.TestData[i].AAD) + ' Exp.: ' +
                  string(TestDataSet.TestData[i].TagResult) + ' Act.: ' +
                  StringOf(TFormat_HexL.Encode(FCipherAES.DataToAuthenticate)));
    end;
  end;
end;

procedure TestTDECGCM.TestGetExpectedAuthenticationResult;
var
  Exp, Act: TBytes;
begin
  SetLength(Exp, 4);
  Exp := [1, 2, 3, 4];
  FCipherAES.ExpectedAuthenticationResult := Exp;
  Act := FCipherAES.ExpectedAuthenticationResult;

  CheckEquals(true, IsEqual(Exp, Act), 'Data length = 4');

  SetLength(Exp, 0);
  FCipherAES.ExpectedAuthenticationResult := Exp;
  Act := FCipherAES.ExpectedAuthenticationResult;

  CheckEquals(true, IsEqual(Exp, Act), 'Data length = 0');
end;

procedure TestTDECGCM.DoTestDecodeFailure;
begin
  FDecryptedData := FCipherAES.DecodeBytes(FCipherText);
  FCipherAES.Done;
end;

function TestTDECGCM.IsEqual(const a, b : TBytes):Boolean;
begin
  if (length(a) <> length(b)) then
    Result := false
  else
    if (Length(a) > 0) then
      Result := CompareMem(@a[0], @b[0], length(a))
    else
      Result := true;
end;

procedure TestTDECGCM.TestDecodeStream;
var
  ctbStream: TBytesStream;
  ctBytes: TBytes;
  TestDataSet : TGCMTestSetEntry;
  i           : Integer;
  DecryptData : TBytes;
  ptbStream: TBytesStream;
begin
  FTestDataLoader.LoadFile('..\..\Unit Tests\Data\gcmEncryptExtIV128.rsp', FTestDataList);
  FTestDataLoader.LoadFile('..\..\Unit Tests\Data\gcmEncryptExtIV192.rsp', FTestDataList);
  FTestDataLoader.LoadFile('..\..\Unit Tests\Data\gcmEncryptExtIV256.rsp', FTestDataList);

  for TestDataSet in FTestDataList do
  begin
    for i := Low(TestDataSet.TestData) to High(TestDataSet.TestData) do
    begin
      ctBytes := TFormat_HexL.Decode(BytesOf(TestDataSet.TestData[i].CT));

      try


        FCipherAES.Init(BytesOf(TFormat_HexL.Decode(TestDataSet.TestData[i].CryptKey)),
                        BytesOf(TFormat_HexL.Decode(TestDataSet.TestData[i].InitVector)),
                        $FF);

        FCipherAES.AuthenticationResultBitLength := TestDataSet.Taglen;
        FCipherAES.DataToAuthenticate            := TFormat_HexL.Decode(
                                                      BytesOf(
                                                        TestDataSet.TestData[i].AAD));

        FCipherAES.ExpectedAuthenticationResult :=
          TFormat_HexL.Decode(BytesOf(TestDataSet.TestData[i].TagResult));

        ctbStream := TBytesStream.Create(ctBytes);
        ptbStream := TBytesStream.Create;

        FCipherAES.DecodeStream(ctbStream, ptbStream, ctbStream.Size);

        FCipherAES.Done;

        DecryptData := ptbStream.Bytes;
        SetLength(DecryptData, ptbStream.Size);

      except
        on E: Exception do
          Status('CryptKey ' + string(TestDataSet.TestData[i].CryptKey) +
            ' ' + E.ClassName + ': ' + E.Message);
      end;
      FreeAndNil(ptbStream);
      FreeAndNil(ctbStream);

      CheckEquals(string(TestDataSet.TestData[i].PT),
                  StringOf(TFormat_HexL.Encode(DecryptData)),
                  'Plaintext wrong for key ' +
                  string(TestDataSet.TestData[i].CryptKey) + ' IV ' +
                  string(TestDataSet.TestData[i].InitVector) + ' PT ' +
                  string(TestDataSet.TestData[i].PT) + ' AAD ' +
                  string(TestDataSet.TestData[i].AAD) + ' Exp.: ' +
                  string(TestDataSet.TestData[i].CT) + ' Act.: ' +
                  StringOf(TFormat_HexL.Encode(DecryptData)));

      // Additional Authentication Data prüfen
      CheckEquals(string(TestDataSet.TestData[i].TagResult),
                         StringOf(TFormat_HexL.Encode(FCipherAES.CalculatedAuthenticationResult)),
                  'Authentication tag wrong for key ' +
                  string(TestDataSet.TestData[i].CryptKey) + ' IV ' +
                  string(TestDataSet.TestData[i].InitVector) + ' PT ' +
                  string(TestDataSet.TestData[i].PT) + ' AAD ' +
                  string(TestDataSet.TestData[i].AAD) + ' Exp.: ' +
                  string(TestDataSet.TestData[i].TagResult) + ' Act.: ' +
                  StringOf(TFormat_HexL.Encode(FCipherAES.DataToAuthenticate)));

    end;
  end;
end;

procedure TestTDECGCM.TestEncodeStream;
begin
  // -1 to disable chunking
  DoTestEncodeStream_LoadAndTestCAVSData(-1);
end;

procedure TestTDECGCM.TestEncodeStreamChunked;
begin
  // Use cipher block size as max chunk size
  DoTestEncodeStream_LoadAndTestCAVSData(
    Max(FCipherAES.Context.BlockSize, FCipherAES.Context.BufferSize));
end;

procedure TestTDECGCM.DoTestEncodeStream_LoadAndTestCAVSData(const
    aMaxChunkSize: Int64);
var
  i           : Integer;
  TestDataSet : TGCMTestSetEntry;
  curSetIndex: Integer;
begin
  FTestDataLoader.LoadFile('..\..\Unit Tests\Data\gcmEncryptExtIV128.rsp', FTestDataList);
  FTestDataLoader.LoadFile('..\..\Unit Tests\Data\gcmEncryptExtIV192.rsp', FTestDataList);
  FTestDataLoader.LoadFile('..\..\Unit Tests\Data\gcmEncryptExtIV256.rsp', FTestDataList);

  for curSetIndex := 0 to FTestDataList.Count - 1 do
  begin
    TestDataSet := FTestDataList[curSetIndex];
    for i := Low(TestDataSet.TestData) to High(TestDataSet.TestData) do
    begin
      DoTestEncodeStream_TestSingleSet(curSetIndex, i, aMaxChunkSize);
    end;
  end;
end;

procedure TestTDECGCM.TestEncodeLargeStream;
begin
  // There is only one record in test data set atm, so need to allow
  // incomplete load
  FTestDataLoader.LoadFile('..\..\Unit Tests\Data\gcmEncryptExtIV256_large.rsp',
    FTestDataList, True);
  Status('Encode large stream using chunking');
  CheckEquals(8192, StreamBufferSize, 'Might need to update data set to have enough data!');
{ TODO : Auskommentierten Code entfernen }
//  Assert(StreamBufferSize = 8192, 'Might need to update data set to have enough data!');
  DoTestEncodeStream_TestSingleSet(0, 0, StreamBufferSize);
  Status('Encode large stream without chunking');
  DoTestEncodeStream_TestSingleSet(0, 0, -1);
end;

procedure TestTDECGCM.DoTestEncodeStream_TestSingleSet(const aSetIndex,
    aDataIndex: Integer; const aMaxChunkSize: Int64 = -1);
var
  ctbStream: TBytesStream;
  curChunkSize: Int64;
  dataLeftToEncode: Int64;
  ptBytes: TBytes;
  TestDataSet : TGCMTestSetEntry;
  EncryptData : TBytes;
  ptbStream: TBytesStream;
begin
  TestDataSet := FTestDataList[aSetIndex];

  ptBytes := TFormat_HexL.Decode(BytesOf(TestDataSet.TestData[aDataIndex].PT));

  FCipherAES.Init(BytesOf(TFormat_HexL.Decode(TestDataSet.TestData[aDataIndex].CryptKey)),
                  BytesOf(TFormat_HexL.Decode(TestDataSet.TestData[aDataIndex].InitVector)),
                  $FF);

  FCipherAES.AuthenticationResultBitLength := TestDataSet.Taglen;
  FCipherAES.DataToAuthenticate            := TFormat_HexL.Decode(
                                                BytesOf(
                                                  TestDataSet.TestData[aDataIndex].AAD));

  ptbStream := TBytesStream.Create(ptBytes);
  ctbStream := TBytesStream.Create;
  try
    dataLeftToEncode := ptbStream.Size;
    curChunkSize := dataLeftToEncode;
    repeat
      // Apply chunking if needed
      if aMaxChunkSize > 0 then
        curChunkSize := Min(dataLeftToEncode, aMaxChunkSize);
      FCipherAES.EncodeStream(ptbStream, ctbStream, curChunkSize);
      Dec(dataLeftToEncode, curChunkSize);
    until (dataLeftToEncode = 0);

    FCipherAES.Done;

    EncryptData := ctbStream.Bytes;
    SetLength(EncryptData, ctbStream.Size);
  except
    on E: Exception do
      Status('CryptKey ' + string(TestDataSet.TestData[aDataIndex].CryptKey) +
        ' ' + E.ClassName + ': ' + E.Message);
  end;

  FreeAndNil(ptbStream);
  FreeAndNil(ctbStream);

  CheckEquals(string(TestDataSet.TestData[aDataIndex].CT),
              StringOf(TFormat_HexL.Encode(EncryptData)),
              'Cipher text wrong for Set ' + aSetIndex.ToString + ' and Data ' + aDataIndex.ToString +
              ' and Key ' + string(TestDataSet.TestData[aDataIndex].CryptKey) + ' IV ' +
              string(TestDataSet.TestData[aDataIndex].InitVector) + ' PT ' +
              string(TestDataSet.TestData[aDataIndex].PT) + ' AAD Exp.: ' +
              string(TestDataSet.TestData[aDataIndex].AAD) + ' Act.: ' +
              StringOf(TFormat_HexL.Encode(FCipherAES.DataToAuthenticate)));

  // Additional Authentication Data prüfen
  CheckEquals(string(TestDataSet.TestData[aDataIndex].TagResult),
                     StringOf(TFormat_HexL.Encode(FCipherAES.CalculatedAuthenticationResult)),
              'Authentication tag wrong for Set ' + aSetIndex.ToString + ' and Data ' + aDataIndex.ToString +
              ' and Key ' + string(TestDataSet.TestData[aDataIndex].CryptKey) + ' IV ' +
              string(TestDataSet.TestData[aDataIndex].InitVector) + ' PT ' +
              string(TestDataSet.TestData[aDataIndex].PT) + ' AAD Exp.: ' +
              string(TestDataSet.TestData[aDataIndex].AAD) + ' Act.: ' +
              StringOf(TFormat_HexL.Encode(FCipherAES.DataToAuthenticate)));
end;

procedure TestTDECGCM.TestGetStandardAuthenticationTagBitLengths;
var
  BitLengths: TStandardBitLengths;
begin
  BitLengths := FCipherAES.GetStandardAuthenticationTagBitLengths;

  CheckEquals( 96, BitLengths[0]);
  CheckEquals(104, BitLengths[1]);
  CheckEquals(112, BitLengths[2]);
  CheckEquals(120, BitLengths[3]);
  CheckEquals(128, BitLengths[4]);
end;

procedure TestTDECGCM.TestSetExpectedAuthenticationResult;
var
  Exp, Act: TBytes;
begin
  SetLength(Exp, 4);
  Exp := [1, 2, 3, 4];
  FCipherAES.ExpectedAuthenticationResult := Exp;
  Act := FCipherAES.ExpectedAuthenticationResult;

  CheckEquals(true, IsEqual(Exp, Act), 'Data length = 4');

  SetLength(Exp, 8);
  Exp := [1, 2, 3, 4, 5, 6, 7, 8];
  FCipherAES.ExpectedAuthenticationResult := Exp;
  Act := FCipherAES.ExpectedAuthenticationResult;

  CheckEquals(true, IsEqual(Exp, Act), 'Data length = 8');

  SetLength(Exp, 12);
  Exp := [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
  FCipherAES.ExpectedAuthenticationResult := Exp;
  Act := FCipherAES.ExpectedAuthenticationResult;

  CheckEquals(true, IsEqual(Exp, Act), 'Data length = 12');

  SetLength(Exp, 0);
  FCipherAES.ExpectedAuthenticationResult := Exp;
  Act := FCipherAES.ExpectedAuthenticationResult;

  CheckEquals(true, IsEqual(Exp, Act), 'Data length = 0');
end;

procedure TestTDECGCM.TestSetGetAuthenticationBitLength;
begin
  FCipherAES.AuthenticationResultBitLength := 128;
  CheckEquals(128, FCipherAES.AuthenticationResultBitLength);

  FCipherAES.AuthenticationResultBitLength := 192;
  CheckEquals(192, FCipherAES.AuthenticationResultBitLength);
end;

procedure TestTDECGCM.TestSetGetDataToAuthenticate;
begin
  FCipherAES.DataToAuthenticate := BytesOf(RawByteString('Hello'));
  CheckEquals(RawByteString('Hello'),
              RawByteString(StringOf(FCipherAES.DataToAuthenticate)));

  FCipherAES.DataToAuthenticate := BytesOf(RawByteString('The quick brown fox jumped over the lazy dog'));
  CheckEquals(RawByteString('The quick brown fox jumped over the lazy dog'),
              RawByteString(StringOf(FCipherAES.DataToAuthenticate)));
end;

initialization
  // Register all test cases to be run
  {$IFDEF DUnitX}
  TDUnitX.RegisterTestFixture(TestTDECGCM);
  {$ELSE}
  RegisterTest(TestTDECGCM.Suite);
  {$ENDIF}
end.

