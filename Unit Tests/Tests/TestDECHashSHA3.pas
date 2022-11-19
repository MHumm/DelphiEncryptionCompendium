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
unit TestDECHashSHA3;

interface

// Needs to be included before any other statements
{$INCLUDE TestDefines.inc}
{$INCLUDE ..\..\Source\DECOptions.inc}

uses
  System.SysUtils, System.Classes, Generics.Collections,
  {$IFDEF DUnitX}
  DUnitX.TestFramework,DUnitX.DUnitCompatibility,
  {$ELSE}
  TestFramework,
  {$ENDIF}
  TestDECTestDataContainer,
  DECTypes, DECBaseClass, DECHash, DECHashBase, DECHashAuthentication, DECUtil,
  DECFormatBase, DECHashBitBase, TestDECHash;

type
  /// <summary>
  ///   Base class for the SHA3 tests, provides loading the test data from files
  /// </summary>
  TestTHash_SHA3_Base = class(THash_TestBaseExtended)
  strict private
    /// <summary>
    ///   Load the data of all test files specified for the test class
    /// </summary>
    procedure LoadTestFiles; inline;
  strict protected
    /// <summary>
    ///   List of test data files to laod
    /// </summary>
    FTestFileNames : TStringList;

    /// <summary>
    ///   Calculate the Unicode hash value of the given test data
    /// </summary>
    /// <param name="TestData">
    ///   Test data as lower case Hex-Value
    /// </param>
    /// <param name="HashInst">
    ///   Instance of the hash algorithm used
    /// </param>
    /// <returns>
    ///   Calculated lower case hex formatted hash over the test data
    /// </returns>
    function CalcUnicodeHash(TestData : string;
                             HashInst : TDECHashAuthentication): RawByteString; inline;

    /// <summary>
    ///   Overridden so that loading of the test data file only happens here
    ///   and not also for the metadata etc. tests as well
    /// </summary>
    procedure DoTest52(HashClass:TDECHash); override;
    /// <summary>
    ///   Overridden so that loading of the test data file only happens here
    ///   and not also for the metadata etc. tests as well
    /// </summary>
    procedure DoTestCalcBuffer(HashClass:TDECHash); override;
    /// <summary>
    ///   Overridden so that loading of the test data file only happens here
    ///   and not also for the metadata etc. tests as well
    /// </summary>
    procedure DoTestCalcBytes(HashClass:TDECHash); override;
    /// <summary>
    ///   Overridden so that loading of the test data file only happens here
    ///   and not also for the metadata etc. tests as well
    /// </summary>
    procedure DoTestCalcStreamRawByteString(HashClass: TDECHashExtended); override;
    /// <summary>
    ///   Overridden so that loading of the test data file only happens here
    ///   and not also for the metadata etc. tests as well
    /// </summary>
    procedure DoTestCalcStream(HashClass: TDECHashExtended); override;
    /// <summary>
    ///   Overridden so that loading of the test data file only happens here
    ///   and not also for the metadata etc. tests as well
    /// </summary>
    procedure DoTestCalcStreamNoDone(HashClass: TDECHashExtended); override;
    /// <summary>
    ///   Overridden so that loading of the test data file only happens here
    ///   and not also for the metadata etc. tests as well
    /// </summary>
    procedure DoTestCalcStreamNoDoneMulti(HashClass: TDECHashExtended); override;
    /// <summary>
    ///   Overridden so that loading of the test data file only happens here
    ///   and not also for the metadata etc. tests as well
    /// </summary>
    procedure DoTestCalcUnicodeString(HashClass:TDECHash); override;
    /// <summary>
    ///   Overridden so that loading of the test data file only happens here
    ///   and not also for the metadata etc. tests as well
    /// </summary>
    procedure DoTestCalcRawByteString(HashClass:TDECHash); override;

    /// <summary>
    ///   Loads data stored in the rsp files provided by NIST into the test
    ///   data lists. Any exceptions will be caught and entries with wrong format
    ///   ignored.
    /// </summary>
    /// <param name="FileName">
    ///   Namne of the file to load
    /// </param>
    /// <param name="TestData">
    ///   Interface to the test data management instance
    /// </param>
    /// <param name="HashInst">
    ///   Instance of the hashing class to be tested for calculating the UTF-string
    ///   test data.
    /// </param>
    procedure LoadTestDataFile(FileName : string;
                               TestData : IHashTestDataContainer;
                               HashInst : TDECHashAuthentication);

    /// <summary>
    ///   Adds the SHA3 padding sheme to an input vector so that calculating
    ///   the hash using Keccak instead of SHA3 provides the same result.
    ///   Deliberately empty here as only implemented in class TestTHash_Keccak_Base.
    /// </summary>
    /// <param name="SHA3InputVector">
    ///   The SHA3 input vector in bytes (not hex encoded!) which shall get
    ///   the padding appended.
    /// </param>
    /// <param name="LastByteLength">
    ///   Number of bits used in the last byte. In the keccak override this will
    ///   be adjusted inside so it's a var param.
    /// </param>
    /// <returns>
    ///   The input vector with added padding
    /// </returns>
    function AddLastByteForKeccakTest(SHA3InputVector    : RawByteString;
                                      var LastByteLength : UInt8): RawByteString; virtual;
  public
    /// <summary>
    ///   Create test file list
    /// </summary>
    procedure SetUp; override;
    /// <summary>
    ///   Free test file lsit
    /// </summary>
    procedure TearDown; override;
  end;

  // Test methods for class THash_SHA3_224
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_SHA3_224 = class(TestTHash_SHA3_Base)
  strict protected
    /// <summary>
    ///   Some tests need to set the SHA3 specific padding byte and final bit length
    ///   parameters
    /// </summary>
    procedure ConfigHashClass(HashClass: TDECHash; IdxTestData:Integer); override;
    procedure TestFinalByteLengthOverflowHelper;
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
    procedure TestFinalByteLength;
    procedure TestFinalByteLengthOverflow;
    procedure TestRegressionDoneCalledTwice;
  end;

  // Test methods for class THash_SHA3_256
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_SHA3_256 = class(TestTHash_SHA3_Base)
  strict protected
    /// <summary>
    ///   Some tests need to set the SHA3 specific padding byte and final bit length
    ///   parameters
    /// </summary>
    procedure ConfigHashClass(HashClass: TDECHash; IdxTestData:Integer); override;
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class THash_SHA3_384
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_SHA3_384 = class(TestTHash_SHA3_Base)
  strict protected
    /// <summary>
    ///   Some tests need to set the SHA3 specific padding byte and final bit length
    ///   parameters
    /// </summary>
    procedure ConfigHashClass(HashClass: TDECHash; IdxTestData:Integer); override;
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class THash_SHA3_512
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_SHA3_512 = class(TestTHash_SHA3_Base)
  strict protected
    /// <summary>
    ///   Some tests need to set the SHA3 specific padding byte and final bit length
    ///   parameters
    /// </summary>
    procedure ConfigHashClass(HashClass: TDECHash; IdxTestData:Integer); override;
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class THash_Shake128
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_Shake128 = class(TestTHash_SHA3_Base)
  strict private
    procedure SetLength0Test;
  strict protected
    /// <summary>
    ///   Some tests need to set the SHA3 specific padding byte and final bit length
    ///   parameters as well as hash output length as Shake128 is an extendable
    ///   output length algorithm
    /// </summary>
    procedure ConfigHashClass(HashClass: TDECHash; IdxTestData:Integer); override;
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
    procedure TestLength0;
  end;

  // Test methods for class THash_Shake128
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_Shake256 = class(TestTHash_SHA3_Base)
  strict private
    procedure SetLength0Test;
  strict protected
    /// <summary>
    ///   Some tests need to set the SHA3 specific padding byte and final bit length
    ///   parameters as well as hash output length as Shake128 is an extendable
    ///   output length algorithm
    /// </summary>
    procedure ConfigHashClass(HashClass: TDECHash; IdxTestData:Integer); override;
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
    procedure TestLength0;
  end;

  /// <summary>
  ///   Base class for all Keccak test. This adds the necessary padding to the
  ///   input data when loading that.
  /// </summary>
  TestTHash_Keccak_Base = class(TestTHash_SHA3_Base)
  strict protected
    /// <summary>
    ///   Adds the SHA3 padding sheme to an input vector so that calculating
    ///   the hash using Keccak instead of SHA3 provides the same result.
    ///   Deliberately empty here as only implemented in class TestTHash_Keccak_Base.
    /// </summary>
    /// <param name="SHA3InputVector">
    ///   The SHA3 input vector in bytes (not hex encoded!) which shall get
    ///   the padding appended.
    /// </param>
    /// <param name="LastByteLength">
    ///   Number of bits used in the last byte. In the keccak override this will
    ///   be adjusted inside so it's a var param.
    /// </param>
    /// <returns>
    ///   The input vector with added padding
    /// </returns>
    function AddLastByteForKeccakTest(SHA3InputVector    : RawByteString;
                                      var LastByteLength : UInt8): RawByteString; override;

    /// <summary>
    ///   Adds the AddLastByteForKeccakTest necessary to be able to use a SHA3
    ///   test vector given in the source code directly for Keccak.
    /// </summary>
    /// <param name="lDataRow">
    ///   The already initialized test data row
    /// </param>
    /// <param name="SHA3InputVector">
    ///   The SHA3 input vector in bytes (not hex encoded!) which shall get
    ///   the padding appended.
    /// </param>
    /// <param name="LastByteLength">
    ///   Number of bits used from the last byte 
    /// </param>
    procedure AddLastByteForCodeTest(var lDataRow    : IHashTestDataRowSetup;
                                     SHA3InputVector : RawByteString;
                                     LastByteLength  : UInt8);
  end;

  // Test methods for class THash_Keccak_224
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_Keccak_224 = class(TestTHash_Keccak_Base)
  strict protected
    /// <summary>
    ///   Some tests need to set the SHA3 specific padding byte and final bit length
    ///   parameters
    /// </summary>
    procedure ConfigHashClass(HashClass: TDECHash; IdxTestData:Integer); override;
    procedure TestFinalByteLengthOverflowHelper;
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
    procedure TestFinalByteLength;
    procedure TestFinalByteLengthOverflow;
  end;

  // Test methods for class THash_Keccak_256
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_Keccak_256 = class(TestTHash_Keccak_Base)
  strict protected
    /// <summary>
    ///   Some tests need to set the SHA3 specific padding byte and final bit length
    ///   parameters
    /// </summary>
    procedure ConfigHashClass(HashClass: TDECHash; IdxTestData:Integer); override;
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class THash_Keccak_384
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_Keccak_384 = class(TestTHash_Keccak_Base)
  strict protected
    /// <summary>
    ///   Some tests need to set the SHA3 specific padding byte and final bit length
    ///   parameters
    /// </summary>
    procedure ConfigHashClass(HashClass: TDECHash; IdxTestData:Integer); override;
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class THash_Keccak_512
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_Keccak_512 = class(TestTHash_Keccak_Base)
  strict protected
    /// <summary>
    ///   Some tests need to set the SHA3 specific padding byte and final bit length
    ///   parameters
    /// </summary>
    procedure ConfigHashClass(HashClass: TDECHash; IdxTestData:Integer); override;
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

implementation

uses
  Winapi.Windows,
  DECFormat;

{ TestTHash_SHA3_Base }

procedure TestTHash_SHA3_Base.SetUp;
begin
  inherited;

  FTestFileNames := TStringList.Create;
end;

procedure TestTHash_SHA3_Base.TearDown;
begin
  inherited;

  FTestFileNames.Free;
end;

procedure TestTHash_SHA3_Base.LoadTestFiles;
var
  FileName : string;
begin
  for FileName in FTestFileNames do
    LoadTestDataFile(FileName, FTestData, FHash);
end;

procedure TestTHash_SHA3_Base.DoTest52(HashClass: TDECHash);
begin
  LoadTestFiles;
  inherited;
end;

procedure TestTHash_SHA3_Base.DoTestCalcBuffer(HashClass:TDECHash);
begin
  LoadTestFiles;
  inherited;
end;

procedure TestTHash_SHA3_Base.DoTestCalcBytes(HashClass:TDECHash);
begin
  LoadTestFiles;
  inherited;
end;

procedure TestTHash_SHA3_Base.DoTestCalcStream(HashClass:TDECHashExtended);
begin
  LoadTestFiles;
  inherited;
end;

procedure TestTHash_SHA3_Base.DoTestCalcStreamNoDone(HashClass: TDECHashExtended);
begin
  LoadTestFiles;
  inherited;
end;

procedure TestTHash_SHA3_Base.DoTestCalcStreamNoDoneMulti(HashClass: TDECHashExtended);
begin
  LoadTestFiles;
  inherited;
end;

procedure TestTHash_SHA3_Base.DoTestCalcStreamRawByteString(
  HashClass: TDECHashExtended);
begin
  LoadTestFiles;
  inherited;
end;

procedure TestTHash_SHA3_Base.DoTestCalcUnicodeString(HashClass:TDECHash);
begin
  LoadTestFiles;
  inherited;
end;

procedure TestTHash_SHA3_Base.DoTestCalcRawByteString(HashClass:TDECHash);
begin
  LoadTestFiles;
  inherited;
end;

procedure TestTHash_SHA3_Base.LoadTestDataFile(FileName : string;
                                               TestData : IHashTestDataContainer;
                                               HashInst : TDECHashAuthentication);
var
  Contents     : TStringList;
  FileRow,
  FileRowTrim,
  s1, msg      : string;
  MsgWithFixup : RawByteString; // if necessary msg with added padding for Keccak
  Len          : Int32;
  FinalByteLen : UInt8;
  HashLength   : Int16;
  lDataRow     : IHashTestDataRowSetup;

//NewContents: TStringList;
U : RawByteString;
begin
  Len      := 0;
  Contents := TStringList.Create;
//NewContents := TStringList.Create;
  try
    Contents.LoadFromFile(FileName);

    for FileRow in Contents do
    begin
//if FileRow.StartsWith('MDuni') then
//  Continue
//else
//  NewContents.Add(FileRow);

      FileRowTrim := LowerCase(Trim(FileRow));

      // # denotes comments
      if FileRow.StartsWith('#') then
        Continue;

      // length in bit
      if (Pos('len', FileRowTrim) = 1) then
      begin
        lDataRow := FTestData.AddRow;

        s1  := FileRowTrim;
        Delete(s1, 1, 6);
        Len := StrToInt(s1);
        FinalByteLen := Len mod 8;
        lDataRow.FinalBitLength := FinalByteLen;
        THash_SHA3Base(HashInst).FinalByteLength := FinalByteLen;

        Continue;
      end;

      // the message to be hashed = test data input
      if (Pos('msg', FileRowTrim) = 1) then
      begin
        msg := FileRowTrim;
        Delete(msg, 1, 6);

        if (Len > 0) then
        begin
          MsgWithFixup := AddLastByteForKeccakTest(
                                    TFormat_HexL.Decode(RawByteString(msg)),
                                    FinalByteLen);
          lDataRow.AddInputVector(MsgWithFixup);

          lDataRow.FinalBitLength := FinalByteLen;
          THash_SHA3Base(HashInst).FinalByteLength := FinalByteLen;

          // For Shake variants this will be overwritten once we know the output
          // hash length
//U := CalcUnicodeHash(string(TFormat_HexL.Encode(MsgWithFixup)), HashInst);
//NewContents.Add('MDuni = ' + string(U));
//          lDataRow.ExpectedOutputUTFStrTest :=
//            CalcUnicodeHash(string(TFormat_HexL.Encode(MsgWithFixup)), HashInst);
        end
        else
        begin
          FinalByteLen := 0;
          MsgWithFixup := AddLastByteForKeccakTest('', FinalByteLen);
          lDataRow.AddInputVector(MsgWithFixup);
          lDataRow.FinalBitLength := FinalByteLen;
          THash_SHA3Base(HashInst).FinalByteLength := FinalByteLen;
//
//          FinalByteLen := 0;
//U := CalcUnicodeHash(string(TFormat_HexL.Encode(MsgWithFixup)), HashInst);
////NewContents.Add('MDuni = ' + string(U));

//          lDataRow.ExpectedOutputUTFStrTest := U;
//            CalcUnicodeHash(string(TFormat_HexL.Encode(MsgWithFixup)), HashInst);
        end;

        Continue;
      end;

      // the expected output
      if (Pos('md =', FileRowTrim) = 1) or (Pos('squeezed ', FileRowTrim) = 1) then
      begin
        s1 := FileRowTrim;
        Delete(s1, 1, 5);

        // squeezed is from the Shake128/256 files
        if (Pos('squeezed ', FileRowTrim) = 1) then
        begin
          Delete(s1, 1, 6);
          lDataRow.ExpectedOutput            := RawByteString(s1);
          HashLength                         := Length(RawByteString(s1)) div 2;
          lDataRow.HashResultByteLength      := HashLength;
//
//          // Shake can caculate unicode test data only after hash length is known
//          THash_ShakeBase(HashInst).HashSize := HashLength;
////
//          if (Len > 0) then
////U := CalcUnicodeHash(msg, HashInst)
//////            lDataRow.ExpectedOutputUTFStrTest  := CalcUnicodeHash(msg, HashInst)
//          else
////U := CalcUnicodeHash('', HashInst);
//////            lDataRow.ExpectedOutputUTFStrTest  := CalcUnicodeHash('', HashInst);
////NewContents.Add('MDuni = ' + string(U));
        end
        else
          // md from the SHA3 ones
          lDataRow.ExpectedOutput := RawByteString(s1);

        Continue;
      end;

      if (Pos('mduni', FileRowTrim) = 1) then
      begin
        s1 := FileRowTrim;
        Delete(s1, 1, 8);

        lDataRow.ExpectedOutputUTFStrTest := RawByteString(s1);
      end;
    end;
  finally
    Contents.Free;
//NewContents.SaveToFile(FileName + ' 2');
//NewContents.Free;
  end;
end;

function TestTHash_SHA3_Base.AddLastByteForKeccakTest(SHA3InputVector    : RawByteString;
                                                      var LastByteLength : UInt8): RawByteString;
begin
  // For non Keccak use do rather nothing
  Result := SHA3InputVector;
end;

function TestTHash_SHA3_Base.CalcUnicodeHash(TestData : string;
                                             HashInst : TDECHashAuthentication): RawByteString;
begin
  Result := BytesToRawString(TFormat_HEXL.Encode(
               System.SysUtils.BytesOf(HashInst.CalcString(
                 string(TFormat_HexL.Decode(RawByteString(TestData)))))));
end;

{ TestTHash_SHA3_224 }

procedure TestTHash_SHA3_224.ConfigHashClass(HashClass: TDECHash;
  IdxTestData: Integer);
begin
  inherited;

  THash_SHA3_224(FHash).FinalByteLength := FTestData[IdxTestData].FinalByteBitLength;
end;

procedure TestTHash_SHA3_224.SetUp;
var
  lDataRow : IHashTestDataRowSetup;
  i        : Integer;
  s        : RawByteString;
begin
  // All specified data sources are for the non unicode expected outputs
  inherited;
  FHash := THash_SHA3_224.Create;

  //Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-
  //       Validation-Program/documents/sha3/sha-3bittestvectors.zip
  FTestFileNames.Add('..\..\Unit Tests\Data\SHA3_224ShortMsg.rsp');
  FTestFileNames.Add('..\..\Unit Tests\Data\SHA3_224LongMsg.rsp');
  // SourceEnd

// Für Unittests für CalcStream verschoben Start
  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-224_Msg5.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'ffbad5da96bad71789330206dc6768ecaeb1b32d' +
                                       'ca6b3301489674ab';
  lDataRow.ExpectedOutputUTFStrTest := '3d0e88c1e4fe0f6577e921e50805155b0748b40a' +
                                       '3ab368c96b63f686';
  lDataRow.AddInputVector(#$13);
  lDataRow.FinalBitLength := 5;

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-224_Msg30.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd666a514cc9dba25ac1ba69ed3930460deaac985' +
                                       '1b5f0baab007df3b';
  lDataRow.ExpectedOutputUTFStrTest := '098526f4e121e977c325078374bf13ee9b0f2ed3' +
                                       '14ce743c5641cebe';
  lDataRow.AddInputVector(#$53#$58#$7B#$19);
  lDataRow.FinalBitLength := 6;
// Für Unittests für CalcStream verschoben Ende

  // Source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //         and-Guidelines/documents/examples/SHA3-224_1600.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '9376816aba503f72f96ce7eb65ac095deee3be4b' +
                                       'f9bbc2a1cb7e11e0';
  lDataRow.ExpectedOutputUTFStrTest := '28a4a80fded04a676674687c8330422eedeb18c9' +
                                       'dba976234a9e007a';
  lDataRow.AddInputVector(RawByteString(#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3), 1, 20);
  lDataRow.FinalBitLength := 0;

  // Source: https://emn178.github.io/online-tools/sha3_224.html
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '32eb6a4121daebe223db1987740814e1dd9d9ddb' +
                                       'ddfd466feff5c9b4';
  lDataRow.ExpectedOutputUTFStrTest := '0f1ad8cd5a85fe68319b67427e1f0b685498bc24' +
                                       '6a81a1f595c89e4e';
  lDataRow.AddInputVector(RawByteString('e21et2e2et1208e7t12e07812te08127et1028e' +
                                        '7t1208e7gd81d872t178r02tr370823'), 1, 10);
  lDataRow.FinalBitLength := 0;

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'f7fc914c8fe4827d866b02df2459840260f4adb0' +
                                       'db4deb9fa661756c';
  lDataRow.ExpectedOutputUTFStrTest := 'e4d44bbda0b8fc8a73b421f6795c6380c0e21d50' +
                                       '539a7b43c20a7529';

   for i := 1 to 10 do
     s := s + 'e21et2e2et1208e7t12e07812te08127et1028e7t1208e7gd81d872t178r02tr370823';
   s := s + 'TurboMagic';
   s := s + s + s;

  lDataRow.AddInputVector(s);
  lDataRow.FinalBitLength := 0;

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-224_Msg5.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'ffbad5da96bad71789330206dc6768ecaeb1b32d' +
                                       'ca6b3301489674ab';
  lDataRow.ExpectedOutputUTFStrTest := '3d0e88c1e4fe0f6577e921e50805155b0748b40a' +
                                       '3ab368c96b63f686';
  lDataRow.AddInputVector(#$13);
  lDataRow.FinalBitLength := 5;

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-224_Msg30.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd666a514cc9dba25ac1ba69ed3930460deaac985' +
                                       '1b5f0baab007df3b';
  lDataRow.ExpectedOutputUTFStrTest := '098526f4e121e977c325078374bf13ee9b0f2ed3' +
                                       '14ce743c5641cebe';
  lDataRow.AddInputVector(#$53#$58#$7B#$19);
  lDataRow.FinalBitLength := 6;

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-224_Msg1605.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '22d2f7bb0b173fd8c19686f9173166e3ee627380' +
                                       '47d7eadd69efb228';
  lDataRow.ExpectedOutputUTFStrTest := 'a6871aef1c16c4c0fcaef97636711fb6216b1586' +
                                       '26d4e2b7e9e7e962';
  lDataRow.AddInputVector(RawByteString(#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3));
  lDataRow.FinalBitLength := 5;

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-224_1630.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4e907bb1057861f200a599e9d4f85b02d88453bf' +
                                       '5b8ace9ac589134c';
  lDataRow.ExpectedOutputUTFStrTest := '30a15a07d7f0a34e5b36de3bec18c31eac2c9495' +
                                       '2b50820095c8807e';
  lDataRow.AddInputVector(RawByteString(#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3));
  lDataRow.FinalBitLength := 6;
end;

procedure TestTHash_SHA3_224.TestBlockSize;
begin
  CheckEquals(144, FHash.BlockSize);
end;

procedure TestTHash_SHA3_224.TestClassByName;
begin
  DoTestClassByName('THash_SHA3_224', THash_SHA3_224);
end;

procedure TestTHash_SHA3_224.TestDigestSize;
begin
  CheckEquals(28, FHash.DigestSize);
end;

procedure TestTHash_SHA3_224.TestIdentity;
begin
  CheckEquals($D0579DA9, FHash.Identity);
end;

procedure TestTHash_SHA3_224.TestFinalByteLength;
var
  Hash_SHA3_224 : THash_SHA3_224;
  i             : Integer;
begin
  Hash_SHA3_224 := THash_SHA3_224.Create;
  try
    for i := 0 to 7 do
    begin
      Hash_SHA3_224.FinalByteLength := i;
      CheckEquals(i, Hash_SHA3_224.FinalByteLength);
    end;
  finally
    Hash_SHA3_224.Free;
  end;
end;

procedure TestTHash_SHA3_224.TestFinalByteLengthOverflow;
begin
  CheckException(TestFinalByteLengthOverflowHelper, EDECHashException);
end;

procedure TestTHash_SHA3_224.TestFinalByteLengthOverflowHelper;
var
  Hash_SHA3_224 : THash_SHA3_224;
begin
  Hash_SHA3_224 := THash_SHA3_224.Create;
  try
    Hash_SHA3_224.FinalByteLength := 8;
    CheckEquals(8, Hash_SHA3_224.FinalByteLength);
  finally
    Hash_SHA3_224.Free;
  end;
end;

procedure TestTHash_SHA3_224.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_SHA3_224.TestRegressionDoneCalledTwice;
var
  Hash   : THash_SHA3_224;
  Stream : TMemoryStream;
  Result : TBytes;
begin
  // Regression test for a bug reported by Harry Rogers via private e-mail.
  // The failure was that Done raisedn an exception when called after calling
  // one of the CalcFile or CalcStream variants which automatically call Done
  // at the end.
  Hash := THash_SHA3_224.Create;
  try
    Stream := TMemoryStream.Create;
    try
      Stream.WriteData($af);
      Stream.Seek(0, TSeekOrigin.soBeginning);

      Hash.CalcStream(Stream, 1, Result, nil);
      Hash.Done;

      CheckEquals(RawByteString('1545e234dd648d51afe85b758f865c4855715cccf276eeb004a37a74'),
                  BytesToRawString(TFormat_HEXL.Encode(Result)));
    finally
      Stream.Free;
    end;
  finally
    Hash.Free;
  end;
end;

{ TestTHash_SHA3_256 }

procedure TestTHash_SHA3_256.ConfigHashClass(HashClass: TDECHash;
  IdxTestData: Integer);
begin
  inherited;

  THash_SHA3_256(FHash).FinalByteLength := FTestData[IdxTestData].FinalByteBitLength;
end;

procedure TestTHash_SHA3_256.SetUp;
var
  lDataRow:IHashTestDataRowSetup;
begin
  // All specified data sources are for the non unicode expected outputs
  inherited;
  FHash := THash_SHA3_256.Create;

  //Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-
  //       Validation-Program/documents/sha3/sha-3bittestvectors.zip
  FTestFileNames.Add('..\..\Unit Tests\Data\SHA3_256ShortMsg.rsp');
  FTestFileNames.Add('..\..\Unit Tests\Data\SHA3_256LongMsg.rsp');
  // SourceEnd

  // Source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //         and-Guidelines/documents/examples/SHA3-256_Msg0.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'a7ffc6f8bf1ed76651c14756a061d662f580ff4d' +
                                       'e43b49fa82d80a4b80f8434a';
  lDataRow.ExpectedOutputUTFStrTest := 'a7ffc6f8bf1ed76651c14756a061d662f580ff4d' +
                                       'e43b49fa82d80a4b80f8434a';
  lDataRow.AddInputVector('');

  // Source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //         and-Guidelines/documents/examples/SHA3-224_1600.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '79f38adec5c20307a98ef76e8324afbfd46cfd81' +
                                       'b22e3973c65fa1bd9de31787';
  lDataRow.ExpectedOutputUTFStrTest := '06ea5e186dab1b3f99bcf91918b53748367674c0' +
                                       '5baa627010fba06edb67f0ba';
  lDataRow.AddInputVector(RawByteString(
                          #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3), 1, 20);
  lDataRow.FinalBitLength := 0;

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-256_Msg5.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '7b0047cf5a456882363cbf0fb05322cf65f4b705' +
                                       '9a46365e830132e3b5d957af';
  lDataRow.ExpectedOutputUTFStrTest := 'f2771aed86eba40f0f20c80aed2efb2ccdcd2a45' +
                                       '14a89642353dc4ab6f31a0a1';
  lDataRow.AddInputVector(#$13);
  lDataRow.FinalBitLength := 5;


  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-256_Msg30.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c8242fef409e5ae9d1f1c857ae4dc624b92b1980' +
                                       '9f62aa8c07411c54a078b1d0';
  lDataRow.ExpectedOutputUTFStrTest := '0264f8f24160a1c2336453338772637b64864ce1' +
                                       '3c3c4207c40b34d28d68cd23';
  lDataRow.AddInputVector(#$53#$58#$7B#$19);
  lDataRow.FinalBitLength := 6;

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-256_Msg1605.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '81ee769bed0950862b1ddded2e84aaa6ab7bfdd3' +
                                       'ceaa471be31163d40336363c';
  lDataRow.ExpectedOutputUTFStrTest := '7a4185574238ca2e2550a9fa85a0c5a327811698' +
                                       'c3a05531a70e0a7ec369e2e5';
  lDataRow.AddInputVector(RawByteString(#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3));
  lDataRow.FinalBitLength := 5;

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-256_1630.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '52860aa301214c610d922a6b6cab981ccd06012e' +
                                       '54ef689d744021e738b9ed20';
  lDataRow.ExpectedOutputUTFStrTest := '8f0bb49b3327e5a03dd69bded05a86c9e7d72a7d' +
                                       '719dd354a873cf2a70c30354';
  lDataRow.AddInputVector(RawByteString(#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3));
  lDataRow.FinalBitLength := 6;
end;

procedure TestTHash_SHA3_256.TestBlockSize;
begin
  CheckEquals(136, FHash.BlockSize);
end;

procedure TestTHash_SHA3_256.TestClassByName;
begin
  DoTestClassByName('THash_SHA3_256', THash_SHA3_256);
end;

procedure TestTHash_SHA3_256.TestDigestSize;
begin
  CheckEquals(32, FHash.DigestSize);
end;

procedure TestTHash_SHA3_256.TestIdentity;
begin
  CheckEquals($71186A42, FHash.Identity);
end;

procedure TestTHash_SHA3_256.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

{ TestTHash_SHA3_384 }

procedure TestTHash_SHA3_384.ConfigHashClass(HashClass: TDECHash;
  IdxTestData: Integer);
begin
  inherited;

  THash_SHA3_384(FHash).FinalByteLength := FTestData[IdxTestData].FinalByteBitLength;
end;

procedure TestTHash_SHA3_384.SetUp;
var
  lDataRow:IHashTestDataRowSetup;
begin
  inherited;
  FHash := THash_SHA3_384.Create;

  //Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-
  //       Validation-Program/documents/sha3/sha-3bittestvectors.zip
  FTestFileNames.Add('..\..\Unit Tests\Data\SHA3_384ShortMsg.rsp');
  FTestFileNames.Add('..\..\Unit Tests\Data\SHA3_384LongMsg.rsp');
  // SourceEnd

  // Source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //         and-Guidelines/documents/examples/SHA3-384_Msg0.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '0c63a75b845e4f7d01107d852e4c2485c51a50aa' +
                                       'aa94fc61995e71bbee983a2ac3713831264adb47' +
                                       'fb6bd1e058d5f004';
  lDataRow.ExpectedOutputUTFStrTest := '0c63a75b845e4f7d01107d852e4c2485c51a50aa' +
                                       'aa94fc61995e71bbee983a2ac3713831264adb47' +
                                       'fb6bd1e058d5f004';
  lDataRow.AddInputVector('');

  // Source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //         and-Guidelines/documents/examples/SHA3-384_1600.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '1881de2ca7e41ef95dc4732b8f5f002b189cc1e4' +
                                       '2b74168ed1732649ce1dbcdd76197a31fd55ee98' +
                                       '9f2d7050dd473e8f';
  lDataRow.ExpectedOutputUTFStrTest := '50dd07a64dc6ff190db60e612d8511742baa8eb5' +
                                       'a499a0a02e51cea3f4b922f8ecf72785dc0a2ef3' +
                                       '8230340378d3d104';
  lDataRow.AddInputVector(RawByteString(
                          #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3), 1, 20);
  lDataRow.FinalBitLength := 0;

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-384_Msg5.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '737c9b491885e9bf7428e792741a7bf8dca96534' +
                                       '71c3e148473f2c236b6a0a6455eb1dce9f779b4b' +
                                       '6b237fef171b1c64';
  lDataRow.ExpectedOutputUTFStrTest := 'c2ab721500b00f70be1f5adfcbe70cdf22581c35' +
                                       'ed47d265538c1cbd939f1fe8290e58d096eb3378' +
                                       'f3a75818d623ebb8';
  lDataRow.AddInputVector(#$13);
  lDataRow.FinalBitLength := 5;

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-384_Msg30.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '955b4dd1be03261bd76f807a7efd432435c41736' +
                                       '2811b8a50c564e7ee9585e1ac7626dde2fdc030f' +
                                       '876196ea267f08c3';
  lDataRow.ExpectedOutputUTFStrTest := '20243fac26472f874f31539f8b26c1eb226f0c02' +
                                       '3f7f3affa688a471a1943c6fb00dbcbb928b5234' +
                                       'e19423670f34c328';
  lDataRow.AddInputVector(#$53#$58#$7B#$19);
  lDataRow.FinalBitLength := 6;

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-384_Msg1605.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'a31fdbd8d576551c21fb1191b54bda65b6c5fe97' +
                                       'f0f4a69103424b43f7fdb835979fdbeae8b3fe16' +
                                       'cb82e587381eb624';
  lDataRow.ExpectedOutputUTFStrTest := 'f3c3516f2b9d8a07233fc3dd427f8aba27d8e2e5' +
                                       '793a6054f5bcdf005ce6de90d8dc6c69a833f5a7' +
                                       '9da35504fc3ea8bc';
  lDataRow.AddInputVector(RawByteString(#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3));
  lDataRow.FinalBitLength := 5;

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-384_1630.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '3485d3b280bd384cf4a777844e94678173055d1c' +
                                       'bc40c7c2c3833d9ef12345172d6fcd31923bb879' +
                                       '5ac81847d3d8855c';
  lDataRow.ExpectedOutputUTFStrTest := '63f5d9652bc5a4619ea4b3baf70a43e9d43d0620' +
                                       '20109c162265f84c95eeb5768a4ce055dbe64385' +
                                       '324650c2cd9091d5';
  lDataRow.AddInputVector(RawByteString(#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3));
  lDataRow.FinalBitLength := 6;
end;

procedure TestTHash_SHA3_384.TestBlockSize;
begin
  CheckEquals(104, FHash.BlockSize);
end;

procedure TestTHash_SHA3_384.TestClassByName;
begin
  DoTestClassByName('THash_SHA3_384', THash_SHA3_384);
end;

procedure TestTHash_SHA3_384.TestDigestSize;
begin
  CheckEquals(48, FHash.DigestSize);
end;

procedure TestTHash_SHA3_384.TestIdentity;
begin
  CheckEquals($2B7A1F14, FHash.Identity);
end;

procedure TestTHash_SHA3_384.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

{ TestTHash_SHA3_512 }

procedure TestTHash_SHA3_512.ConfigHashClass(HashClass: TDECHash;
  IdxTestData: Integer);
begin
  inherited;

  THash_SHA3_512(FHash).FinalByteLength := FTestData[IdxTestData].FinalByteBitLength;
end;

procedure TestTHash_SHA3_512.SetUp;
var
  lDataRow : IHashTestDataRowSetup;
begin
  inherited;
  FHash := THash_SHA3_512.Create;

  //Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-
  //       Validation-Program/documents/sha3/sha-3bittestvectors.zip
  FTestFileNames.Add('..\..\Unit Tests\Data\SHA3_512ShortMsg.rsp');
  FTestFileNames.Add('..\..\Unit Tests\Data\SHA3_512LongMsg.rsp');
  // SourceEnd

  // Source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //         and-Guidelines/documents/examples/SHA3-512_1600.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'e76dfad22084a8b1467fcf2ffa58361bec7628ed' +
                                       'f5f3fdc0e4805dc48caeeca81b7c13c30adf52a3' +
                                       '659584739a2df46be589c51ca1a4a8416df6545a' +
                                       '1ce8ba00';
  lDataRow.ExpectedOutputUTFStrTest := '54ab223a7cee7603f2b89596b54f8d838845e0a0' +
                                       'af2be3e9ad2cd7acb111757cb0c41b3564c07778' +
                                       '47684435da78577781eef8e6a6652c9844a85882' +
                                       'e0fa8b28';
  lDataRow.AddInputVector(RawByteString(
                          #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3), 1, 20);
  lDataRow.FinalBitLength := 0;

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-512_Msg5.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'a13e01494114c09800622a70288c432121ce7003' +
                                       '9d753cadd2e006e4d961cb27544c1481e5814bdc' +
                                       'eb53be6733d5e099795e5e81918addb058e22a9f' +
                                       '24883f37';
  lDataRow.ExpectedOutputUTFStrTest := '6961fe7f75e0ad35aead16be49c711b373d22226' +
                                       'ea2b7b2897df24048287a1b6d7b43bad246c8a44' +
                                       'ddccb49263a688343fa60142650a3e06af2a87c9' +
                                       '296438a8';
  lDataRow.AddInputVector(#$13);
  lDataRow.FinalBitLength := 5;

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-512_Msg30.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '9834c05a11e1c5d3da9c740e1c106d9e590a0e53' +
                                       '0b6f6aaa7830525d075ca5db1bd8a6aa981a2861' +
                                       '3ac334934a01823cd45f45e49b6d7e6917f2f167' +
                                       '78067bab';
  lDataRow.ExpectedOutputUTFStrTest := '7e59a0c8fca17a79c748f927c85408bfda1b158d' +
                                       '7ab95df59f650a3bb773e1eb6c1112cd2c351b24' +
                                       'b99a2f8e08688ec19816bfc292fba63305307571' +
                                       'ce9360cf';
  lDataRow.AddInputVector(#$53#$58#$7B#$19);
  lDataRow.FinalBitLength := 6;

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-512_Msg1605.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'fc4a167ccb31a937d698fde82b04348c9539b28f' +
                                       '0c9d3b4505709c03812350e4990e9622974f6e57' +
                                       '5c47861c0d2e638ccfc2023c365bb60a93f52855' +
                                       '0698786b';
  lDataRow.ExpectedOutputUTFStrTest := '7e65803342ce242fdc8cfd27019516669615327f' +
                                       '679ced86453df7ee0a745267a453e7b94568c2ea' +
                                       'dc4ce7a7de02f48a5c2204d03418542f1a64f7db' +
                                       '78026218';
  lDataRow.AddInputVector(RawByteString(#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3));
  lDataRow.FinalBitLength := 5;

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-512_1630.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'cf9a30ac1f1f6ac0916f9fef1919c595debe2ee8' +
                                       '0c85421210fdf05f1c6af73aa9cac881d0f91db6' +
                                       'd034a2bbadc1cf7fbcb2ecfa9d191d3a5016fb3f' +
                                       'ad8709c9';
  lDataRow.ExpectedOutputUTFStrTest := '55971e2e5d0182f25bc453364f9d3a77fef05e7e' +
                                       '32c99e630a8586c37815aea5087a51aa3730f855' +
                                       'df963c7740f4e6bd2b73f5079cf317031ed120c3' +
                                       '3df4054d';
  lDataRow.AddInputVector(RawByteString(#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                        #$A3#$A3#$A3#$A3));
  lDataRow.FinalBitLength := 6;
end;

procedure TestTHash_SHA3_512.TestBlockSize;
begin
  CheckEquals(72, FHash.BlockSize);
end;

procedure TestTHash_SHA3_512.TestClassByName;
begin
  DoTestClassByName('THash_SHA3_512', THash_SHA3_512);
end;

procedure TestTHash_SHA3_512.TestDigestSize;
begin
  CheckEquals(64, FHash.DigestSize);
end;

procedure TestTHash_SHA3_512.TestIdentity;
begin
  CheckEquals($17567DDA, FHash.Identity);
end;

procedure TestTHash_SHA3_512.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

{ TestTHash_Shake128 }

procedure TestTHash_Shake128.ConfigHashClass(HashClass: TDECHash;
  IdxTestData: Integer);
begin
  inherited;

  THash_Shake128(FHash).FinalByteLength := FTestData[IdxTestData].FinalByteBitLength;
  THash_Shake128(FHash).HashSize        := FTestData[IdxTestData].HashResultByteLength;
end;

procedure TestTHash_Shake128.SetUp;
var
  lDataRow : IHashTestDataRowSetup;
begin
  inherited;
  FHash := THash_SHake128.Create;

  // Source https://github.com/XKCP/XKCP/tree/4017707cade3c1fd42f3c6fa984609db87606700/tests/TestVectors
  FTestFileNames.Add('..\..\Unit Tests\Data\ShortMsgKAT_SHAKE128.txt');
  // SourceEnd

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '7f9c2ba4e88f827d616045507605853ed73b8093' + // 20
                                       'f6efbc88eb1a6eacfa66ef263cb1eea988004b93' +
                                       '103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3' +
                                       'f9ae57e235b8cc873c23dc62b8d260169afa2f75' +
                                       'ab916a58d974918835d25e6a435085b2badfd6df' +
                                       'aac359a5efbb7bcc4b59d538df9a04302e10c8bc' +
                                       '1cbf1a0b3a5120ea17cda7cfad765f5623474d36' +
                                       '8ccca8af0007cd9f5e4c849f167a580b14aabdef' +
                                       'aee7eef47cb0fca9767be1fda69419dfb927e9df' +
                                       '07348b196691abaeb580b32def58538b8d23f877' + // 200
                                       '32ea63b02b4fa0f4873360e2841928cd60dd4cee' +
                                       '8cc0d4c922a96188d032675c8ac850933c7aff15' +
                                       '33b94c834adbb69c6115bad4692d8619f90b0cdf' +
                                       '8a7b9c264029ac185b70b83f2801f2f4b3f70c59' +
                                       '3ea3aeeb613a7f1b1de33fd75081f592305f2e45' +
                                       '26edc09631b10958f464d889f31ba010250fda7f' +
                                       '1368ec2967fc84ef2ae9aff268e0b1700affc682' +
                                       '0b523a3d917135f2dff2ee06bfe72b3124721d4a' +
                                       '26c04e53a75e30e73a7a9c4a95d91c55d495e9f5' +
                                       '1dd0b5e9d83c6d5e8ce803aa62b8d654db53d09b' + // 400
                                       '8dcff273cdfeb573fad8bcd45578bec2e770d01e' +
                                       'fde86e721a3f7c6cce275dabe6e2143f1af18da7' +
                                       'efddc4c7b70b5e345db93cc936bea323491ccb38' +
                                       'a388f546a9ff00dd4e1300b9b2153d2041d205b4' +
                                       '43e41b45a653f2a5c4492c1add544512dda25298' + // 500
                                       '33462b71a41a45be97290b6f';                  // 512
  lDataRow.ExpectedOutputUTFStrTest := '7f9c2ba4e88f827d616045507605853ed73b8093' + // 20
                                       'f6efbc88eb1a6eacfa66ef263cb1eea988004b93' +
                                       '103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3' +
                                       'f9ae57e235b8cc873c23dc62b8d260169afa2f75' +
                                       'ab916a58d974918835d25e6a435085b2badfd6df' +
                                       'aac359a5efbb7bcc4b59d538df9a04302e10c8bc' +
                                       '1cbf1a0b3a5120ea17cda7cfad765f5623474d36' +
                                       '8ccca8af0007cd9f5e4c849f167a580b14aabdef' +
                                       'aee7eef47cb0fca9767be1fda69419dfb927e9df' +
                                       '07348b196691abaeb580b32def58538b8d23f877' + // 200
                                       '32ea63b02b4fa0f4873360e2841928cd60dd4cee' +
                                       '8cc0d4c922a96188d032675c8ac850933c7aff15' +
                                       '33b94c834adbb69c6115bad4692d8619f90b0cdf' +
                                       '8a7b9c264029ac185b70b83f2801f2f4b3f70c59' +
                                       '3ea3aeeb613a7f1b1de33fd75081f592305f2e45' +
                                       '26edc09631b10958f464d889f31ba010250fda7f' +
                                       '1368ec2967fc84ef2ae9aff268e0b1700affc682' +
                                       '0b523a3d917135f2dff2ee06bfe72b3124721d4a' +
                                       '26c04e53a75e30e73a7a9c4a95d91c55d495e9f5' +
                                       '1dd0b5e9d83c6d5e8ce803aa62b8d654db53d09b' + // 400
                                       '8dcff273cdfeb573fad8bcd45578bec2e770d01e' +
                                       'fde86e721a3f7c6cce275dabe6e2143f1af18da7' +
                                       'efddc4c7b70b5e345db93cc936bea323491ccb38' +
                                       'a388f546a9ff00dd4e1300b9b2153d2041d205b4' +
                                       '43e41b45a653f2a5c4492c1add544512dda25298' + // 500
                                       '33462b71a41a45be97290b6f';                  // 512
  lDataRow.HashResultByteLength     := 512;
  lDataRow.AddInputVector('');
  lDataRow.FinalBitLength := 0;

  // Source until SourceEnd: ShortMSGKAT_SHake128.txt
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'f7b1c8f5fd6136aeb4d8bfa0740787a6d2e7af48' +
                                       '8e96cbc3a5e0929a5989c0af49794aa6c64a5842' +
                                       'b9c081238dfc4d5c2f175843026f72ec10c46436' +
                                       '71372fd083809f51e2a7456e55e1a07deb95aeea' +
                                       '62bb39adfadc4b42aa6b289aafebe2c056f86200' +
                                       '7b7f891716573bc54bd65657fd5dd112c87663cd' +
                                       '4584c92247baa3d228415a98e0dbe5bb128e4365' +
                                       '492c322ca720120bf34db0b97a6dc032d5dfe068' +
                                       'dc96173ceeaa9baf48f21e4ccbba134faf84b025' +
                                       '08d9e1fc9486aeb673b27ba86124cd285b4c1b17' +
                                       '60124c4ad6c503ad35f691f62853e979ceedf706' +
                                       '27a0b93a42738388752c8f4154c3e9abb1b53638' +
                                       '081d8259545f801b5f15764dda74490a3397518f' +
                                       '8f78c73ec68e5178e8434f31381b1fe50e034b2e' +
                                       'b7839f134e5753de6106a0214f7f4d8ff53c063a' +
                                       'eb1f4a74e66d3e2c925fc2f55be83a9e8d23061c' +
                                       'df014dfab5976ca0da87ab6dfe263512782eade5' +
                                       'ab9b95f11447a8f0900c4aa6e31665957ec3acb1' +
                                       '7a3654d683e03ed22ed330c2894f7a2097ba004c' +
                                       '612b7c86cd7438215197557385d12bd86d9a0a7d' +
                                       '8efe64d0b6254aa04f87c4807ada5f276fccf016' +
                                       '8f058c1b15bdf96f369dc5ed5585b8d5fe0fe009' +
                                       'db407d0b168c78703d8f7d57ab254176c2464204' +
                                       '61becdafafdfd4dff6429f4f2592806c7e7aa6d2' +
                                       '3984df1b6c548fb0174e8daf725f04051aa995e3' +
                                       'dfab45b411979ca49dde8622';
  lDataRow.ExpectedOutputUTFStrTest := 'bf95de572093ec60363d6053886cb78ff78b7f' +
                                       '08c28bfd70d50f1a53b7c41aa3cdfb2d2d8987' +
                                       '86a6f8da4116b19ffa00f97179667bb582a6ed' +
                                       'f9597af69bf28a159f5a8b787b564240ca44bd' +
                                       '144e515b563c39ea53ab399ab290544ae54d48' +
                                       '29fa940c5943c8178b4efe0e2399b258322228' +
                                       'c011df8c49fff3d813802e7e10814a9862caa0' +
                                       '4f9ee33ac29de1bdb067e21cf98361b77d349d' +
                                       '5b3a591939ad3be7de57cd2c5bc054af941bca' +
                                       '6185f2c7d4ae0499c718c988c5d60885ca4478' +
                                       'c11752f9be846dece8ad0d8a24baad9256fe0e' +
                                       '993fbe5b8e4f43b7ed2ee5cdf304e34f439698' +
                                       '269011492b63475f1a769c7e0290cedfef5e11' +
                                       'c1bef1547d1e508f86063d0aa5a5bb57c13c7a' +
                                       'e5d65dda0c0c49c2f4913780c4e9c42dc55aed' +
                                       '3bf77e1f2523fc89718fc97ff6e9c5dc7b6338' +
                                       '7784b0cdabb12694917308c3c2326b2235757f' +
                                       '6cdd5f3664a4b66314ab6e59f1699fe4ebce11' +
                                       'a1dd16847ddf1704d5fb9c4cd69f32f579e1ef' +
                                       'a317bc7d6d226322d1011d0cb989d0bb0202be' +
                                       '841ea4e0551339f3af0fed065cbfc869925861' +
                                       'a51d6a8e6e5d46dcb4f83ab3ddf5bd8a13bd7f' +
                                       '93e5ad39d451e6ad1bb3f2a571978b85b74e01' +
                                       '95293d2febcd8c96b4c7c815801136a48ee84c' +
                                       '5ba94984fd29aa0b3e2e3b6ac46fc0dfe57536' +
                                       '642a6d3bf53542475f8a68ed0b51dfc75d85ca' +
                                       'e89622dd24c4dc4556f9685b31220280c546';
  lDataRow.HashResultByteLength     := 512;
  lDataRow.AddInputVector(TFormat_HEXL.Decode('0372cd1ce0b74ce05e717fc4b9a82ce1a' +
                                              '888f4ef7b0027a5d6dc5f8d13936e01'));
  lDataRow.FinalBitLength := 2;
  // SourceEnd
end;

procedure TestTHash_Shake128.TestBlockSize;
begin
  CheckEquals(168, FHash.BlockSize);
end;

procedure TestTHash_Shake128.TestClassByName;
begin
  DoTestClassByName('THash_Shake128', THash_Shake128);
end;

procedure TestTHash_Shake128.TestDigestSize;
begin
  CheckEquals(0, FHash.DigestSize);
end;

procedure TestTHash_Shake128.TestIdentity;
begin
  CheckEquals($2DA1732E, FHash.Identity);
end;

procedure TestTHash_Shake128.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_Shake128.SetLength0Test;
var
  Shake: THash_Shake128;
begin
  Shake := THash_Shake128.Create;
  try
    Shake.HashSize := 0;
  finally
    Shake.Free;
  end;
end;

procedure TestTHash_Shake128.TestLength0;
begin
  CheckException(SetLength0Test, EDECHashException);
end;

{ TestTHash_Shake256 }

procedure TestTHash_Shake256.ConfigHashClass(HashClass: TDECHash;
  IdxTestData: Integer);
begin
  inherited;

  THash_Shake256(FHash).FinalByteLength := FTestData[IdxTestData].FinalByteBitLength;
  THash_Shake256(FHash).HashSize        := FTestData[IdxTestData].HashResultByteLength;
end;

procedure TestTHash_Shake256.SetUp;
var
  lDataRow : IHashTestDataRowSetup;
begin
  inherited;
  FHash := THash_Shake256.Create;

  // Source https://github.com/XKCP/XKCP/tree/4017707cade3c1fd42f3c6fa984609db87606700/tests/TestVectors
  FTestFileNames.Add('..\..\Unit Tests\Data\ShortMsgKAT_SHAKE256.txt');
  // SourceEnd

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '46b9dd2b0ba88d13233b3feb743eeb243fcd52' +
                                       'ea62b81b82b50c27646ed5762fd75dc4ddd8c0' +
                                       'f200cb05019d67b592f6fc821c49479ab48640' +
                                       '292eacb3b7c4be141e96616fb13957692cc7ed' +
                                       'd0b45ae3dc07223c8e92937bef84bc0eab8628' +
                                       '53349ec75546f58fb7c2775c38462c5010d846' +
                                       'c185c15111e595522a6bcd16cf86f3d122109e' +
                                       '3b1fdd943b6aec468a2d621a7c06c6a957c62b' +
                                       '54dafc3be87567d677231395f6147293b68cea' +
                                       'b7a9e0c58d864e8efde4e1b9a46cbe85471367' +
                                       '2f5caaae314ed9083dab4b099f8e300f01b865' +
                                       '0f1f4b1d8fcf3f3cb53fb8e9eb2ea203bdc970' +
                                       'f50ae55428a91f7f53ac266b28419c3778a15f' +
                                       'd248d339ede785fb7f5a1aaa96d313eacc8909' +
                                       '36c173cdcd0fab882c45755feb3aed96d477ff' +
                                       '96390bf9a66d1368b208e21f7c10d04a3dbd4e' +
                                       '360633e5db4b602601c14cea737db3dcf72263' +
                                       '2cc77851cbdde2aaf0a33a07b373445df490cc' +
                                       '8fc1e4160ff118378f11f0477de055a81a9eda' +
                                       '57a4a2cfb0c83929d310912f729ec6cfa36c6a' +
                                       'c6a75837143045d791cc85eff5b21932f23861' +
                                       'bcf23a52b5da67eaf7baae0f5fb1369db78f3a' +
                                       'c45f8c4ac5671d85735cdddb09d2b1e34a1fc0' +
                                       '66ff4a162cb263d6541274ae2fcc865f618abe' +
                                       '27c124cd8b074ccd516301b91875824d09958f' +
                                       '341ef274bdab0bae316339894304e35877b0c2' +
                                       '8a9b1fd166c796b9cc258a064a8f57e27f2a';

  lDataRow.ExpectedOutputUTFStrTest := '46b9dd2b0ba88d13233b3feb743eeb243fcd52' +
                                       'ea62b81b82b50c27646ed5762fd75dc4ddd8c0' +
                                       'f200cb05019d67b592f6fc821c49479ab48640' +
                                       '292eacb3b7c4be141e96616fb13957692cc7ed' +
                                       'd0b45ae3dc07223c8e92937bef84bc0eab8628' +
                                       '53349ec75546f58fb7c2775c38462c5010d846' +
                                       'c185c15111e595522a6bcd16cf86f3d122109e' +
                                       '3b1fdd943b6aec468a2d621a7c06c6a957c62b' +
                                       '54dafc3be87567d677231395f6147293b68cea' +
                                       'b7a9e0c58d864e8efde4e1b9a46cbe85471367' +
                                       '2f5caaae314ed9083dab4b099f8e300f01b865' +
                                       '0f1f4b1d8fcf3f3cb53fb8e9eb2ea203bdc970' +
                                       'f50ae55428a91f7f53ac266b28419c3778a15f' +
                                       'd248d339ede785fb7f5a1aaa96d313eacc8909' +
                                       '36c173cdcd0fab882c45755feb3aed96d477ff' +
                                       '96390bf9a66d1368b208e21f7c10d04a3dbd4e' +
                                       '360633e5db4b602601c14cea737db3dcf72263' +
                                       '2cc77851cbdde2aaf0a33a07b373445df490cc' +
                                       '8fc1e4160ff118378f11f0477de055a81a9eda' +
                                       '57a4a2cfb0c83929d310912f729ec6cfa36c6a' +
                                       'c6a75837143045d791cc85eff5b21932f23861' +
                                       'bcf23a52b5da67eaf7baae0f5fb1369db78f3a' +
                                       'c45f8c4ac5671d85735cdddb09d2b1e34a1fc0' +
                                       '66ff4a162cb263d6541274ae2fcc865f618abe' +
                                       '27c124cd8b074ccd516301b91875824d09958f' +
                                       '341ef274bdab0bae316339894304e35877b0c2' +
                                       '8a9b1fd166c796b9cc258a064a8f57e27f2a';
  lDataRow.HashResultByteLength     := 512;
  lDataRow.AddInputVector('');
  lDataRow.FinalBitLength := 0;

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '807b2445e62e7e5c2a1a701b065a4c05b500b9' +
                                       'e34b1b26bc3a014f9c7d03935ea9e3b06631df' +
                                       'c57e33b60b31c8a0c886e1c4665faf272a12cd' +
                                       '9cf0bd1a3bc69703fbf9e1816c618cb8e917b3' +
                                       'fb59aa93937c892eed9082076aefc8ad23d04a' +
                                       '1bed882fa743cbefc517aa20040eb71e209ad5' +
                                       'e7db5a78d8bd2786f7b3a04190ca39cf3f8660' +
                                       'be6346eb7bf77fd2524b10405e92e37a10b67f' +
                                       '80cb4222be9e0019d33094057306e7ba6539a7' +
                                       '13948e97618a5ca6ff014aa79250b517bc8556' +
                                       '7f4451de22e6cfe3d98d52391349ffe68c6e8f' +
                                       'dc958295aff3ff2f0a8aeff2e3d46ac2baf871' +
                                       '1cda4df06c245df4da8c2b0d722c1363a94c38' +
                                       'f24b63021126505241ca85a03c5731c0b70149' +
                                       'c10545a1a7b5d9ca7dd1c18158884d4c37a40e' +
                                       '0ab2b97180274a02db7025d232cee6a8d9d4a2' +
                                       'c652d33383fe05ba439659b80309b69faa71f7' +
                                       '00d550a0d1d0a0efe3f67ada02e2d9ba8a7f2e' +
                                       '416e89a3e3cb37de73838dd753aa93647cabfb' +
                                       'b2a99c9fea2d9d0e02b0829294c6f4367b4d09' +
                                       'e213cf2e11dddf0c4c00d6167e81738518e0b4' +
                                       'abfbd34d2655a3553fba1756f6094743c406e5' +
                                       'ad5de5fdda11242306c52faa87540816df9314' +
                                       '4f77c1d8ea958c73f8d47bc4cacec1105452c4' +
                                       '47fe940c8a9e949842c3d7c2ef5e27fd1a2087' +
                                       'dd4e008fc23dd654e46951b7e782d987f8d1f1' +
                                       '29b13e98b3def7072ef5f6c1887a8ddbaa33';
  lDataRow.ExpectedOutputUTFStrTest := 'f55ac9e264ca9a6f6da7a38673cd565e012963' +
                                       'b8f76714a8e29b7a9c260380dfd1609cdcf265' +
                                       '8e8aff9a9e67d41f8a859600fdc28b7b8120d3' +
                                       '1fb43574ccc24faec89376d7696b6b2e998730' +
                                       '70159287b8e70a6fbf9ba9e181ce294e70d9c8' +
                                       '61951bf5ce40e91a71bbf78f00c4726c59aa5e' +
                                       'b38ef10ddf9f23767a68f4afbac8caba04494d' +
                                       '9bb4c6a6a8dfaf12e4eb65dbc697f665e1e630' +
                                       '774d777696ddc79ec0ef528a493cc82adfbb91' +
                                       'a218f4d0d5cbdf072f6e95b88f1778679066a3' +
                                       'ff4ec286a4b2cc0fa3f3729c42fb70d3563cd9' +
                                       '43144018199bf2f43c76ba19e3ef824dba6996' +
                                       '0786a8fff7398fc33519b4032cccce970172c7' +
                                       '354ac3e0826bdd34cb4fcd238ba80076586a7a' +
                                       '7767cf2408f1936d058787027c09630325d37e' +
                                       '7156c2a2a3f200e67b77802488a5558d276444' +
                                       '3a0727a4fbee7245ef21d1def66c8baa89294d' +
                                       'f3e8c31cce30b5bd86c9da303ea5ec806cf015' +
                                       'f82203426e6d2cece44b974b7378acaadee472' +
                                       '1710cb05f640d93a421bc8be93a551a4a8767d' +
                                       '888a497a9cde8c00f84b62bdaa07db0e1d817c' +
                                       'c23be18711422ef0cc86336755effca31073fc' +
                                       '289ee7b43bace5c29d14ad5a9c092aa2ac13af' +
                                       'e6eade2b167448dc8ee1c2d3babb7f5017bb4f' +
                                       '854f4ce68c3ccf97215dc4059e7d7da56f1465' +
                                       '373abb45a714a7b896dfdb9c5b886c2926192b' +
                                       '29e181a3de25c9180729e6c357d0a6edc858';

  lDataRow.HashResultByteLength     := 512;
  lDataRow.AddInputVector(TFormat_HEXL.Decode('0372cd1ce0b74ce05e717fc4b9a82ce1a' +
                                              '888f4ef7b0027a5d6dc5f8d13936e01'));
  lDataRow.FinalBitLength := 2;
end;

procedure TestTHash_Shake256.TestBlockSize;
begin
  CheckEquals(136, FHash.BlockSize);
end;

procedure TestTHash_Shake256.TestClassByName;
begin
  DoTestClassByName('THash_Shake256', THash_Shake256);
end;

procedure TestTHash_Shake256.TestDigestSize;
begin
  CheckEquals(0, FHash.DigestSize);
end;

procedure TestTHash_Shake256.TestIdentity;
begin
  CheckEquals($871E76B7, FHash.Identity);
end;

procedure TestTHash_Shake256.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_Shake256.SetLength0Test;
var
  Shake: THash_Shake256;
begin
  Shake := THash_Shake256.Create;
  try
    Shake.HashSize := 0;
  finally
    Shake.Free;
  end;
end;

procedure TestTHash_Shake256.TestLength0;
begin
  CheckException(SetLength0Test, EDECHashException);
end;

{ TestTHash_Keccak_Base }

procedure TestTHash_Keccak_Base.AddLastByteForCodeTest(var lDataRow    : IHashTestDataRowSetup;
                                                       SHA3InputVector : RawByteString;
                                                       LastByteLength  : UInt8);
var
  LastByteLen  : UInt8;
  MsgWithFixup : RawByteString;
begin
  lDataRow.FinalBitLength := LastByteLength;
  LastByteLen             := LastByteLength;
  MsgWithFixup            := AddLastByteForKeccakTest(SHA3InputVector, LastByteLen);
  lDataRow.AddInputVector(MsgWithFixup);
  lDataRow.FinalBitLength := LastByteLen;

  THash_SHA3Base(FHash).FinalByteLength := LastByteLen;

  lDataRow.ExpectedOutputUTFStrTest :=
            CalcUnicodeHash(string(TFormat_HexL.Encode(MsgWithFixup)), FHash);
end;

function TestTHash_Keccak_Base.AddLastByteForKeccakTest(SHA3InputVector    : RawByteString;
                                                        var LastByteLength : UInt8): RawByteString;
var
  lastbyte : UInt8;
begin
  case LastByteLength of
  0 : begin // ist ok
        SHA3InputVector := SHA3InputVector + chr($02);
        LastByteLength := 2;
      end;
  1..6 :
      begin
        lastbyte := UInt8(SHA3InputVector[High(SHA3InputVector)]);
        // in lastbyte 0 an stelle fblSHA3 einfügen:
        lastbyte := lastbyte and (( 1 shl LastByteLength ) xor $FF);
        // in lastbyte 1 an stelle fblSHA3+1 einfügen:
        lastbyte := lastbyte or BYTE( 1 shl (LastByteLength + 1));
        SHA3InputVector[High(SHA3InputVector)] := Ansichar(lastbyte);
        if LastByteLength < 6 then
          inc(LastByteLength,2)
        else
          LastByteLength := 0;
      end;
  7 : begin // ist ok
        // 0 anhängen - es könnte sein, dass in mSHA3 eine 1 steht
        // wenn man sicher ist, dass dies nie der Fall ist, dann kann
        // man auf die vier Zeilen verzichten
        lastbyte := UInt8(SHA3InputVector[High(SHA3InputVector)]);
        lastbyte := lastbyte and $7F; // evt vorhandene 1 an vorderster Stelle löschen
        SHA3InputVector[High(SHA3InputVector)] := Ansichar(lastbyte);

        SHA3InputVector := SHA3InputVector + chr($01);
        LastByteLength := 1;
      end;
  end;

  Result := SHA3InputVector;
end;

{ TestTHash_Keccak_224 }

procedure TestTHash_Keccak_224.ConfigHashClass(HashClass: TDECHash;
  IdxTestData: Integer);
begin
  inherited;

  THash_Keccak_224(FHash).FinalByteLength := FTestData[IdxTestData].FinalByteBitLength;
end;

procedure TestTHash_Keccak_224.SetUp;
var
  lDataRow : IHashTestDataRowSetup;
//  i        : Integer;
//  s        : RawByteString;
begin
  // All specified data sources are for the non unicode expected outputs
  inherited;
  FHash := THash_Keccak_224.Create;

  //Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-
  //       Validation-Program/documents/sha3/sha-3bittestvectors.zip
  FTestFileNames.Add('..\..\Unit Tests\Data\SHA3_224ShortMsg.rsp');
  FTestFileNames.Add('..\..\Unit Tests\Data\SHA3_224LongMsg.rsp');
  // SourceEnd

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-224_Msg5.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'ffbad5da96bad71789330206dc6768ecaeb1b32d' +
                                       'ca6b3301489674ab';
  AddLastByteForCodeTest(lDataRow, #$13, 5);

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-224_Msg30.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd666a514cc9dba25ac1ba69ed3930460deaac985' +
                                       '1b5f0baab007df3b';
  AddLastByteForCodeTest(lDataRow, #$53#$58#$7B#$19, 6);

// Commented out because AddLastByteForCodeTest cannot handle the 1, 20 syntax
//  // Source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
//  //         and-Guidelines/documents/examples/SHA3-224_1600.pdf
//  lDataRow := FTestData.AddRow;
//  lDataRow.ExpectedOutput           := '9376816aba503f72f96ce7eb65ac095deee3be4b' +
//                                       'f9bbc2a1cb7e11e0';
//  lDataRow.ExpectedOutputUTFStrTest := '28a4a80fded04a676674687c8330422eedeb18c9' +
//                                       'dba976234a9e007a';
//  lDataRow.AddInputVector(RawByteString(#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3), 1, 20);
//  lDataRow.FinalBitLength := 0;
//
//  // Source: https://emn178.github.io/online-tools/sha3_224.html
//  lDataRow := FTestData.AddRow;
//  lDataRow.ExpectedOutput           := '32eb6a4121daebe223db1987740814e1dd9d9ddb' +
//                                       'ddfd466feff5c9b4';
//  lDataRow.ExpectedOutputUTFStrTest := '0f1ad8cd5a85fe68319b67427e1f0b685498bc24' +
//                                       '6a81a1f595c89e4e';
//  lDataRow.AddInputVector(RawByteString('e21et2e2et1208e7t12e07812te08127et1028e' +
//                                        '7t1208e7gd81d872t178r02tr370823'), 1, 10);
//  lDataRow.FinalBitLength := 0;

//  lDataRow := FTestData.AddRow;
//  lDataRow.ExpectedOutput           := 'f7fc914c8fe4827d866b02df2459840260f4adb0' +
//                                       'db4deb9fa661756c';
//  lDataRow.ExpectedOutputUTFStrTest := 'e4d44bbda0b8fc8a73b421f6795c6380c0e21d50' +
//                                       '539a7b43c20a7529';
//
//   for i := 1 to 10 do
//     s := s + 'e21et2e2et1208e7t12e07812te08127et1028e7t1208e7gd81d872t178r02tr370823';
//   s := s + 'TurboMagic';
//   s := s + s + s;
//
//  lDataRow.AddInputVector(s);
//  lDataRow.FinalBitLength := 0;


  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-224_Msg1605.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '22d2f7bb0b173fd8c19686f9173166e3ee627380' +
                                       '47d7eadd69efb228';

  AddLastByteForCodeTest(lDataRow, RawByteString(
                                     #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                     #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                     #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                     #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                     #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                     #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                     #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                     #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                     #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                     #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                     #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                     #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                     #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                     #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                     #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                     #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                     #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                     #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                     #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                     #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                     #$A3), 5);

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-224_1630.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4e907bb1057861f200a599e9d4f85b02d88453bf' +
                                       '5b8ace9ac589134c';
  AddLastByteForCodeTest(lDataRow, RawByteString(
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3), 6);
end;

procedure TestTHash_Keccak_224.TestBlockSize;
begin
  CheckEquals(144, FHash.BlockSize);
end;

procedure TestTHash_Keccak_224.TestClassByName;
begin
  DoTestClassByName('THash_Keccak_224', THash_Keccak_224);
end;

procedure TestTHash_Keccak_224.TestDigestSize;
begin
  CheckEquals(28, FHash.DigestSize);
end;

procedure TestTHash_Keccak_224.TestIdentity;
begin
  CheckEquals($5F9A1BC1, FHash.Identity);
end;

procedure TestTHash_Keccak_224.TestFinalByteLength;
var
  Hash_Keccack_224 : THash_Keccak_224;
  i                : Integer;
begin
  Hash_Keccack_224 := THash_Keccak_224.Create;
  try
    for i := 0 to 7 do
    begin
      Hash_Keccack_224.FinalByteLength := i;
      CheckEquals(i, Hash_Keccack_224.FinalByteLength);
    end;
  finally
    Hash_Keccack_224.Free;
  end;
end;

procedure TestTHash_Keccak_224.TestFinalByteLengthOverflow;
begin
  CheckException(TestFinalByteLengthOverflowHelper, EDECHashException);
end;

procedure TestTHash_Keccak_224.TestFinalByteLengthOverflowHelper;
var
  Hash_Keccack_224 : THash_Keccak_224;
begin
  Hash_Keccack_224 := THash_Keccak_224.Create;
  try
    Hash_Keccack_224.FinalByteLength := 8;
    CheckEquals(8, Hash_Keccack_224.FinalByteLength);
  finally
    Hash_Keccack_224.Free;
  end;
end;

procedure TestTHash_Keccak_224.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

{ TestTHash_Keccak_256 }

procedure TestTHash_Keccak_256.ConfigHashClass(HashClass: TDECHash;
  IdxTestData: Integer);
begin
  inherited;

  THash_Keccak_256(FHash).FinalByteLength := FTestData[IdxTestData].FinalByteBitLength;
end;

procedure TestTHash_Keccak_256.SetUp;
var
  lDataRow:IHashTestDataRowSetup;
begin
  // All specified data sources are for the non unicode expected outputs
  inherited;
  FHash := THash_Keccak_256.Create;

  //Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-
  //       Validation-Program/documents/sha3/sha-3bittestvectors.zip
  FTestFileNames.Add('..\..\Unit Tests\Data\SHA3_256ShortMsg.rsp');
  FTestFileNames.Add('..\..\Unit Tests\Data\SHA3_256LongMsg.rsp');
  // SourceEnd

//  // Source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
//  //         and-Guidelines/documents/examples/SHA3-224_1600.pdf
//  lDataRow := FTestData.AddRow;
//  lDataRow.ExpectedOutput           := '79f38adec5c20307a98ef76e8324afbfd46cfd81' +
//                                       'b22e3973c65fa1bd9de31787';
//  lDataRow.ExpectedOutputUTFStrTest := '06ea5e186dab1b3f99bcf91918b53748367674c0' +
//                                       '5baa627010fba06edb67f0ba';
//  lDataRow.AddInputVector(RawByteString(
//                          #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3), 1, 20);
//  lDataRow.FinalBitLength := 0;

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-256_Msg5.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '7b0047cf5a456882363cbf0fb05322cf65f4b705' +
                                       '9a46365e830132e3b5d957af';
  AddLastByteForCodeTest(lDataRow, #$13, 5);

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-256_Msg30.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c8242fef409e5ae9d1f1c857ae4dc624b92b1980' +
                                       '9f62aa8c07411c54a078b1d0';
  AddLastByteForCodeTest(lDataRow, #$53#$58#$7B#$19, 6);

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-256_Msg1605.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '81ee769bed0950862b1ddded2e84aaa6ab7bfdd3' +
                                       'ceaa471be31163d40336363c';
  AddLastByteForCodeTest(lDataRow, RawByteString(
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3), 5);

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-256_1630.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '52860aa301214c610d922a6b6cab981ccd06012e' +
                                       '54ef689d744021e738b9ed20';
  AddLastByteForCodeTest(lDataRow, RawByteString(
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3), 6);
end;

procedure TestTHash_Keccak_256.TestBlockSize;
begin
  CheckEquals(136, FHash.BlockSize);
end;

procedure TestTHash_Keccak_256.TestClassByName;
begin
  DoTestClassByName('THash_Keccak_256', THash_Keccak_256);
end;

procedure TestTHash_Keccak_256.TestDigestSize;
begin
  CheckEquals(32, FHash.DigestSize);
end;

procedure TestTHash_Keccak_256.TestIdentity;
begin
  CheckEquals($FED5EC2A, FHash.Identity);
end;

procedure TestTHash_Keccak_256.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

{ TestTHash_Keccak_384 }

procedure TestTHash_Keccak_384.ConfigHashClass(HashClass: TDECHash;
  IdxTestData: Integer);
begin
  inherited;

  THash_Keccak_384(FHash).FinalByteLength := FTestData[IdxTestData].FinalByteBitLength;
end;

procedure TestTHash_Keccak_384.SetUp;
var
  lDataRow:IHashTestDataRowSetup;
begin
  inherited;
  FHash := THash_Keccak_384.Create;

  //Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-
  //       Validation-Program/documents/sha3/sha-3bittestvectors.zip
  FTestFileNames.Add('..\..\Unit Tests\Data\SHA3_384ShortMsg.rsp');
  FTestFileNames.Add('..\..\Unit Tests\Data\SHA3_384LongMsg.rsp');
  // SourceEnd

//  // Source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
//  //         and-Guidelines/documents/examples/SHA3-384_1600.pdf
//  lDataRow := FTestData.AddRow;
//  lDataRow.ExpectedOutput           := '1881de2ca7e41ef95dc4732b8f5f002b189cc1e4' +
//                                       '2b74168ed1732649ce1dbcdd76197a31fd55ee98' +
//                                       '9f2d7050dd473e8f';
//  lDataRow.ExpectedOutputUTFStrTest := '50dd07a64dc6ff190db60e612d8511742baa8eb5' +
//                                       'a499a0a02e51cea3f4b922f8ecf72785dc0a2ef3' +
//                                       '8230340378d3d104';
//  lDataRow.AddInputVector(RawByteString(
//                          #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3), 1, 20);
//  lDataRow.FinalBitLength := 0;

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-384_Msg5.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '737c9b491885e9bf7428e792741a7bf8dca96534' +
                                       '71c3e148473f2c236b6a0a6455eb1dce9f779b4b' +
                                       '6b237fef171b1c64';
  AddLastByteForCodeTest(lDataRow, #$13, 5);

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-384_Msg30.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '955b4dd1be03261bd76f807a7efd432435c41736' +
                                       '2811b8a50c564e7ee9585e1ac7626dde2fdc030f' +
                                       '876196ea267f08c3';
  AddLastByteForCodeTest(lDataRow, #$53#$58#$7B#$19, 6);

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-384_Msg1605.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'a31fdbd8d576551c21fb1191b54bda65b6c5fe97' +
                                       'f0f4a69103424b43f7fdb835979fdbeae8b3fe16' +
                                       'cb82e587381eb624';
  AddLastByteForCodeTest(lDataRow, RawByteString(
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3), 5);

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-384_1630.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '3485d3b280bd384cf4a777844e94678173055d1c' +
                                       'bc40c7c2c3833d9ef12345172d6fcd31923bb879' +
                                       '5ac81847d3d8855c';
  AddLastByteForCodeTest(lDataRow, RawByteString(
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3), 6);
end;

procedure TestTHash_Keccak_384.TestBlockSize;
begin
  CheckEquals(104, FHash.BlockSize);
end;

procedure TestTHash_Keccak_384.TestClassByName;
begin
  DoTestClassByName('THash_Keccak_384', THash_Keccak_384);
end;

procedure TestTHash_Keccak_384.TestDigestSize;
begin
  CheckEquals(48, FHash.DigestSize);
end;

procedure TestTHash_Keccak_384.TestIdentity;
begin
  CheckEquals($A4B7997C, FHash.Identity);
end;

procedure TestTHash_Keccak_384.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

{ TestTHash_Keccak_512 }

procedure TestTHash_Keccak_512.ConfigHashClass(HashClass: TDECHash;
  IdxTestData: Integer);
begin
  inherited;

  THash_Keccak_512(FHash).FinalByteLength := FTestData[IdxTestData].FinalByteBitLength;
end;

procedure TestTHash_Keccak_512.SetUp;
var
  lDataRow : IHashTestDataRowSetup;
begin
  inherited;
  FHash := THash_Keccak_512.Create;

  //Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-
  //       Validation-Program/documents/sha3/sha-3bittestvectors.zip
  FTestFileNames.Add('..\..\Unit Tests\Data\SHA3_512ShortMsg.rsp');
  FTestFileNames.Add('..\..\Unit Tests\Data\SHA3_512LongMsg.rsp');
  // SourceEnd

//  // Source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
//  //         and-Guidelines/documents/examples/SHA3-512_1600.pdf
//  lDataRow := FTestData.AddRow;
//  lDataRow.ExpectedOutput           := 'e76dfad22084a8b1467fcf2ffa58361bec7628ed' +
//                                       'f5f3fdc0e4805dc48caeeca81b7c13c30adf52a3' +
//                                       '659584739a2df46be589c51ca1a4a8416df6545a' +
//                                       '1ce8ba00';
//  lDataRow.ExpectedOutputUTFStrTest := '54ab223a7cee7603f2b89596b54f8d838845e0a0' +
//                                       'af2be3e9ad2cd7acb111757cb0c41b3564c07778' +
//                                       '47684435da78577781eef8e6a6652c9844a85882' +
//                                       'e0fa8b28';
//  lDataRow.AddInputVector(RawByteString(
//                          #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3), 1, 20);
//  lDataRow.FinalBitLength := 0;

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-512_Msg5.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'a13e01494114c09800622a70288c432121ce7003' +
                                       '9d753cadd2e006e4d961cb27544c1481e5814bdc' +
                                       'eb53be6733d5e099795e5e81918addb058e22a9f' +
                                       '24883f37';
  AddLastByteForCodeTest(lDataRow, #$13, 5);

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-512_Msg30.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '9834c05a11e1c5d3da9c740e1c106d9e590a0e53' +
                                       '0b6f6aaa7830525d075ca5db1bd8a6aa981a2861' +
                                       '3ac334934a01823cd45f45e49b6d7e6917f2f167' +
                                       '78067bab';
  AddLastByteForCodeTest(lDataRow, #$53#$58#$7B#$19, 6);

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-512_Msg1605.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'fc4a167ccb31a937d698fde82b04348c9539b28f' +
                                       '0c9d3b4505709c03812350e4990e9622974f6e57' +
                                       '5c47861c0d2e638ccfc2023c365bb60a93f52855' +
                                       '0698786b';
  AddLastByteForCodeTest(lDataRow, RawByteString(
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3), 5);

  // Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-
  //        and-Guidelines/documents/examples/SHA3-512_1630.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'cf9a30ac1f1f6ac0916f9fef1919c595debe2ee8' +
                                       '0c85421210fdf05f1c6af73aa9cac881d0f91db6' +
                                       'd034a2bbadc1cf7fbcb2ecfa9d191d3a5016fb3f' +
                                       'ad8709c9';
  AddLastByteForCodeTest(lDataRow, RawByteString(
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3#$A3 +
                                      #$A3#$A3#$A3#$A3), 6);
end;

procedure TestTHash_Keccak_512.TestBlockSize;
begin
  CheckEquals(72, FHash.BlockSize);
end;

procedure TestTHash_Keccak_512.TestClassByName;
begin
  DoTestClassByName('THash_Keccak_512', THash_Keccak_512);
end;

procedure TestTHash_Keccak_512.TestDigestSize;
begin
  CheckEquals(64, FHash.DigestSize);
end;

procedure TestTHash_Keccak_512.TestIdentity;
begin
  CheckEquals($989BFBB2, FHash.Identity);
end;

procedure TestTHash_Keccak_512.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

initialization
  // Register any test cases with the test runner
  {$IFDEF DUnitX}
  TDUnitX.RegisterTestFixture(TestTHash_SHA3_224);
  TDUnitX.RegisterTestFixture(TestTHash_SHA3_256);
  TDUnitX.RegisterTestFixture(TestTHash_SHA3_384);
  TDUnitX.RegisterTestFixture(TestTHash_SHA3_512);
  TDUnitX.RegisterTestFixture(TestTHash_Shake128);
  TDUnitX.RegisterTestFixture(TestTHash_Shake256);
  TDUnitX.RegisterTestFixture(TestTHash_Keccak_224);
  TDUnitX.RegisterTestFixture(TestTHash_Keccak_256);
  TDUnitX.RegisterTestFixture(TestTHash_Keccak_384);
  TDUnitX.RegisterTestFixture(TestTHash_Keccak_512);
  {$ELSE}
  RegisterTests('DECHash', [TestTHash_SHA3_224.Suite,
                            TestTHash_SHA3_256.Suite,
                            TestTHash_SHA3_384.Suite,
                            TestTHash_SHA3_512.Suite,
                            TestTHash_Shake128.Suite,
                            TestTHash_Shake256.Suite,
                            TestTHash_Keccak_224.Suite,
                            TestTHash_Keccak_256.Suite,
                            TestTHash_Keccak_384.Suite,
                            TestTHash_Keccak_512.Suite]);
  {$ENDIF}

end.
