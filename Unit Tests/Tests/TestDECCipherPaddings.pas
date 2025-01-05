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
unit TestDECCipherPaddings;

// Needs to be included before any other statements
{$INCLUDE TestDefines.inc}

interface

uses
  System.SysUtils, System.Classes, Generics.Collections,
  {$IFDEF DUnitX}
  DUnitX.TestFramework,DUnitX.DUnitCompatibility,
  {$ELSE}
  TestFramework,
  {$ENDIF}
  DECCipherPaddings, DECUtil;

type
  TPaddingTestData = record
    InputData    : RawByteString;
    OutputData   : RawByteString;
    BlockSize    : integer;
  end;

  /// <summary>
  ///   Base class for all padding test classes which contains code to load the
  ///  test data
  ///  </summary>
  TestTPaddingBase = class(TTestCase)
  strict protected
  end;

  // Test methods for class TPKCS7Padding
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTPKCS7Padding = class(TestTPaddingBase)
  strict private
    FValidTestData: TArray<TPaddingTestData>;
    FNegativeTestData: TArray<TPaddingTestData>;
  public
    procedure SetUp; override;
  published
    procedure TestAddPadding_RawByteString;
    procedure TestRemovePadding_RawByteString;
    procedure TestAddPadding_Bytes;
    procedure TestRemovePadding_Bytes;
    procedure TestHasValidPadding_Bytes;
  end;

  // Test methods for class TANSI_X9_23Padding
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTANSI_X9_23Padding = class(TestTPaddingBase)
  strict private
  public
  published
  end;

  // Test methods for class TANSI_X9_23Padding_Legacy
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTANSI_X9_23Padding_Legacy = class(TestTPaddingBase)
  strict private
  public
  published
  end;


// {, pmISO10126, pmISO7816

implementation

{ TestTDECPKCS7Padding }

procedure TestTPKCS7Padding.SetUp;
begin
  inherited;
  SetLength(FValidTestData, 15);
  FValidTestData[0].BlockSize := 8;
  FValidTestData[0].InputData := '';
  FValidTestData[0].OutputData := #8#8#8#8#8#8#8#8;

  FValidTestData[1].BlockSize := 8;
  FValidTestData[1].InputData := 'V';
  FValidTestData[1].OutputData := 'V'#7#7#7#7#7#7#7;

  FValidTestData[2].BlockSize := 8;
  FValidTestData[2].InputData := 'no';
  FValidTestData[2].OutputData := 'no'#6#6#6#6#6#6;

  FValidTestData[3].BlockSize := 8;
  FValidTestData[3].InputData := 'Cow';
  FValidTestData[3].OutputData := 'Cow'#5#5#5#5#5;

  FValidTestData[4].BlockSize := 8;
  FValidTestData[4].InputData := 'Hell';
  FValidTestData[4].OutputData := 'Hell'#4#4#4#4;

  FValidTestData[5].BlockSize := 8;
  FValidTestData[5].InputData := 'Hello';
  FValidTestData[5].OutputData := 'Hello'#3#3#3;

  FValidTestData[6].BlockSize := 8;
  FValidTestData[6].InputData := 'Hello ';
  FValidTestData[6].OutputData := 'Hello '#2#2;

  FValidTestData[7].BlockSize := 8;
  FValidTestData[7].InputData := 'HellO V';
  FValidTestData[7].OutputData := 'HellO V'#1;

  FValidTestData[8].BlockSize := 8;
  FValidTestData[8].InputData := 'HELLO Vi';
  FValidTestData[8].OutputData := 'HELLO Vi'#8#8#8#8#8#8#8#8;

  FValidTestData[9].BlockSize := 16;
  FValidTestData[9].InputData := '';
  FValidTestData[9].OutputData := #16#16#16#16#16#16#16#16#16#16#16#16#16#16#16#16;

  FValidTestData[10].BlockSize := 16;
  FValidTestData[10].InputData := 'a';
  FValidTestData[10].OutputData := 'a'#15#15#15#15#15#15#15#15#15#15#15#15#15#15#15;

  FValidTestData[11].BlockSize := 16;
  FValidTestData[11].InputData := 'ICE ICE BABY';
  FValidTestData[11].OutputData := 'ICE ICE BABY'#4#4#4#4;

  FValidTestData[12].BlockSize := 16;
  FValidTestData[12].InputData := 'ICE ICE BABY GO';
  FValidTestData[12].OutputData := 'ICE ICE BABY GO'#1;

  FValidTestData[13].BlockSize := 16;
  FValidTestData[13].InputData := 'ICE ICE BABY GOg';
  FValidTestData[13].OutputData := 'ICE ICE BABY GOg'#16#16#16#16#16#16#16#16#16#16#16#16#16#16#16#16;

  FValidTestData[14].BlockSize := 24;
  FValidTestData[14].InputData := '';
  FValidTestData[14].OutputData := #24#24#24#24#24#24#24#24#24#24#24#24#24#24#24#24#24#24#24#24#24#24#24#24;

  SetLength(FNegativeTestData, 4);
  FNegativeTestData[0].BlockSize := 8;
  FNegativeTestData[0].InputData := '';
  FNegativeTestData[0].OutputData := '';

  FNegativeTestData[1].BlockSize := 8;
  FNegativeTestData[1].InputData := 'no';
  FNegativeTestData[1].OutputData := 'no'#1#2#3#4#5#6;

  FNegativeTestData[2].BlockSize := 8;
  FNegativeTestData[2].InputData := 'HELLO Vi';
  FNegativeTestData[2].OutputData := 'HELLO Vi';

  FNegativeTestData[3].BlockSize := 16;
  FNegativeTestData[3].InputData := 'ICE ICE BABY';
  FNegativeTestData[3].OutputData := 'ICE ICE BABY'#3#4#4#4;
end;

procedure TestTPKCS7Padding.TestAddPadding_RawByteString;
var
  I: integer;
  Res: RawByteString;
begin
  for I := Low(FValidTestData) to High(FValidTestData) do
  begin
    Res := TPKCS7Padding.AddPadding(FValidTestData[I].InputData,
      FValidTestData[I].BlockSize);
    CheckEquals(Res, FValidTestData[I].OutputData,
      'Valid test data set ' + I.ToString + ' failed');
  end;
  Status(length(FValidTestData).ToString + ' test pattern passed');
end;

procedure TestTPKCS7Padding.TestRemovePadding_RawByteString;
var
  I: integer;
  Res: RawByteString;
begin
  for I := Low(FValidTestData) to High(FValidTestData) do
  begin
    Res := TPKCS7Padding.RemovePadding(FValidTestData[I].OutputData,
      FValidTestData[I].BlockSize);
    CheckEquals(Res, FValidTestData[I].InputData,
      'Valid test data set ' + I.ToString + ' failed');
  end;
  Status(length(FValidTestData).ToString + ' test pattern passed');
end;

procedure TestTPKCS7Padding.TestAddPadding_Bytes;
var
  I: integer;
  Res: TBytes;
begin
  for I := Low(FValidTestData) to High(FValidTestData) do
  begin
    Res := TPKCS7Padding.AddPadding(DECUtil.RawStringToBytes(FValidTestData[I].InputData),
      FValidTestData[I].BlockSize);
    CheckEquals(DECUtil.BytesToRawString(Res), FValidTestData[I].OutputData,
      'Valid test data set ' + I.ToString + ' failed');
  end;
  Status(length(FValidTestData).ToString + ' test pattern passed');
end;

procedure TestTPKCS7Padding.TestRemovePadding_Bytes;
var
  I: integer;
  Res: TBytes;
begin
  for I := Low(FValidTestData) to High(FValidTestData) do
  begin
    Res := TPKCS7Padding.RemovePadding(DECUtil.RawStringToBytes(FValidTestData[I].OutputData),
      FValidTestData[I].BlockSize);
    CheckEquals(DECUtil.BytesToRawString(Res), FValidTestData[I].InputData,
      'Valid test data set ' + I.ToString + ' failed');
  end;
  Status(length(FValidTestData).ToString + ' test pattern passed');
end;

procedure TestTPKCS7Padding.TestHasValidPadding_Bytes;
var
  I: integer;
begin
  for I := Low(FValidTestData) to High(FValidTestData) do
    CheckTrue(TPKCS7Padding.HasValidPadding(DECUtil.RawStringToBytes(FValidTestData[I].OutputData),
      FValidTestData[I].BlockSize));
  for I := Low(FNegativeTestData) to High(FNegativeTestData) do
    CheckFalse(TPKCS7Padding.HasValidPadding(DECUtil.RawStringToBytes(FNegativeTestData[I].OutputData),
      FNegativeTestData[I].BlockSize));
  Status(length(FValidTestData).ToString + ' positive test pattern passed, ' +
    length(FNegativeTestData).ToString + ' negative test pattern passed');
end;

initialization
  // Register any test cases with the test runner
  {$IFDEF DUnitX}
  TDUnitX.RegisterTestFixture(TestTDECPKCS7Padding);
  TDUnitX.RegisterTestFixture(TestTANSI_X9_23Padding);
  TDUnitX.RegisterTestFixture(TestTANSI_X9_23Padding_Legacy);
  {$ELSE}
  RegisterTests('DECCipherPaddings', [TestTPKCS7Padding.Suite, TestTANSI_X9_23Padding.Suite]);
  {$ENDIF}
end.
