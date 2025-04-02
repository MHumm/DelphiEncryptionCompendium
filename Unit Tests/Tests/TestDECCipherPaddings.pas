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
  DECCipherPaddings, DECTypes, DECUtil;

type
  /// <summary>
  ///   One single test vector
  ///  </summary>
  TPaddingTestData = record
    InputData    : RawByteString;
    OutputData   : RawByteString;
    BlockSize    : integer;
  end;

  /// <summary>
  ///   Base class for all padding test classes which contains code to load the
  ///   test data
  ///  </summary>
  TestTPaddingBase = class(TTestCase)
  strict protected
    FPaddingClass : TDECPaddingClass;
    FValidTestData: TArray<TPaddingTestData>;
    FNegativeTestData: TArray<TPaddingTestData>;
    FValidRemoveTestData: TArray<TPaddingTestData>;
  published
    procedure TestAddPadding_RawByteString; virtual;
    procedure TestRemovePadding_RawByteString; virtual;
    procedure TestRemovePadding_RawByteStringExceptions; virtual;
    procedure TestAddPadding_Bytes; virtual;
    procedure TestRemovePadding_Bytes; virtual;
    procedure TestRemovePadding_BytesExceptions; virtual;
    procedure TestHasValidPadding_Bytes; virtual;
  end;

  /// <summary>
  ///   Test methods for class TPKCS7Padding
  ///  </summary>
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTPKCS7Padding = class(TestTPaddingBase)
  public
    procedure SetUp; override;
  end;

  /// <summary>
  ///   Test methods for class TPKCS5Padding
  ///  </summary>
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTPKCS5Padding = class(TestTPaddingBase)
  public
    procedure SetUp; override;
  end;

  /// <summary>
  ///   Test methods for class TANSI_X9_23Padding
  ///  </summary>
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTANSI_X9_23Padding = class(TestTPaddingBase)
  public
    procedure SetUp; override;
  end;

  /// <summary>
  ///   Test methods for class TISO10126Padding
  ///  </summary>
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTISO10126Padding = class(TestTPaddingBase)
  protected
    function RemoveRandomPadding(const Res, Pattern: RawByteString): RawByteString;
  public
    procedure SetUp; override;
  published
    procedure TestAddPadding_RawByteString; override;
    procedure TestAddPadding_Bytes; override;
  end;

  /// <summary>
  ///   Test methods for class TISO7816Padding
  ///  </summary>
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTISO7816Padding = class(TestTPaddingBase)
  public
    procedure SetUp; override;
  end;

implementation

{ TestTPaddingBase }

procedure TestTPaddingBase.TestAddPadding_RawByteString;
var
  I   : integer;
  Res : RawByteString;
begin
  for I := Low(FValidTestData) to High(FValidTestData) do
  begin
    Res := FPaddingClass.AddPadding(FValidTestData[I].InputData,
                                    FValidTestData[I].BlockSize);

    CheckEquals(Res,
                FValidTestData[I].OutputData,
                'Valid test data set ' + I.ToString + ' failed');
  end;

  Status(length(FValidTestData).ToString + ' test pattern passed');
end;

procedure TestTPaddingBase.TestAddPadding_Bytes;
var
  I   : integer;
  Res : TBytes;
begin
  for I := Low(FValidTestData) to High(FValidTestData) do
  begin
    Res := FPaddingClass.AddPadding(DECUtil.RawStringToBytes(FValidTestData[I].InputData),
                                    FValidTestData[I].BlockSize);

    CheckEquals(DECUtil.BytesToRawString(Res),
                FValidTestData[I].OutputData,
                'Valid test data set ' + I.ToString + ' failed');
  end;

  Status(length(FValidTestData).ToString + ' test pattern passed');
end;

procedure TestTPaddingBase.TestRemovePadding_RawByteString;
var
  I   : integer;
  Res : RawByteString;
begin
  for I := Low(FValidTestData) to High(FValidTestData) do
  begin
    Res := FPaddingClass.RemovePadding(FValidTestData[I].OutputData,
                                       FValidTestData[I].BlockSize);

    CheckEquals(Res,
                FValidTestData[I].InputData,
                'Valid test data set ' + I.ToString + ' failed');
  end;

  Status(length(FValidTestData).ToString + ' test pattern passed');

  // Additional tests, if data is availale
  if length(FValidRemoveTestData) > 0 then
  begin
    for I := Low(FValidRemoveTestData) to High(FValidRemoveTestData) do
    begin
      Res := FPaddingClass.RemovePadding(FValidRemoveTestData[I].OutputData,
                                         FValidRemoveTestData[I].BlockSize);

      CheckEquals(Res,
                  FValidRemoveTestData[I].InputData,
                  'Valid test data set ' + I.ToString + ' failed');
    end;

    Status(length(FValidRemoveTestData).ToString + ' additional remove test pattern passed');
  end;
end;

procedure TestTPaddingBase.TestRemovePadding_RawByteStringExceptions;
var
  I   : integer;
begin
  // Test that faulty data is detected and raises an exception
  for I := Low(FNegativeTestData) to High(FNegativeTestData) do
  begin
    try
      FPaddingClass.RemovePadding(FNegativeTestData[I].OutputData,
                                  FNegativeTestData[I].BlockSize);

      {$IFNDEF DUnitX}
      Fail('Remove padding should return an exception for NegativeTestData[' + I.ToString + ']');
      {$ELSE}
      Assert.Fail('Remove padding should return an exception for NegativeTestData[' + I.ToString + ']');
      {$ENDIF}
    except
      on e: EDECCipherException do
        // expected
    end;
  end;

  Status(length(FNegativeTestData).ToString + ' negative test pattern passed');
end;

procedure TestTPaddingBase.TestRemovePadding_Bytes;
var
  I   : integer;
  Res : TBytes;
begin
  for I := Low(FValidTestData) to High(FValidTestData) do
  begin
    Res := FPaddingClass.RemovePadding(DECUtil.RawStringToBytes(FValidTestData[I].OutputData),
                                       FValidTestData[I].BlockSize);

    CheckEquals(DECUtil.BytesToRawString(Res),
                FValidTestData[I].InputData,
                'Valid test data set ' + I.ToString + ' failed');
  end;

  Status(length(FValidTestData).ToString + ' test pattern passed');

  // Additional tests, if data is availale
  if length(FValidRemoveTestData) > 0 then
  begin
    for I := Low(FValidRemoveTestData) to High(FValidRemoveTestData) do
    begin
      Res := FPaddingClass.RemovePadding(DECUtil.RawStringToBytes(FValidRemoveTestData[I].OutputData),
                                         FValidRemoveTestData[I].BlockSize);

      CheckEquals(DECUtil.BytesToRawString(Res),
                  FValidRemoveTestData[I].InputData,
                  'Valid test data set ' + I.ToString + ' failed');
    end;

    Status(length(FValidRemoveTestData).ToString + ' additional remove test pattern passed');
  end;
end;

procedure TestTPaddingBase.TestRemovePadding_BytesExceptions;
var
  I   : integer;
begin
  // Test that faulty data is detected and raises an exception
  for I := Low(FNegativeTestData) to High(FNegativeTestData) do
  begin
    try
      FPaddingClass.RemovePadding(DECUtil.RawStringToBytes(FNegativeTestData[I].OutputData),
                                  FNegativeTestData[I].BlockSize);

      {$IFNDEF DUnitX}
      Fail('Remove padding should return an exception for NegativeTestData[' + I.ToString + ']');
      {$ELSE}
      Assert.Fail('Remove padding should return an exception for NegativeTestData[' + I.ToString + ']');
      {$ENDIF}
    except
      on e: EDECCipherException do
        // expected
    end;
  end;

  Status(length(FNegativeTestData).ToString + ' negative test pattern passed');
end;

procedure TestTPaddingBase.TestHasValidPadding_Bytes;
var
  I: integer;
begin
  for I := Low(FValidTestData) to High(FValidTestData) do
    CheckTrue(FPaddingClass.HasValidPadding(DECUtil.RawStringToBytes(FValidTestData[I].OutputData),
              FValidTestData[I].BlockSize),
              'ValidTestData failed on ' + I.ToString);

  for I := Low(FNegativeTestData) to High(FNegativeTestData) do
    CheckFalse(FPaddingClass.HasValidPadding(DECUtil.RawStringToBytes(FNegativeTestData[I].OutputData),
               FNegativeTestData[I].BlockSize),
               'NegativeTestData failed on ' + I.ToString);

  for I := Low(FValidRemoveTestData) to High(FValidRemoveTestData) do
    CheckTrue(FPaddingClass.HasValidPadding(DECUtil.RawStringToBytes(FValidRemoveTestData[I].OutputData),
              FValidRemoveTestData[I].BlockSize),
              'ValidRemoveTestData failed on ' + I.ToString);

  Status(length(FValidTestData).ToString + ' positive test pattern passed, ' +
         length(FNegativeTestData).ToString + ' negative test pattern passed, ' +
         length(FValidRemoveTestData).ToString);
end;

{ TestTDECPKCS7Padding }

procedure TestTPKCS7Padding.SetUp;
begin
  inherited;
  FPaddingClass := TPKCS7Padding;

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

  SetLength(FValidRemoveTestData, 0);
end;

{ TestTPKCS5Padding }

procedure TestTPKCS5Padding.SetUp;
begin
  inherited;
  FPaddingClass := TPKCS5Padding;

  SetLength(FValidTestData, 9);
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

  SetLength(FNegativeTestData, 7);
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

  FNegativeTestData[4].BlockSize := 16;
  FNegativeTestData[4].InputData := '';
  FNegativeTestData[4].OutputData := #16#16#16#16#16#16#16#16#16#16#16#16#16#16#16#16;

  FNegativeTestData[5].BlockSize := 16;
  FNegativeTestData[5].InputData := 'a';
  FNegativeTestData[5].OutputData := 'a'#15#15#15#15#15#15#15#15#15#15#15#15#15#15#15;

  FNegativeTestData[6].BlockSize := 16;
  FNegativeTestData[6].InputData := 'ICE ICE BABY';
  FNegativeTestData[6].OutputData := 'ICE ICE BABY'#4#4#4#4;

  SetLength(FValidRemoveTestData, 0);
end;

{ TestTANSI_X9_23Padding }

procedure TestTANSI_X9_23Padding.SetUp;
begin
  inherited;
  FPaddingClass := TANSI_X9_23_Padding;

  SetLength(FValidTestData, 22);
  FValidTestData[0].BlockSize := 8;
  FValidTestData[0].InputData := '';
  FValidTestData[0].OutputData := #0#0#0#0#0#0#0#8;

  FValidTestData[1].BlockSize := 8;
  FValidTestData[1].InputData := '7';
  FValidTestData[1].OutputData := '7'#0#0#0#0#0#0#7;

  FValidTestData[2].BlockSize := 8;
  FValidTestData[2].InputData := '78';
  FValidTestData[2].OutputData := '78'#0#0#0#0#0#6;

  FValidTestData[3].BlockSize := 8;
  FValidTestData[3].InputData := '789';
  FValidTestData[3].OutputData := '789'#0#0#0#0#5;

  FValidTestData[4].BlockSize := 8;
  FValidTestData[4].InputData := '789A';
  FValidTestData[4].OutputData := '789A'#0#0#0#4;

  FValidTestData[5].BlockSize := 8;
  FValidTestData[5].InputData := '789AB';
  FValidTestData[5].OutputData := '789AB'#0#0#3;

  FValidTestData[6].BlockSize := 8;
  FValidTestData[6].InputData := '789ABC';
  FValidTestData[6].OutputData := '789ABC'#0#2;

  FValidTestData[7].BlockSize := 8;
  FValidTestData[7].InputData := '789ABCD';
  FValidTestData[7].OutputData := '789ABCD'#1;

  FValidTestData[8].BlockSize := 8;
  FValidTestData[8].InputData := '789ABCDE';
  FValidTestData[8].OutputData := '789ABCDE'#0#0#0#0#0#0#0#8;

  FValidTestData[9].BlockSize := 8;
  FValidTestData[9].InputData := '789ABCDEF';
  FValidTestData[9].OutputData := '789ABCDEF'#0#0#0#0#0#0#7;

  FValidTestData[10].BlockSize := 8;
  FValidTestData[10].InputData := '789ABCDEFG';
  FValidTestData[10].OutputData := '789ABCDEFG'#0#0#0#0#0#6;

  FValidTestData[11].BlockSize := 8;
  FValidTestData[11].InputData := '789ABCDEFGH';
  FValidTestData[11].OutputData := '789ABCDEFGH'#0#0#0#0#5;

  FValidTestData[12].BlockSize := 8;
  FValidTestData[12].InputData := '789ABCDEFGHI';
  FValidTestData[12].OutputData := '789ABCDEFGHI'#0#0#0#4;

  FValidTestData[13].BlockSize := 8;
  FValidTestData[13].InputData := '789ABCDEFGHIJ';
  FValidTestData[13].OutputData := '789ABCDEFGHIJ'#0#0#3;

  FValidTestData[14].BlockSize := 8;
  FValidTestData[14].InputData := '789ABCDEFGHIJK';
  FValidTestData[14].OutputData := '789ABCDEFGHIJK'#0#2;

  FValidTestData[15].BlockSize := 8;
  FValidTestData[15].InputData := '789ABCDEFGHIJKL';
  FValidTestData[15].OutputData := '789ABCDEFGHIJKL'#1;

  FValidTestData[16].BlockSize := 8;
  FValidTestData[16].InputData := '789ABCDEFGHIJKLM';
  FValidTestData[16].OutputData := '789ABCDEFGHIJKLM'#0#0#0#0#0#0#0#8;

  FValidTestData[17].BlockSize := 16;
  FValidTestData[17].InputData := '';
  FValidTestData[17].OutputData := #0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#16;

  FValidTestData[18].BlockSize := 16;
  FValidTestData[18].InputData := '1';
  FValidTestData[18].OutputData := '1'#0#0#0#0#0#0#0#0#0#0#0#0#0#0#15;

  FValidTestData[19].BlockSize := 16;
  FValidTestData[19].InputData := '123456789ABCDEF';
  FValidTestData[19].OutputData := '123456789ABCDEF'#1;

  FValidTestData[20].BlockSize := 16;
  FValidTestData[20].InputData := '123456789ABCDEFG';
  FValidTestData[20].OutputData := '123456789ABCDEFG'#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#16;

  FValidTestData[21].BlockSize := 16;
  FValidTestData[21].InputData := '123456789ABCDEFGHI';
  FValidTestData[21].OutputData := '123456789ABCDEFGHI'#0#0#0#0#0#0#0#0#0#0#0#0#0#14;

  SetLength(FNegativeTestData, 5);
  FNegativeTestData[0].BlockSize := 8;
  FNegativeTestData[0].InputData := '';
  FNegativeTestData[0].OutputData := '';

  FNegativeTestData[1].BlockSize := 8;
  FNegativeTestData[1].InputData := '7';
  FNegativeTestData[1].OutputData := '7'#0#0#0#0#0#0#9;  // Len > BlockSize

  FNegativeTestData[2].BlockSize := 8;
  FNegativeTestData[2].InputData := '78';
  FNegativeTestData[2].OutputData := '78'#0#0#0#0#0#0#9; // Len mod BlockSize <> 0

  FNegativeTestData[3].BlockSize := 16;
  FNegativeTestData[3].InputData := '123456789ABCDEFGHI';
  FNegativeTestData[3].OutputData := '123456789ABCDEFGHI'#0#0#0#0#0#0#0#0#0#0#0#0#15; // Len mod BlockSize <> 0

  FNegativeTestData[4].BlockSize := 16;
  FNegativeTestData[4].InputData := '123456789ABCDEFGHI';
  FNegativeTestData[4].OutputData := '123456789ABCDEFGHI'#0#0#0#0#0#0#0#0#0#0#0#0#0#17; // Len > BlockSize

  SetLength(FValidRemoveTestData, 4);
  FValidRemoveTestData[0].BlockSize := 8;
  FValidRemoveTestData[0].InputData := '';
  FValidRemoveTestData[0].OutputData := #1#2#3#4#5#6#7#8;

  FValidRemoveTestData[1].BlockSize := 8;
  FValidRemoveTestData[1].InputData := '789ABC';
  FValidRemoveTestData[1].OutputData := '789ABC'#3#2;

  FValidRemoveTestData[2].BlockSize := 8;
  FValidRemoveTestData[2].InputData := '789ABC';
  FValidRemoveTestData[2].OutputData := '789ABC'#127#2;

  FValidRemoveTestData[3].BlockSize := 16;
  FValidRemoveTestData[3].InputData := '123456789ABCDEFGHI';
  FValidRemoveTestData[3].OutputData := '123456789ABCDEFGHI'#127#0#126#1#7#0#0#0#11#0#9#0#0#14;
end;

{ TestTISO10126Padding }

procedure TestTISO10126Padding.SetUp;
begin
  inherited;
  FPaddingClass := TISO10126Padding;

  SetLength(FValidTestData, 22);
  FValidTestData[0].BlockSize := 8;
  FValidTestData[0].InputData := '';
  FValidTestData[0].OutputData := '???????'#8;

  FValidTestData[1].BlockSize := 8;
  FValidTestData[1].InputData := '7';
  FValidTestData[1].OutputData := '7??????'#7;

  FValidTestData[2].BlockSize := 8;
  FValidTestData[2].InputData := '78';
  FValidTestData[2].OutputData := '78?????'#6;

  FValidTestData[3].BlockSize := 8;
  FValidTestData[3].InputData := '789';
  FValidTestData[3].OutputData := '789????'#5;

  FValidTestData[4].BlockSize := 8;
  FValidTestData[4].InputData := '789A';
  FValidTestData[4].OutputData := '789A???'#4;

  FValidTestData[5].BlockSize := 8;
  FValidTestData[5].InputData := '789AB';
  FValidTestData[5].OutputData := '789AB??'#3;

  FValidTestData[6].BlockSize := 8;
  FValidTestData[6].InputData := '789ABC';
  FValidTestData[6].OutputData := '789ABC?'#2;

  FValidTestData[7].BlockSize := 8;
  FValidTestData[7].InputData := '789ABCD';
  FValidTestData[7].OutputData := '789ABCD'#1;

  FValidTestData[8].BlockSize := 8;
  FValidTestData[8].InputData := '789ABCDE';
  FValidTestData[8].OutputData := '789ABCDE???????'#8;

  FValidTestData[9].BlockSize := 8;
  FValidTestData[9].InputData := '789ABCDEF';
  FValidTestData[9].OutputData := '789ABCDEF??????'#7;

  FValidTestData[10].BlockSize := 8;
  FValidTestData[10].InputData := '789ABCDEFG';
  FValidTestData[10].OutputData := '789ABCDEFG?????'#6;

  FValidTestData[11].BlockSize := 8;
  FValidTestData[11].InputData := '789ABCDEFGH';
  FValidTestData[11].OutputData := '789ABCDEFGH????'#5;

  FValidTestData[12].BlockSize := 8;
  FValidTestData[12].InputData := '789ABCDEFGHI';
  FValidTestData[12].OutputData := '789ABCDEFGHI???'#4;

  FValidTestData[13].BlockSize := 8;
  FValidTestData[13].InputData := '789ABCDEFGHIJ';
  FValidTestData[13].OutputData := '789ABCDEFGHIJ??'#3;

  FValidTestData[14].BlockSize := 8;
  FValidTestData[14].InputData := '789ABCDEFGHIJK';
  FValidTestData[14].OutputData := '789ABCDEFGHIJK?'#2;

  FValidTestData[15].BlockSize := 8;
  FValidTestData[15].InputData := '789ABCDEFGHIJKL';
  FValidTestData[15].OutputData := '789ABCDEFGHIJKL'#1;

  FValidTestData[16].BlockSize := 8;
  FValidTestData[16].InputData := '789ABCDEFGHIJKLM';
  FValidTestData[16].OutputData := '789ABCDEFGHIJKLM???????'#8;

  FValidTestData[17].BlockSize := 16;
  FValidTestData[17].InputData := '';
  FValidTestData[17].OutputData := '???????????????'#16;

  FValidTestData[18].BlockSize := 16;
  FValidTestData[18].InputData := '1';
  FValidTestData[18].OutputData := '1??????????????'#15;

  FValidTestData[19].BlockSize := 16;
  FValidTestData[19].InputData := '123456789ABCDEF';
  FValidTestData[19].OutputData := '123456789ABCDEF'#1;

  FValidTestData[20].BlockSize := 16;
  FValidTestData[20].InputData := '123456789ABCDEFG';
  FValidTestData[20].OutputData := '123456789ABCDEFG???????????????'#16;

  FValidTestData[21].BlockSize := 16;
  FValidTestData[21].InputData := '123456789ABCDEFGHI';
  FValidTestData[21].OutputData := '123456789ABCDEFGHI?????????????'#14;

  SetLength(FNegativeTestData, 5);
  FNegativeTestData[0].BlockSize := 8;
  FNegativeTestData[0].InputData := '';
  FNegativeTestData[0].OutputData := '';

  FNegativeTestData[1].BlockSize := 8;
  FNegativeTestData[1].InputData := '7';
  FNegativeTestData[1].OutputData := '7'#0#0#0#0#0#0#9;  // Len > BlockSize

  FNegativeTestData[2].BlockSize := 8;
  FNegativeTestData[2].InputData := '78';
  FNegativeTestData[2].OutputData := '78'#0#0#0#0#0#0#9; // Len mod BlockSize <> 0

  FNegativeTestData[3].BlockSize := 16;
  FNegativeTestData[3].InputData := '123456789ABCDEFGHI';
  FNegativeTestData[3].OutputData := '123456789ABCDEFGHI'#0#0#0#0#0#0#0#0#0#0#0#0#15; // Len mod BlockSize <> 0

  FNegativeTestData[4].BlockSize := 16;
  FNegativeTestData[4].InputData := '123456789ABCDEFGHI';
  FNegativeTestData[4].OutputData := '123456789ABCDEFGHI'#0#0#0#0#0#0#0#0#0#0#0#0#0#17; // Len > BlockSize

  SetLength(FValidRemoveTestData, 4);
  FValidRemoveTestData[0].BlockSize := 8;
  FValidRemoveTestData[0].InputData := '';
  FValidRemoveTestData[0].OutputData := #1#2#3#4#5#6#7#8;

  FValidRemoveTestData[1].BlockSize := 8;
  FValidRemoveTestData[1].InputData := '789ABC';
  FValidRemoveTestData[1].OutputData := '789ABC'#3#2;

  FValidRemoveTestData[2].BlockSize := 8;
  FValidRemoveTestData[2].InputData := '789ABC';
  FValidRemoveTestData[2].OutputData := '789ABC'#127#2;

  FValidRemoveTestData[3].BlockSize := 16;
  FValidRemoveTestData[3].InputData := '123456789ABCDEFGHI';
  FValidRemoveTestData[3].OutputData := '123456789ABCDEFGHI'#127#0#126#1#7#0#0#0#11#0#9#0#0#14;
end;

function TestTISO10126Padding.RemoveRandomPadding(const Res, Pattern: RawByteString): RawByteString;
var
  c: Integer;
begin
  Result := '';

  for c := low(Pattern) to high(Pattern) do
    if Pattern[c] <> '?' then
      Result := Result + Res[c];
end;

procedure TestTISO10126Padding.TestAddPadding_RawByteString;
var
  I   : integer;
  Res : RawByteString;
begin
  for I := Low(FValidTestData) to High(FValidTestData) do
  begin
    Res := FPaddingClass.AddPadding(FValidTestData[I].InputData,
                                    FValidTestData[I].BlockSize);

    Res := RemoveRandomPadding(Res, FValidTestData[I].OutputData);
    CheckEquals(Res,
                RemoveRandomPadding(FValidTestData[I].OutputData,
                                    FValidTestData[I].OutputData),
                'Valid test data set ' + I.ToString + ' failed');
  end;

  Status(length(FValidTestData).ToString + ' test pattern passed');
end;

procedure TestTISO10126Padding.TestAddPadding_Bytes;
var
  I   : integer;
  Res : TBytes;
begin
  for I := Low(FValidTestData) to High(FValidTestData) do
  begin
    Res := FPaddingClass.AddPadding(DECUtil.RawStringToBytes(FValidTestData[I].InputData),
                                    FValidTestData[I].BlockSize);

    CheckEquals(RemoveRandomPadding(DECUtil.BytesToRawString(Res),
                                    FValidTestData[I].OutputData),
                RemoveRandomPadding(FValidTestData[I].OutputData,
                                    FValidTestData[I].OutputData),
                'Valid test data set ' + I.ToString + ' failed');
  end;

  Status(length(FValidTestData).ToString + ' test pattern passed');
end;

{ TestTISO7816Padding }

procedure TestTISO7816Padding.SetUp;
begin
  inherited;
  FPaddingClass := TISO7816Padding;

  SetLength(FValidTestData, 22);
  FValidTestData[0].BlockSize := 8;
  FValidTestData[0].InputData := '';
  FValidTestData[0].OutputData := RawByteString(#$80#0#0#0#0#0#0#0);

  FValidTestData[1].BlockSize := 8;
  FValidTestData[1].InputData := '7';
  FValidTestData[1].OutputData := RawByteString('7'#$80#0#0#0#0#0#0);

  FValidTestData[2].BlockSize := 8;
  FValidTestData[2].InputData := '78';
  FValidTestData[2].OutputData := RawByteString('78'#$80#0#0#0#0#0);

  FValidTestData[3].BlockSize := 8;
  FValidTestData[3].InputData := '789';
  FValidTestData[3].OutputData := RawByteString('789'#$80#0#0#0#0);

  FValidTestData[4].BlockSize := 8;
  FValidTestData[4].InputData := '789A';
  FValidTestData[4].OutputData := RawByteString('789A'#$80#0#0#0);

  FValidTestData[5].BlockSize := 8;
  FValidTestData[5].InputData := '789AB';
  FValidTestData[5].OutputData := RawByteString('789AB'#$80#0#0);

  FValidTestData[6].BlockSize := 8;
  FValidTestData[6].InputData := '789ABC';
  FValidTestData[6].OutputData := RawByteString('789ABC'#$80#0);

  FValidTestData[7].BlockSize := 8;
  FValidTestData[7].InputData := '789ABCD';
  FValidTestData[7].OutputData := RawByteString('789ABCD'#$80);

  FValidTestData[8].BlockSize := 8;
  FValidTestData[8].InputData := '789ABCDE';
  FValidTestData[8].OutputData := RawByteString('789ABCDE'#$80#0#0#0#0#0#0#0);

  FValidTestData[9].BlockSize := 8;
  FValidTestData[9].InputData := '789ABCDEF';
  FValidTestData[9].OutputData := RawByteString('789ABCDEF'#$80#0#0#0#0#0#0);

  FValidTestData[10].BlockSize := 8;
  FValidTestData[10].InputData := '789ABCDEFG';
  FValidTestData[10].OutputData := RawByteString('789ABCDEFG'#$80#0#0#0#0#0);

  FValidTestData[11].BlockSize := 8;
  FValidTestData[11].InputData := '789ABCDEFGH';
  FValidTestData[11].OutputData := RawByteString('789ABCDEFGH'#$80#0#0#0#0);

  FValidTestData[12].BlockSize := 8;
  FValidTestData[12].InputData := '789ABCDEFGHI';
  FValidTestData[12].OutputData := RawByteString('789ABCDEFGHI'#$80#0#0#0);

  FValidTestData[13].BlockSize := 8;
  FValidTestData[13].InputData := '789ABCDEFGHIJ';
  FValidTestData[13].OutputData := RawByteString('789ABCDEFGHIJ'#$80#0#0);

  FValidTestData[14].BlockSize := 8;
  FValidTestData[14].InputData := '789ABCDEFGHIJK';
  FValidTestData[14].OutputData := RawByteString('789ABCDEFGHIJK'#$80#0);

  FValidTestData[15].BlockSize := 8;
  FValidTestData[15].InputData := '789ABCDEFGHIJKL';
  FValidTestData[15].OutputData := RawByteString('789ABCDEFGHIJKL'#$80);

  FValidTestData[16].BlockSize := 8;
  FValidTestData[16].InputData := '789ABCDEFGHIJKLM';
  FValidTestData[16].OutputData := RawByteString('789ABCDEFGHIJKLM'#$80#0#0#0#0#0#0#0);

  FValidTestData[17].BlockSize := 16;
  FValidTestData[17].InputData := '';
  FValidTestData[17].OutputData := RawByteString(#$80#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0);

  FValidTestData[18].BlockSize := 16;
  FValidTestData[18].InputData := '1';
  FValidTestData[18].OutputData := RawByteString('1'#$80#0#0#0#0#0#0#0#0#0#0#0#0#0#0);

  FValidTestData[19].BlockSize := 16;
  FValidTestData[19].InputData := '123456789ABCDEF';
  FValidTestData[19].OutputData := RawByteString('123456789ABCDEF'#$80);

  FValidTestData[20].BlockSize := 16;
  FValidTestData[20].InputData := '123456789ABCDEFG';
  FValidTestData[20].OutputData := RawByteString('123456789ABCDEFG'#$80#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0);

  FValidTestData[21].BlockSize := 16;
  FValidTestData[21].InputData := '123456789ABCDEFGHI';
  FValidTestData[21].OutputData := RawByteString('123456789ABCDEFGHI'#$80#0#0#0#0#0#0#0#0#0#0#0#0#0);

  SetLength(FNegativeTestData, 5);
  FNegativeTestData[0].BlockSize := 8;
  FNegativeTestData[0].InputData := '';
  FNegativeTestData[0].OutputData := '';

  FNegativeTestData[1].BlockSize := 8;
  FNegativeTestData[1].InputData := '7';
  FNegativeTestData[1].OutputData := RawByteString('7'#$81#0#0#0#0#0#0);  // First Padding <> $80

  FNegativeTestData[2].BlockSize := 8;
  FNegativeTestData[2].InputData := '78';
  FNegativeTestData[2].OutputData := RawByteString('78'#$80#0#0#0#0#0#0); // Len mod BlockSize <> 0

  FNegativeTestData[3].BlockSize := 16;
  FNegativeTestData[3].InputData := '123456789ABCDEFGHI';
  FNegativeTestData[3].OutputData := RawByteString('123456789ABCDEFGHI'#0#0#0#0#0#0#0#0#0#0#0#0#0#0); // First Padding <> $80

  FNegativeTestData[4].BlockSize := 16;
  FNegativeTestData[4].InputData := '123456789ABCDEFGHI';
  FNegativeTestData[4].OutputData := RawByteString('123456789ABCDEFGHI'#0#0#0#0#0#0#0#0#0#0#0#0#0); // Len mod BlockSize <> 0

  SetLength(FValidRemoveTestData, 0);
end;

initialization
  // Register any test cases with the test runner
  {$IFDEF DUnitX}
  TDUnitX.RegisterTestFixture(TestTPKCS7Padding);
  TDUnitX.RegisterTestFixture(TestTANSI_X9_23Padding);
  TDUnitX.RegisterTestFixture(TestTPKCS5Padding);
  TDUnitX.RegisterTestFixture(TestTISO10126Padding);
  TDUnitX.RegisterTestFixture(TestTISO7816Padding);
  {$ELSE}
  RegisterTests('DECCipherPaddings', [TestTPKCS7Padding.Suite,
                                      TestTANSI_X9_23Padding.Suite,
                                      TestTPKCS5Padding.Suite,
                                      TestTISO10126Padding.Suite,
                                      TestTISO7816Padding.Suite]);
  {$ENDIF}
end.
