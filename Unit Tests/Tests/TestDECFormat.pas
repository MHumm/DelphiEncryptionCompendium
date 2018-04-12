{*****************************************************************************

  Delphi Encryption Compendium (DEC)
  Version 6.0

  Copyright (c) 2016 - 2018 Markus Humm (markus [dot] humm [at] googlemail [dot] com)
  Copyright (c) 2008 - 2012 Frederik A. Winkelsdorf (winkelsdorf [at] gmail [dot] com)
  Copyright (c) 1999 - 2008 Hagen Reddmann (HaReddmann [at] T-Online [dot] de)
  All rights reserved.

                               *** License ***

  This file is part of the Delphi Encryption Compendium (DEC). The DEC is free
  software being offered under a dual licensing scheme: BSD or MPL 1.1.

  The contents of this file are subject to the Mozilla Public License (MPL)
  Version 1.1 (the "License"); you may not use this file except in compliance
  with the License. You may obtain a copy of the License at
  http://www.mozilla.org/MPL/

  Alternatively, you may redistribute it and/or modify it under the terms of
  the following Berkeley Software Distribution (BSD) license:

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
  THE POSSIBILITY OF SUCH DAMAGE.

                        *** Export/Import Controls ***

  This is cryptographic software. Even if it is created, maintained and
  distributed from liberal countries in Europe (where it is legal to do this),
  it falls under certain export/import and/or use restrictions in some other
  parts of the world.

  PLEASE REMEMBER THAT EXPORT/IMPORT AND/OR USE OF STRONG CRYPTOGRAPHY
  SOFTWARE OR EVEN JUST COMMUNICATING TECHNICAL DETAILS ABOUT CRYPTOGRAPHY
  SOFTWARE IS ILLEGAL IN SOME PARTS OF THE WORLD. SO, WHEN YOU IMPORT THIS
  PACKAGE TO YOUR COUNTRY, RE-DISTRIBUTE IT FROM THERE OR EVEN JUST EMAIL
  TECHNICAL SUGGESTIONS OR EVEN SOURCE PATCHES TO THE AUTHOR OR OTHER PEOPLE
  YOU ARE STRONGLY ADVISED TO PAY CLOSE ATTENTION TO ANY EXPORT/IMPORT AND/OR
  USE LAWS WHICH APPLY TO YOU. THE AUTHORS OF THE DEC ARE NOT LIABLE FOR ANY
  VIOLATIONS YOU MAKE HERE. SO BE CAREFUL, IT IS YOUR RESPONSIBILITY.

*****************************************************************************}

{$M+} // DUnitX would add it anyway
unit TestDECFormat;

interface

// Needs to be included before any other statements
{$I defines.inc}

uses
  {$IFNDEF DUnitX}
  TestFramework,
  {$ENDIF}
  {$IFDEF DUnitX}
  DUnitX.TestFramework,DUnitX.DUnitCompatibility,
  {$ENDIF}
  DECBaseClass, Classes, SysUtils, DECUtil, DECFormat, DECFormatBase;

type
  /// <summary>
  ///   Test methods for global functions/procedures inn DECFormat
  /// </summary>
    {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestFormat = class(TTestCase)
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestUpCaseBinary;
    procedure TestTableFindBinary;
  end;

  /// <summary>
  ///   Type needed for the EncodeBytes und DecodeBytes test data definition
  /// </summary>
  TestRecRawByteString = record
    Input, Output: RawByteString;
  end;

  /// <summary>
  ///   Type needed for passing the right encode or decode method to the
  ///   generic encode/decode test
  /// </summary>
  TEncodeDecodeProc = function(const data: TBytes):TBytes of Object;

  // Basic test implementations to be shared by the individual formatting class
  // test classes to enable easier DUnit and DUnitX compatibility
  TFormatTestsBase = class(TTestCase)
  protected
    procedure DoTestEncodeDecode(EncodeDecodeProc: TEncodeDecodeProc;
                                 TestData: array of TestRecRawByteString); virtual;
  end;

  // Test methods for class TFormat_HEX
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_HEX = class(TFormatTestsBase)
  strict private
    FFormat_HEX: TFormat_HEX;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestDecodeBytes;
    procedure TestIsValidTypeless;
    procedure TestIsValidTBytes;
    procedure TestIsValidRawByteString;
  end;

  // Test methods for class TFormat_HEXL
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_HEXL = class(TFormatTestsBase)
  strict private
    FFormat_HEXL: TFormat_HEXL;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestDecodeBytes;
    procedure TestIsValidTypeless;
    procedure TestIsValidTBytes;
    procedure TestIsValidRawByteString;
  end;

  // Test methods for class TFormat_DECMIME32
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_DECMIME32 = class(TFormatTestsBase)
  strict private
    FFormat_DECMIME32: TFormat_DECMIME32;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestDecodeBytes;
  end;

  // Test methods for class TFormat_Base64
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_Base64 = class(TFormatTestsBase)
  strict private
    FFormat_Base64: TFormat_Base64;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestDecodeBytes;
  end;

  // Test methods for class TFormat_Radix64
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_Radix64 = class(TFormatTestsBase)
  strict private
    FFormat_Radix64: TFormat_Radix64;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestDecodeBytes;
  end;

  // Test methods for class TFormat_UU
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_UU = class(TFormatTestsBase)
  strict private
    FFormat_UU: TFormat_UU;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestDecodeBytes;
    procedure TestIsValidTypeless;
    procedure TestIsValidTBytes;
    procedure TestIsValidRawByteString;
  end;

  // Test methods for class TFormat_XX
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_XX = class(TFormatTestsBase)
  strict private
    FFormat_XX: TFormat_XX;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestDecodeBytes;
  end;

  // Test methods for class TFormat_ESCAPE
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_ESCAPE = class(TFormatTestsBase)
  strict private
    FFormat_ESCAPE: TFormat_ESCAPE;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestDecodeBytes;
  end;

implementation

type
  TestRecTableFindBinary = record
    Value: Byte;
    Table: RawByteString;
    Len  : Integer;
    Index: Integer;
  end;

  TestRecIsValidRawByteString = record
    Input: RawByteString;
    Valid: Boolean;
  end;

procedure TestTFormat_HEX.SetUp;
begin
  FFormat_HEX := TFormat_HEX.Create;
end;

procedure TestTFormat_HEX.TearDown;
begin
  FFormat_HEX.Free;
  FFormat_HEX := nil;
end;

procedure TestTFormat_HEX.TestDecodeBytes;
const
  TestData : array[1..2] of TestRecRawByteString = (
    (Input:  RawByteString('');
     Output: ''),
    (Input:  '546573740A09AA55ABCDEF';
     Output: RawByteString('Test'+#10+#9+#$AA+#$55+#$AB+#$CD+#$EF)));
begin
  DoTestEncodeDecode(FFormat_HEX.Decode, TestData);
end;

procedure TestTFormat_HEX.TestEncodeBytes;
const
  TestData : array[1..2] of TestRecRawByteString = (
    (Input:  RawByteString('');
     Output: ''),
    (Input:  RawByteString('Test'+#10+#9+#$AA+#$55+#$AB+#$CD+#$EF);
     Output: '546573740A09AA55ABCDEF'));
begin
  DoTestEncodeDecode(FFormat_HEX.Encode, TestData);
end;

procedure TestTFormat_HEX.TestIsValidRawByteString;
begin
  CheckEquals(true,  TFormat_HEX.IsValid(BytesOf('')));
  CheckEquals(true,  TFormat_HEX.IsValid(BytesOf('0123456789abcdefABCDEF')));
  // Invalid character: q is not a hex char
  CheckEquals(false, TFormat_HEX.IsValid(BytesOf('1q')));
  // Hex input length needs to be a multiple of 2, if input is not empty
  CheckEquals(false, TFormat_HEX.IsValid(BytesOf('6')));
end;

procedure TestTFormat_HEX.TestIsValidTBytes;
var
  SrcBuf: TBytes;
begin
  SrcBuf := BytesOf(RawByteString(''));
  CheckEquals(true, TFormat_HEX.IsValid(SrcBuf));

  SrcBuf := BytesOf(RawByteString('0123456789abcdefABCDEF'));
  CheckEquals(true, TFormat_HEX.IsValid(SrcBuf));

  SrcBuf := BytesOf(RawByteString('q'));
  CheckEquals(false, TFormat_HEX.IsValid(SrcBuf));
end;

procedure TestTFormat_HEX.TestIsValidTypeless;
var
  SrcBuf: TBytes;
  p     : Pointer;
begin
  { TODO : Ersten test überprüfen, ist dieser wirklich sinnvoll so? }
  SrcBuf := BytesOf(RawByteString(''));
  CheckEquals(true, TFormat_HEX.IsValid(SrcBuf, 0));

  SrcBuf := BytesOf(RawByteString('0123456789abcdefABCDEF'));
  p := @SrcBuf[0];
  CheckEquals(true, TFormat_HEX.IsValid(p^, length(SrcBuf)));

  SrcBuf := BytesOf(RawByteString('q'));
  p := @SrcBuf[0];
  CheckEquals(false, TFormat_HEX.IsValid(p^, length(SrcBuf)));
end;

procedure TestTFormat_HEXL.SetUp;
begin
  FFormat_HEXL := TFormat_HEXL.Create;
end;

procedure TestTFormat_HEXL.TearDown;
begin
  FFormat_HEXL.Free;
  FFormat_HEXL := nil;
end;

procedure TestTFormat_HEXL.TestDecodeBytes;
const
  TestData : array[1..2] of TestRecRawByteString = (
    (Input:  RawByteString('');
     Output: ''),
    (Input:  '546573740a09aa55abcdef';
     Output: RawByteString('Test'+#10+#9+#$AA+#$55+#$AB+#$CD+#$EF)));
begin
  DoTestEncodeDecode(FFormat_HEXL.Decode, TestData);
end;

procedure TestTFormat_HEXL.TestEncodeBytes;
const
  TestData : array[1..2] of TestRecRawByteString = (
    (Input:  RawByteString('');
     Output: ''),
    (Input:  RawByteString('Test'+#10+#9+#$AA+#$55+#$AB+#$CD+#$EF);
     Output: '546573740a09aa55abcdef'));
begin
  DoTestEncodeDecode(FFormat_HEXL.Encode, TestData);
end;

procedure TestTFormat_HEXL.TestIsValidRawByteString;
begin
  CheckEquals(true, TFormat_HEXL.IsValid(BytesOf('')));
  CheckEquals(true, TFormat_HEXL.IsValid(BytesOf('0123456789abcdefABCDEF')));
  // Invalid character: q is not a hex char
  CheckEquals(false, TFormat_HEX.IsValid(BytesOf('1q')));
  // Hex input length needs to be a multiple of 2, if input is not empty
  CheckEquals(false, TFormat_HEX.IsValid(BytesOf('6')));
end;

procedure TestTFormat_HEXL.TestIsValidTBytes;
var
  SrcBuf: TBytes;
begin
  SrcBuf := BytesOf(RawByteString(''));
  CheckEquals(true, TFormat_HEXL.IsValid(SrcBuf));

  SrcBuf := BytesOf(RawByteString('0123456789abcdefABCDEF'));
  CheckEquals(true, TFormat_HEXL.IsValid(SrcBuf));

  SrcBuf := BytesOf(RawByteString('q'));
  CheckEquals(false, TFormat_HEXL.IsValid(SrcBuf));
end;

procedure TestTFormat_HEXL.TestIsValidTypeless;
var
  SrcBuf: TBytes;
begin
  SrcBuf := BytesOf(RawByteString(''));
  CheckEquals(true, TFormat_HEXL.IsValid(SrcBuf, 0));

  SrcBuf := BytesOf(RawByteString('0123456789abcdefABCDEF'));
  CheckEquals(true, TFormat_HEXL.IsValid(SrcBuf[0], length(SrcBuf)));

  SrcBuf := BytesOf(RawByteString('q'));
  CheckEquals(false, TFormat_HEXL.IsValid(SrcBuf[0], length(SrcBuf)));
end;

procedure TestTFormat_DECMIME32.SetUp;
begin
  FFormat_DECMIME32 := TFormat_DECMIME32.Create;
end;

procedure TestTFormat_DECMIME32.TearDown;
begin
  FFormat_DECMIME32.Free;
  FFormat_DECMIME32 := nil;
end;

procedure TestTFormat_DECMIME32.TestDecodeBytes;
const
  TestData : array[1..6] of TestRecRawByteString = (
    (Input:  '';
     Output: RawByteString('')),
    (Input:  'xk3gh4jbjsklf'; // lt. alter DECTest.vec aber xk3gh4jbjsklf f statt y ???
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55)),
    (Input:  'xk3gh4jbjsklfyc';
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA)),
    (Input:  'xk3gh4jbjsklfyzk';
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55)),
    (Input:  'xk3gh4jbjsklfyzkkf';
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA)),
    (Input:  'xk3gh4jbjsklfyzkkpya';
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA + #$55)));
begin
  DoTestEncodeDecode(FFormat_DECMIME32.Decode, TestData);
end;

procedure TestTFormat_DECMIME32.TestEncodeBytes;
{ TODO :
Alte Fassung der Routine aus V5.2 mit diesen Testdaten testen.
Testdaten überprüfen: f oder y, was war früher korrekt? }
const
  TestData : array[1..6] of TestRecRawByteString = (
    (Input:  RawByteString('');
     Output: ''),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55);
     Output: 'xk3gh4jbjsklf'),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA);
     Output: 'xk3gh4jbjsklfyc'),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55);
     Output: 'xk3gh4jbjsklfyzk'),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA);
     Output: 'xk3gh4jbjsklfyzkkf'),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA + #$55);
     Output: 'xk3gh4jbjsklfyzkkpya')); // als letzter Buchstabe kommt manchmal oft ,u statt a heraus?
                                       // scheint etwas zufällig? Was ist da faul?
                                       // lt. DECTest.vec ist a richtig

//var
//  i       : Integer;
//  SrcBuf,
//  DestBuf : TBytes;
//  b : Boolean;
//begin
//  for i := Low(TestData) to High(TestData) do
//  begin
//    SrcBuf := RawStringToBytes(TestData[i].Input);
//
//LogFile.Add('------------------------------------------------------------------');
//LogFile.Add('Test: ' + i.ToString + ' Daten: ' + TestData[i].Input + ' / ' + BytesToRawString(SrcBuf));
//
//    DestBuf := TFormat_DECMIME32.Encode(SrcBuf);
//
//b := TestData[i].Output = BytesToRawString(DestBuf);
//LogFile.Add(SysUtils.BoolToStr(b, true));
//
//    CheckEquals(TestData[i].Output,
//                BytesToRawString(DestBuf));
//  end;
begin
  DoTestEncodeDecode(FFormat_DECMIME32.Encode, TestData);
end;

procedure TestTFormat_Base64.SetUp;
begin
  FFormat_Base64 := TFormat_Base64.Create;
end;

procedure TestTFormat_Base64.TearDown;
begin
  FFormat_Base64.Free;
  FFormat_Base64 := nil;
end;

procedure TestTFormat_Base64.TestDecodeBytes;
const
  TestData : array[1..6] of TestRecRawByteString = (
    (Input:  '';
     Output: RawByteString('')),
    (Input:  'VGVzdAoJqlU=';
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55)),
    (Input:  'VGVzdAoJqlWq';
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA)),
    (Input:  'VGVzdAoJqlWqVQ==';
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55)),
    (Input:  'VGVzdAoJqlWqVao=';
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA)),
    (Input:  'VGVzdAoJqlWqVapV';
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA + #$55)));
begin
  DoTestEncodeDecode(FFormat_Base64.Decode, TestData);
end;

procedure TestTFormat_Base64.TestEncodeBytes;
const
  TestData : array[1..6] of TestRecRawByteString = (
    (Input:  RawByteString('');
     Output: ''),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55);
     Output: 'VGVzdAoJqlU='),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA);
     Output: 'VGVzdAoJqlWq'),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55);
     Output: 'VGVzdAoJqlWqVQ=='),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA);
     Output: 'VGVzdAoJqlWqVao='),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA + #$55);
     Output: 'VGVzdAoJqlWqVapV'));

begin
  DoTestEncodeDecode(FFormat_Base64.Encode, TestData);
end;

procedure TestTFormat_Radix64.SetUp;
begin
  FFormat_Radix64 := TFormat_Radix64.Create;
end;

procedure TestTFormat_Radix64.TearDown;
begin
  FFormat_Radix64.Free;
  FFormat_Radix64 := nil;
end;

procedure TestTFormat_Radix64.TestDecodeBytes;
const
  TestData : array[1..6] of TestRecRawByteString = (
    (Input:  RawByteString('');
     Output: RawByteString('')),
    (Input:  RawByteString('VGVzdAoJqlU=' + #13 + #10 +'=XtiM');
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55)),
    (Input:  RawByteString('VGVzdAoJqlWq' + #13 + #10 + '=qBH3');
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA)),
    (Input:  RawByteString('VGVzdAoJqlWqVQ==' + #13 + #10 + '=Rqc1');
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55)),
    (Input:  RawByteString('VGVzdAoJqlWqVao=' + #13 + #10 +'=s2dH');
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA)),
    (Input:  RawByteString('VGVzdAoJqlWqVapV' + #13 + #10 +'=WEFz');
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA + #$55)));

//var
//  i       : Integer;
//  SrcBuf,
//  DestBuf : TBytes;
//begin
//{ TODO : Test schlägt in DecodeBytes fehl, CRC Prüfung da drin schlägt fehl }
//  for i := Low(TestData) to High(TestData) do
//  begin
//    SrcBuf := RawStringToBytes(TestData[i].Input);
//    DestBuf := TFormat_Radix64.Decode(SrcBuf);
//
//    CheckEquals(TestData[i].Output,
//                BytesToRawString(DestBuf));
//  end;

begin
  DoTestEncodeDecode(FFormat_Radix64.Decode, TestData);
end;

procedure TestTFormat_Radix64.TestEncodeBytes;
const
  TestData : array[1..6] of TestRecRawByteString = (
    (Input:  RawByteString('');
     Output: RawByteString('')),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55);
     Output: RawByteString('VGVzdAoJqlU=' + #13 + #10 +'=XtiM')),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA);
     Output: RawByteString('VGVzdAoJqlWq' + #13 + #10 + '=qBH3')),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55);
     Output: RawByteString('VGVzdAoJqlWqVQ==' + #13 + #10 + '=Rqc1')),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA);
     Output: RawByteString('VGVzdAoJqlWqVao=' + #13 + #10 +'=s2dH')),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA + #$55);
     Output: RawByteString('VGVzdAoJqlWqVapV' + #13 + #10 +'=WEFz')));
begin
  DoTestEncodeDecode(FFormat_Radix64.Encode, TestData);
end;

procedure TestTFormat_UU.SetUp;
begin
  FFormat_UU := TFormat_UU.Create;
end;

procedure TestTFormat_UU.TearDown;
begin
  FFormat_UU.Free;
  FFormat_UU := nil;
end;

procedure TestTFormat_UU.TestDecodeBytes;
const
  TestData : array[1..6] of TestRecRawByteString = (
    (Input:  '';
     Output: RawByteString('')),
    (Input:  RawByteString('(5&5S=`H)JE4`');
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55)),
    (Input:  RawByteString(')5&5S=`H)JE6J');
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA)),
    (Input:  RawByteString('*5&5S=`H)JE6J50``');
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55)),
    (Input:  RawByteString('+5&5S=`H)JE6J5:H`');
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA)),
    (Input:  RawByteString(',5&5S=`H)JE6J5:I5');
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA + #$55)));
begin
  DoTestEncodeDecode(FFormat_UU.Decode, TestData);
end;

procedure TestTFormat_UU.TestEncodeBytes;
const
  TestData : array[1..6] of TestRecRawByteString = (
    (Input:  RawByteString('');
     Output: ''),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55);
     Output: '(5&5S=`H)JE4`'),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA);
     Output: ')5&5S=`H)JE6J'),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55);
     Output: '*5&5S=`H)JE6J50``'),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA);
     Output: '+5&5S=`H)JE6J5:H`'),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA + #$55);
     Output: ',5&5S=`H)JE6J5:I5'));
begin
  DoTestEncodeDecode(FFormat_UU.Encode, TestData);
end;

procedure TestTFormat_UU.TestIsValidRawByteString;
const
  TestData : array[1..5] of TestRecIsValidRawByteString = (
    (Input: RawByteString('(5&5S=`H)JE4`');
     Valid: true),
    (Input: RawByteString(')5&5S=`H)JE6J');
     Valid: true),
    (Input: RawByteString('*5&5S=`H)JE6J50``');
     Valid: true),
    (Input: RawByteString('+5&5S=`H)JE6J5:H`');
     Valid: true),
    (Input: RawByteString(',5&5S=`H)JE6J5:I5');
     Valid: true));

var
  SrcBuf: TBytes;
  i     : Integer;
begin
  SetLength(SrcBuf, 0);
  CheckEquals(TestData[1].Valid, TFormat_UU.IsValid(DECUtil.BytesToRawString(SrcBuf)));

  for i := Low(TestData)+1 to High(TestData) do
  begin
    SrcBuf := BytesOf(RawByteString(TestData[i].Input));
    CheckEquals(TestData[i].Valid, TFormat_UU.IsValid(DECUtil.BytesToRawString(SrcBuf)));
  end;
end;

procedure TestTFormat_UU.TestIsValidTBytes;
const
  TestData : array[1..5] of TestRecIsValidRawByteString = (
    (Input: RawByteString('(5&5S=`H)JE4`');
     Valid: true),
    (Input: RawByteString(')5&5S=`H)JE6J');
     Valid: true),
    (Input: RawByteString('*5&5S=`H)JE6J50``');
     Valid: true),
    (Input: RawByteString('+5&5S=`H)JE6J5:H`');
     Valid: true),
    (Input: RawByteString(',5&5S=`H)JE6J5:I5');
     Valid: true));

var
  SrcBuf: TBytes;
  i     : Integer;
begin
  SetLength(SrcBuf, 0);
  CheckEquals(TestData[1].Valid, TFormat_UU.IsValid(SrcBuf, length(SrcBuf)));

  for i := Low(TestData)+1 to High(TestData) do
  begin
    SrcBuf := BytesOf(RawByteString(TestData[i].Input));
    CheckEquals(TestData[i].Valid, TFormat_UU.IsValid(SrcBuf[0], length(SrcBuf)));
  end;
end;

procedure TestTFormat_UU.TestIsValidTypeless;
const
  TestData : array[1..5] of TestRecIsValidRawByteString = (
    (Input: RawByteString('(5&5S=`H)JE4`');
     Valid: true),
    (Input: RawByteString(')5&5S=`H)JE6J');
     Valid: true),
    (Input: RawByteString('*5&5S=`H)JE6J50``');
     Valid: true),
    (Input: RawByteString('+5&5S=`H)JE6J5:H`');
     Valid: true),
    (Input: RawByteString(',5&5S=`H)JE6J5:I5');
     Valid: true));

var
  SrcBuf: TBytes;
  i     : Integer;
  p     : Pointer;
begin
  SetLength(SrcBuf, 0);
  p := @SrcBuf;
  CheckEquals(TestData[1].Valid, TFormat_UU.IsValid(p^, length(SrcBuf)));

  for i := Low(TestData)+1 to High(TestData) do
  begin
    SrcBuf := BytesOf(RawByteString(TestData[i].Input));
    p := @SrcBuf[0];
    CheckEquals(TestData[i].Valid, TFormat_UU.IsValid(p^, length(SrcBuf)));
  end;
end;

procedure TestTFormat_XX.SetUp;
begin
  FFormat_XX := TFormat_XX.Create;
end;

procedure TestTFormat_XX.TearDown;
begin
  FFormat_XX.Free;
  FFormat_XX := nil;
end;

procedure TestTFormat_XX.TestDecodeBytes;
const
  TestData : array[1..6] of TestRecRawByteString = (
    (Input:  RawByteString('');
     Output: ''),
    (Input:  RawByteString('6J4JnR+c7eZI+');
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55)),
    (Input:  RawByteString('7J4JnR+c7eZKe');
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA)),
    (Input:  RawByteString('8J4JnR+c7eZKeJE++');
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55)),
    (Input:  RawByteString('9J4JnR+c7eZKeJOc+');
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA)),
    (Input:  RawByteString('AJ4JnR+c7eZKeJOdJ');
     Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA + #$55)));

begin
  DoTestEncodeDecode(FFormat_XX.Decode, TestData);
end;

procedure TestTFormat_XX.TestEncodeBytes;
const
  TestData : array[1..6] of TestRecRawByteString = (
    (Input:  RawByteString('');
     Output: ''),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55);
     Output: '6J4JnR+c7eZI+'),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA);
     Output: '7J4JnR+c7eZKe'),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55);
     Output: '8J4JnR+c7eZKeJE++'),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA);
     Output: '9J4JnR+c7eZKeJOc+'),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA + #$55);
     Output: 'AJ4JnR+c7eZKeJOdJ'));
begin
  DoTestEncodeDecode(FFormat_XX.Encode, TestData);
end;

procedure TestTFormat_ESCAPE.SetUp;
begin
  FFormat_ESCAPE := TFormat_ESCAPE.Create;
end;

procedure TestTFormat_ESCAPE.TearDown;
begin
  FFormat_ESCAPE.Free;
  FFormat_ESCAPE := nil;
end;

procedure TestTFormat_ESCAPE.TestDecodeBytes;
const
  TestData : array[1..9] of TestRecRawByteString = (
    (Input:  '';
     Output: RawByteString('')),
    (Input:  RawByteString('Test\xAAU');
     Output: RawByteString('Test' + #$AA + #$55)),
    (Input:  RawByteString('Test\x80U');
     Output: RawByteString('Test' + #$80 + #$55)),
    (Input:  RawByteString('Test U');
     Output: RawByteString('Test' + #$20 + #$55)),
    (Input:  RawByteString('Test\x19U');
     Output: RawByteString('Test' + #$19 + #$55)),
    (Input:  RawByteString('Test\a\b\t\n\v\f\rU');
     Output: RawByteString('Test' + #$07 + #$08 + #$09 + #$0A + #$0B + #$0C + #$0D + #$55)),
    (Input:  RawByteString('Test\\U');
     Output: RawByteString('Test\U')),
    (Input:  RawByteString('Test\\\aU');
     Output: RawByteString('Test\'+#$07 +'U')),
    (Input:  RawByteString('Test\"hello\"U');
     Output: RawByteString('Test"hello"U')));
begin
  DoTestEncodeDecode(FFormat_ESCAPE.Decode, TestData);
end;

procedure TestTFormat_ESCAPE.TestEncodeBytes;
const
  TestData : array[1..9] of TestRecRawByteString = (
    (Input:  '';
     Output: RawByteString('')),
    (Input:  RawByteString('Test' + #$AA + #$55);
     Output: RawByteString('Test\xAAU')),
    (Input:  RawByteString('Test' + #$80 + #$55);
     Output: RawByteString('Test\x80U')),
    (Input:  RawByteString('Test' + #$20 + #$55);
     Output: RawByteString('Test U')),
    (Input:  RawByteString('Test' + #$19 + #$55);
     Output: RawByteString('Test\x19U')),
    (Input:  RawByteString('Test' + #$07 + #$08 + #$09 + #$0A + #$0B + #$0C + #$0D + #$55);
     Output: RawByteString('Test\a\b\t\n\v\f\rU')),
    (Input:  RawByteString('Test\U');
     Output: RawByteString('Test\\U')),
    (Input:  RawByteString('Test\'+#$07 +'U');
     Output: RawByteString('Test\\\aU')),
    (Input:  RawByteString('Test"hello"U');
     Output: RawByteString('Test\"hello\"U')));
begin
  DoTestEncodeDecode(FFormat_ESCAPE.Encode, TestData);
end;

{ TestFormat }

procedure TestFormat.SetUp;
begin
  inherited;
end;

procedure TestFormat.TearDown;
begin
  inherited;
end;

procedure TestFormat.TestUpCaseBinary;
const
  InputChars  = ' !"#$%&''()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
                '[\]^_`abcdefghijklmnopqrstuvwxyz{|}~';
  OutputChars = ' !"#$%&''()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
                '[\]^_`ABCDEFGHIJKLMNOPQRSTUVWXYZ{|}~';

var
  i : Integer;
  b, exp, res : Byte;
begin
  for i := Low(InputChars) to High(InputChars) do
  begin
    b   := ord(InputChars[i]);
    exp := ord(OutputChars[i]);
    res := TDECFormat.UpCaseBinary(b);

    CheckEquals(exp, res);
  end;
end;

procedure TestFormat.TestTableFindBinary;
const
  Data : array[1..8] of TestRecTableFindBinary = (
  (Value: 0;
   Table: '';
   Len:   10;
   Index: -1),
  (Value: 0;
   Table: '';
   Len: -10;
   Index: -1),
  (Value: $31;
   Table: '12345678901';
   Len:   100;
   Index: 0),
  (Value: $32;
   Table: '12345678901';
   Len:   100;
   Index: 1),
  (Value: $30;
   Table: '12345678901';
   Len:   100;
   Index: 9),
  (Value: $29;
   Table: '12345678901';
   Len:   100;
   Index: -1),
  (Value: $30;
   Table: '12345678901';
   Len:   9;
   Index: 9),
  (Value: $30;
   Table: '12345678901';
   Len:   8;
   Index: -1)
  );

var
  i : Integer;
  Idx : Integer;
begin
  for i := Low(Data) to High(Data) do
  begin
    Idx := TDECFormat.TableFindBinary(Data[i].Value,
                                      BytesOf(RawByteString(Data[i].Table)),
                                      Data[i].Len);
    CheckEquals(Data[i].Index, Idx);
  end;
end;

{ TFormatTestsBase }

procedure TFormatTestsBase.DoTestEncodeDecode(EncodeDecodeProc: TEncodeDecodeProc;
                                              TestData: array of TestRecRawByteString);
var
  i       : Integer;
  SrcBuf,
  DestBuf : TBytes;
begin
  for i := Low(TestData) to High(TestData) do
  begin
if (i = 1) then
  sleep(10);

// da liegt der Hase irgendwo im Pfeffer: im Testprogramm wenn jedesmal ein
// RawByteString übergeben wird klappt alles
// Struktur untersuchen: wer ruft wen auf und mit welchen Daten!
    SrcBuf := BytesOf(RawByteString(TestData[i].Input));
    DestBuf := EncodeDecodeProc(SrcBuf);

    CheckEquals(TestData[i].Output,
                BytesToRawString(DestBuf));
  end;
end;

initialization
  // Register any test cases with the test runner
  {$IFNDEF DUnitX}
  RegisterTests('DECFormat', [TestFormat.Suite,         TestTFormat_HEX.Suite,
                              TestTFormat_HEXL.Suite,   TestTFormat_DECMIME32.Suite,
                              TestTFormat_Base64.Suite, TestTFormat_Radix64.Suite,
                              TestTFormat_UU.Suite,     TestTFormat_XX.Suite,
                              TestTFormat_ESCAPE.Suite]);
  {$ELSE}
  TDUnitX.RegisterTestFixture(TestFormat);
  TDUnitX.RegisterTestFixture(TestTFormat_HEX);
  TDUnitX.RegisterTestFixture(TestTFormat_HEXL);
  TDUnitX.RegisterTestFixture(TestTFormat_DECMIME32);
  TDUnitX.RegisterTestFixture(TestTFormat_Base64);
  TDUnitX.RegisterTestFixture(TestTFormat_Radix64);
  TDUnitX.RegisterTestFixture(TestTFormat_UU);
  TDUnitX.RegisterTestFixture(TestTFormat_XX);
  TDUnitX.RegisterTestFixture(TestTFormat_ESCAPE);
  {$ENDIF}

finalization
end.

