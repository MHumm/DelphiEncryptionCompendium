// IsValid Tests für MIME32 und für manche anderen fehlen noch!!!
// Und dann alle anderen Encode/Decode für die anderen Klassen

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
  /// <summary>
  ///   Type needed for passing the right encode or decode method to the
  ///   generic encode/decode test
  /// </summary>
  TEncodeDecodeProcRawByteString = function(const data: RawByteString):RawByteString of Object;
  /// <summary>
  ///   Type needed for passing the right encode or decode method to the
  ///   generic encode/decode test
  /// </summary>
  TEncodeDecodeProcTypeless = function(const Data; Size: Integer): RawByteString of Object;

  // Basic test implementations to be shared by the individual formatting class
  // test classes to enable easier DUnit and DUnitX compatibility
  TFormatTestsBase = class(TTestCase)
  strict protected
    procedure DoTestEncodeDecodeTypeless(
      EncodeDecodeProc: TEncodeDecodeProcTypeless;
      TestData: array of TestRecRawByteString);

    procedure DoTestEncodeDecode(EncodeDecodeProc: TEncodeDecodeProc;
                                 TestData: array of TestRecRawByteString);

    procedure DoTestEncodeDecodeRawByteString(
      EncodeDecodeProc: TEncodeDecodeProcRawByteString;
      TestData: array of TestRecRawByteString);
  end;

  // Test methods for class TFormat_HEX
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_HEX = class(TFormatTestsBase)
  strict private
    FFormat_HEX: TFormat_HEX;

    const
      cTestDataEncode : array[1..2] of TestRecRawByteString = (
        (Input:  RawByteString('');
         Output: ''),
        (Input:  RawByteString('Test'+#10+#9+#$AA+#$55+#$AB+#$CD+#$EF);
         Output: '546573740A09AA55ABCDEF'));

      cTestDataDecode : array[1..2] of TestRecRawByteString = (
        (Input:  RawByteString('');
         Output: ''),
        (Input:  '546573740A09AA55ABCDEF';
         Output: RawByteString('Test'+#10+#9+#$AA+#$55+#$AB+#$CD+#$EF)));
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestEncodeRawByteString;
    procedure TestEncodeTypeless;
    procedure TestDecodeBytes;
    procedure TestDecodeRawByteString;
    procedure TestDecodeTypeless;
    procedure TestIsValidTypeless;
    procedure TestIsValidTBytes;
    procedure TestIsValidRawByteString;
    procedure TestClassByName;
  end;

  // Test methods for class TFormat_HEXL
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_HEXL = class(TFormatTestsBase)
  strict private
    FFormat_HEXL: TFormat_HEXL;

    const
      cTestDataEncode : array[1..2] of TestRecRawByteString = (
        (Input:  RawByteString('');
         Output: ''),
        (Input:  RawByteString('Test'+#10+#9+#$AA+#$55+#$AB+#$CD+#$EF);
         Output: '546573740a09aa55abcdef'));

      cTestDataDecode : array[1..2] of TestRecRawByteString = (
        (Input:  RawByteString('');
         Output: ''),
        (Input:  '546573740a09aa55abcdef';
         Output: RawByteString('Test'+#10+#9+#$AA+#$55+#$AB+#$CD+#$EF)));
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestEncodeRawByteString;
    procedure TestEncodeTypeless;
    procedure TestDecodeBytes;
    procedure TestDecodeRawByteString;
    procedure TestDecodeTypeless;
    procedure TestIsValidTypeless;
    procedure TestIsValidTBytes;
    procedure TestIsValidRawByteString;
    procedure TestClassByName;
  end;

  // Test methods for class TFormat_DECMIME32
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_DECMIME32 = class(TFormatTestsBase)
  strict private
    FFormat_DECMIME32: TFormat_DECMIME32;

    const
      cTestDataEncode : array[1..6] of TestRecRawByteString = (
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

      cTestDataDecode : array[1..6] of TestRecRawByteString = (
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
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestEncodeRawByteString;
    procedure TestEncodeTypeless;
    procedure TestDecodeBytes;
    procedure TestDecodeRawByteString;
    procedure TestDecodeTypeless;
    procedure TestIsValidTypeless;
    procedure TestIsValidTBytes;
    procedure TestIsValidRawByteString;
    procedure TestClassByName;
  end;

  // Test methods for class TFormat_Base64
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_Base64 = class(TFormatTestsBase)
  strict private
    FFormat_Base64: TFormat_Base64;
    const
      cTestDataEncode : array[1..6] of TestRecRawByteString = (
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

      cTestDataDecode : array[1..6] of TestRecRawByteString = (
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
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestEncodeRawByteString;
    procedure TestEncodeTypeless;
    procedure TestDecodeBytes;
    procedure TestDecodeRawByteString;
    procedure TestDecodeTypeless;
    procedure TestClassByName;
  end;

  // Test methods for class TFormat_Radix64
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_Radix64 = class(TFormatTestsBase)
  strict private
    FFormat_Radix64: TFormat_Radix64;

    const
      cTestDataEncode : array[1..6] of TestRecRawByteString = (
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

      cTestDataDecode : array[1..6] of TestRecRawByteString = (
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
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestEncodeRawByteString;
    procedure TestEncodeTypeless;
    procedure TestDecodeBytes;
    procedure TestDecodeRawByteString;
    procedure TestDecodeTypeless;
    procedure TestEncodeRawByteStringWithCharsPerLine;
    procedure TestClassByName;
  end;

  // Test methods for class TFormat_UU
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_UU = class(TFormatTestsBase)
  strict private
    FFormat_UU: TFormat_UU;

    const
      cTestDataEncode : array[1..6] of TestRecRawByteString = (
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

      cTestDataDecode : array[1..6] of TestRecRawByteString = (
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
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestEncodeRawByteString;
    procedure TestEncodeTypeless;
    procedure TestDecodeBytes;
    procedure TestDecodeRawByteString;
    procedure TestDecodeTypeless;
    procedure TestIsValidTypeless;
    procedure TestIsValidTBytes;
    procedure TestIsValidRawByteString;
    procedure TestClassByName;
  end;

  // Test methods for class TFormat_XX
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_XX = class(TFormatTestsBase)
  strict private
    FFormat_XX: TFormat_XX;

    const
      cTestDataEncode : array[1..6] of TestRecRawByteString = (
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

      cTestDataDecode : array[1..6] of TestRecRawByteString = (
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
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestEncodeRawByteString;
    procedure TestEncodeTypeless;
    procedure TestDecodeBytes;
    procedure TestDecodeRawByteString;
    procedure TestDecodeTypeless;
    procedure TestClassByName;
  end;

  // Test methods for class TFormat_ESCAPE
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_ESCAPE = class(TFormatTestsBase)
  strict private
    FFormat_ESCAPE: TFormat_ESCAPE;

    const
      cTestDataEncode : array[1..9] of TestRecRawByteString = (
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

      cTestDataDecode : array[1..9] of TestRecRawByteString = (
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
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestEncodeRawByteString;
    procedure TestEncodeTypeless;
    procedure TestDecodeBytes;
    procedure TestDecodeRawByteString;
    procedure TestDecodeTypeless;
    procedure TestClassByName;
  end;

implementation

type
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

procedure TestTFormat_HEX.TestClassByName;
var
  ReturnValue : TDECFormatClass;
begin
  ReturnValue := FFormat_HEX.ClassByName('TFormat_HEX');
  CheckEquals(TFormat_HEX, ReturnValue, 'Class is not registered');
end;

procedure TestTFormat_HEX.TestDecodeBytes;
begin
  DoTestEncodeDecode(FFormat_HEX.Decode, cTestDataDecode);
end;

procedure TestTFormat_HEX.TestDecodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_HEX.Decode, cTestDataDecode);
end;

procedure TestTFormat_HEX.TestDecodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_HEX.Decode, cTestDataDecode);
end;

procedure TestTFormat_HEX.TestEncodeBytes;
begin
  DoTestEncodeDecode(FFormat_HEX.Encode, cTestDataEncode);
end;

procedure TestTFormat_HEX.TestEncodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_HEX.Encode, cTestDataEncode);
end;

procedure TestTFormat_HEX.TestEncodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_HEX.Encode, cTestDataEncode);
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

procedure TestTFormat_HEXL.TestClassByName;
var
  ReturnValue : TDECFormatClass;
begin
  ReturnValue := FFormat_HEXL.ClassByName('TFormat_HEXL');
  CheckEquals(TFormat_HEXL, ReturnValue, 'Class is not registered');
end;

procedure TestTFormat_HEXL.TestDecodeBytes;
begin
  DoTestEncodeDecode(FFormat_HEXL.Decode, cTestDataDecode);
end;

procedure TestTFormat_HEXL.TestDecodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_HEXL.Decode, cTestDataDecode);
end;

procedure TestTFormat_HEXL.TestDecodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_HEXL.Decode, cTestDataDecode);
end;

procedure TestTFormat_HEXL.TestEncodeBytes;
begin
  DoTestEncodeDecode(FFormat_HEXL.Encode, cTestDataEncode);
end;

procedure TestTFormat_HEXL.TestEncodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_HEXL.Encode, cTestDataEncode);
end;

procedure TestTFormat_HEXL.TestEncodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_HEXL.Encode, cTestDataEncode);
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

procedure TestTFormat_DECMIME32.TestClassByName;
var
  ReturnValue : TDECFormatClass;
begin
  ReturnValue := FFormat_DECMIME32.ClassByName('TFormat_DECMIME32');
  CheckEquals(TFormat_DECMIME32, ReturnValue, 'Class is not registered');
end;

procedure TestTFormat_DECMIME32.TestDecodeBytes;
begin
  DoTestEncodeDecode(FFormat_DECMIME32.Decode, cTestDataDecode);
end;

procedure TestTFormat_DECMIME32.TestDecodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_DECMIME32.Decode, cTestDataDecode);
end;

procedure TestTFormat_DECMIME32.TestDecodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_DECMIME32.Decode, cTestDataDecode);
end;

procedure TestTFormat_DECMIME32.TestEncodeBytes;
begin
  DoTestEncodeDecode(FFormat_DECMIME32.Encode, cTestDataEncode);
end;

procedure TestTFormat_DECMIME32.TestEncodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_DECMIME32.Encode, cTestDataEncode);
end;

procedure TestTFormat_DECMIME32.TestEncodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_DECMIME32.Encode, cTestDataEncode);
end;

procedure TestTFormat_DECMIME32.TestIsValidRawByteString;
begin
  CheckEquals(true, TFormat_DECMIME32.IsValid(BytesOf('')));

  CheckEquals(true, TFormat_DECMIME32.IsValid(BytesOf('abcdefghijklnpqrstuwxyz123456789')));
  CheckEquals(false, TFormat_DECMIME32.IsValid(BytesOf('1Q')));
  CheckEquals(true, TFormat_DECMIME32.IsValid(BytesOf('6')));
end;

procedure TestTFormat_DECMIME32.TestIsValidTBytes;
var
  SrcBuf: TBytes;
begin
  SrcBuf := BytesOf(RawByteString(''));
  CheckEquals(true, TFormat_DECMIME32.IsValid(SrcBuf));

  SrcBuf := BytesOf(cTestDataEncode[3].Output);
  CheckEquals(true, TFormat_DECMIME32.IsValid(SrcBuf));

  SrcBuf := BytesOf(RawByteString('Q'));
  CheckEquals(false, TFormat_DECMIME32.IsValid(SrcBuf));
end;

procedure TestTFormat_DECMIME32.TestIsValidTypeless;
var
  SrcBuf: TBytes;
begin
  SrcBuf := BytesOf(RawByteString(''));
  CheckEquals(true, TFormat_DECMIME32.IsValid(SrcBuf, 0));

  SrcBuf := BytesOf(cTestDataEncode[3].Output);
  CheckEquals(true, TFormat_DECMIME32.IsValid(SrcBuf[0], length(SrcBuf)));

  SrcBuf := BytesOf(RawByteString('Q'));
  CheckEquals(false, TFormat_DECMIME32.IsValid(SrcBuf[0], length(SrcBuf)));
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

procedure TestTFormat_Base64.TestClassByName;
var
  ReturnValue : TDECFormatClass;
begin
  ReturnValue := FFormat_Base64.ClassByName('TFormat_Base64');
  CheckEquals(TFormat_Base64, ReturnValue, 'Class is not registered');
end;

procedure TestTFormat_Base64.TestDecodeBytes;
begin
  DoTestEncodeDecode(FFormat_Base64.Decode, cTestDataDecode);
end;

procedure TestTFormat_Base64.TestDecodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_Base64.Decode, cTestDataDecode);
end;

procedure TestTFormat_Base64.TestDecodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_Base64.Decode, cTestDataDecode);
end;

procedure TestTFormat_Base64.TestEncodeBytes;
begin
  DoTestEncodeDecode(FFormat_Base64.Encode, cTestDataEncode);
end;

procedure TestTFormat_Base64.TestEncodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_Base64.Encode, cTestDataEncode);
end;

procedure TestTFormat_Base64.TestEncodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_Base64.Encode, cTestDataEncode);
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

procedure TestTFormat_Radix64.TestEncodeRawByteStringWithCharsPerLine;
type
  /// <summary>
  ///   Type needed for the EncodeBytes und DecodeBytes test data definition
  /// </summary>
  TestRecCharsPerLine = record
    Input, Output: RawByteString;
    CharsPerLine : Byte;
  end;

const
  cTestDataEncode : array[1..2] of TestRecCharsPerLine = (
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55);
     Output: RawByteString('VGVzdAoJqlU=' + #13 + #10 +'=XtiM');
     CharsPerLine: 20),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55);
     Output: RawByteString('VGVz' + #13 + #10 + 'dAoJ' + #13 + #10 + 'qlU=' +
                           #13 + #10 + '=Xti' + #13 + #10 + 'M');
     CharsPerLine: 4)); 
var
  i       : Integer;
  SrcBuf,
  DestBuf : TBytes;
  OldCharsPerLineValue : Cardinal;
begin
  OldCharsPerLineValue := FFormat_Radix64.GetCharsPerLine;
  for i := Low(cTestDataEncode) to High(cTestDataEncode) do
  begin
    SrcBuf := BytesOf(RawByteString(cTestDataEncode[i].Input));
    FFormat_Radix64.SetCharsPerLine(cTestDataEncode[i].CharsPerLine);

    DestBuf := FFormat_Radix64.Encode(SrcBuf);

    CheckEquals(cTestDataEncode[i].Output,
                BytesToRawString(DestBuf));
  end;
  FFormat_Radix64.SetCharsPerLine(OldCharsPerLineValue);
end;

procedure TestTFormat_Radix64.TestClassByName;
var
  ReturnValue : TDECFormatClass;
begin
  ReturnValue := FFormat_Radix64.ClassByName('TFormat_Radix64');
  CheckEquals(TFormat_Radix64, ReturnValue, 'Class is not registered');
end;

procedure TestTFormat_Radix64.TestDecodeBytes;
begin
  DoTestEncodeDecode(FFormat_Radix64.Decode, cTestDataDecode);
end;

procedure TestTFormat_Radix64.TestDecodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_Radix64.Decode, cTestDataDecode);
end;

procedure TestTFormat_Radix64.TestDecodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_Radix64.Decode, cTestDataDecode);
end;

procedure TestTFormat_Radix64.TestEncodeBytes;
begin
  DoTestEncodeDecode(FFormat_Radix64.Encode, cTestDataEncode);
end;

procedure TestTFormat_Radix64.TestEncodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_Radix64.Encode, cTestDataEncode);
end;

procedure TestTFormat_Radix64.TestEncodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_Radix64.Encode, cTestDataEncode);
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

procedure TestTFormat_UU.TestClassByName;
var
  ReturnValue : TDECFormatClass;
begin
  ReturnValue := FFormat_UU.ClassByName('TFormat_UU');
  CheckEquals(TFormat_UU, ReturnValue, 'Class is not registered');
end;

procedure TestTFormat_UU.TestDecodeBytes;
begin
  DoTestEncodeDecode(FFormat_UU.Decode, cTestDataDecode);
end;

procedure TestTFormat_UU.TestDecodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_UU.Decode, cTestDataDecode);
end;

procedure TestTFormat_UU.TestDecodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_UU.Decode, cTestDataDecode);
end;

procedure TestTFormat_UU.TestEncodeBytes;
begin
  DoTestEncodeDecode(FFormat_UU.Encode, cTestDataEncode);
end;

procedure TestTFormat_UU.TestEncodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_UU.Encode, cTestDataEncode);
end;

procedure TestTFormat_UU.TestEncodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_UU.Encode, cTestDataEncode);
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

procedure TestTFormat_XX.TestClassByName;
var
  ReturnValue : TDECFormatClass;
begin
  ReturnValue := FFormat_XX.ClassByName('TFormat_XX');
  CheckEquals(TFormat_XX, ReturnValue, 'Class is not registered');
end;

procedure TestTFormat_XX.TestDecodeBytes;
begin
  DoTestEncodeDecode(FFormat_XX.Decode, cTestDataDecode);
end;

procedure TestTFormat_XX.TestDecodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_XX.Decode, cTestDataDecode);
end;

procedure TestTFormat_XX.TestDecodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_XX.Decode, cTestDataDecode);
end;

procedure TestTFormat_XX.TestEncodeBytes;
begin
  DoTestEncodeDecode(FFormat_XX.Encode, cTestDataEncode);
end;

procedure TestTFormat_XX.TestEncodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_XX.Encode, cTestDataEncode);
end;

procedure TestTFormat_XX.TestEncodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_XX.Encode, cTestDataEncode);
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

procedure TestTFormat_ESCAPE.TestClassByName;
var
  ReturnValue : TDECFormatClass;
begin
  ReturnValue := FFormat_ESCAPE.ClassByName('TFormat_ESCAPE');
  CheckEquals(TFormat_ESCAPE, ReturnValue, 'Class is not registered');
end;

procedure TestTFormat_ESCAPE.TestDecodeBytes;
begin
  DoTestEncodeDecode(FFormat_ESCAPE.Decode, cTestDataDecode);
end;

procedure TestTFormat_ESCAPE.TestDecodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_ESCAPE.Decode, cTestDataDecode);
end;

procedure TestTFormat_ESCAPE.TestDecodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_ESCAPE.Decode, cTestDataDecode);
end;

procedure TestTFormat_ESCAPE.TestEncodeBytes;
begin
  DoTestEncodeDecode(FFormat_ESCAPE.Encode, cTestDataEncode);
end;

procedure TestTFormat_ESCAPE.TestEncodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_ESCAPE.Encode, cTestDataEncode);
end;

procedure TestTFormat_ESCAPE.TestEncodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_ESCAPE.Encode, cTestDataEncode);
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
    SrcBuf := BytesOf(RawByteString(TestData[i].Input));
    DestBuf := EncodeDecodeProc(SrcBuf);

    CheckEquals(TestData[i].Output,
                BytesToRawString(DestBuf));
  end;
end;

procedure TFormatTestsBase.DoTestEncodeDecodeRawByteString(EncodeDecodeProc: TEncodeDecodeProcRawByteString;
                                                           TestData: array of TestRecRawByteString);
var
  i      : Integer;
  result : RawByteString;
begin
  for i := Low(TestData) to High(TestData) do
  begin
    result := EncodeDecodeProc(TestData[i].Input);

    CheckEquals(TestData[i].Output, result);
  end;
end;

procedure TFormatTestsBase.DoTestEncodeDecodeTypeless(EncodeDecodeProc: TEncodeDecodeProcTypeless;
                                                      TestData: array of TestRecRawByteString);
var
  i      : Integer;
  result : RawByteString;
  pdata  : PByte;
  len    : Integer;
begin
  for i := Low(TestData) to High(TestData) do
  begin
    if length(TestData[i].Input) > 0 then
    begin
      pdata := @TestData[i].Input[low(TestData[i].Input)];

      len := length(TestData[i].Input) * SizeOf(TestData[i].Input[low(TestData[i].Input)]);
    end
    else
    begin
      pdata := nil;
      len   := 0;
    end;

    result := EncodeDecodeProc(pdata^, len);

    CheckEquals(TestData[i].Output, result);
  end;
end;

initialization
  // Register any test cases with the test runner
  {$IFNDEF DUnitX}
  RegisterTests('DECFormat', [TestTFormat_HEX.Suite,
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

