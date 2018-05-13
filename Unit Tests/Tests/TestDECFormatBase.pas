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
unit TestDECFormatBase;

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
  Classes, DECUtil, DECBaseClass, SysUtils, DECFormatBase;

type
  // Test methods for class TFormat_Copy
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat = class(TTestCase)
  strict private
  private
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestUpCaseBinary;
    procedure TestTableFindBinary;
    procedure TestIsClassListCreated;
  end;

  // Test methods for class TFormat_Copy
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_Copy = class(TTestCase)
  strict private
    FFormat_Copy: TFormat_Copy;
  private
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
  end;

implementation

type
  TestRecTableFindBinary = record
    Value: Byte;
    Table: RawByteString;
    Len  : Integer;
    Index: Integer;
  end;

procedure TestTFormat_Copy.SetUp;
begin
  FFormat_Copy := TFormat_Copy.Create;
end;

procedure TestTFormat_Copy.TearDown;
begin
  FFormat_Copy.Free;
  FFormat_Copy := nil;
end;

procedure TestTFormat_Copy.TestDecodeBytes;
var
  SrcBuf,
  DestBuf : TBytes;
begin
  SrcBuf  := BytesOf(RawByteString('1234567890abcdefghijklmnopqrstuvwxyz@!$'));
  DestBuf := TFormat_Copy.Decode(SrcBuf);

  CheckEquals('1234567890abcdefghijklmnopqrstuvwxyz@!$',
              string(BytesToRawString(DestBuf)));
end;

procedure TestTFormat_Copy.TestDecodeRawByteString;
var
  SrcString,
  DestString : RawByteString;
begin
  SrcString  := '1234567890abcdefghijklmnopqrstuvwxyz@!$';
  DestString := TFormat_Copy.Decode(SrcString);

  CheckEquals(RawByteString('1234567890abcdefghijklmnopqrstuvwxyz@!$'),
              DestString);
end;

procedure TestTFormat_Copy.TestDecodeTypeless;
var
  SrcBuf     : TBytes;
  DestString : RawByteString;
begin
  SrcBuf     := BytesOf(RawByteString('1234567890abcdefghijklmnopqrstuvwxyz@!$'));
  DestString := TFormat_Copy.Encode(SrcBuf[0], length(SrcBuf));

  CheckEquals(RawByteString('1234567890abcdefghijklmnopqrstuvwxyz@!$'),
              DestString);
end;

procedure TestTFormat_Copy.TestEncodeBytes;
var
  SrcBuf,
  DestBuf : TBytes;
begin
  SrcBuf  := BytesOf(RawByteString('1234567890abcdefghijklmnopqrstuvwxyz@!$'));
  DestBuf := TFormat_Copy.Encode(SrcBuf);

  CheckEquals('1234567890abcdefghijklmnopqrstuvwxyz@!$',
              string(BytesToRawString(DestBuf)));
end;

procedure TestTFormat_Copy.TestEncodeRawByteString;
var
  SrcString,
  DestString : RawByteString;
begin
  SrcString  := '1234567890abcdefghijklmnopqrstuvwxyz@!$';
  DestString := TFormat_Copy.Encode(SrcString);

  CheckEquals(RawByteString('1234567890abcdefghijklmnopqrstuvwxyz@!$'),
              DestString);
end;

procedure TestTFormat_Copy.TestEncodeTypeless;
var
  SrcBuf     : TBytes;
  DestString : RawByteString;
begin
  SrcBuf     := BytesOf(RawByteString('1234567890abcdefghijklmnopqrstuvwxyz@!$'));
  DestString := TFormat_Copy.Encode(SrcBuf[0], length(SrcBuf));

  CheckEquals(RawByteString('1234567890abcdefghijklmnopqrstuvwxyz@!$'),
              DestString);
end;

procedure TestTFormat_Copy.TestIsValidRawByteString;
begin
  CheckEquals(true, TFormat_Copy.IsValid(BytesOf('abcdefghijklmnopqrstuvwxyz')));
  CheckEquals(true, TFormat_Copy.IsValid(BytesOf('')));
end;

procedure TestTFormat_Copy.TestIsValidTBytes;
var
  SrcBuf : TBytes;
begin
  SrcBuf  := BytesOf(RawByteString('1234567890abcdefghijklmnopqrstuvwxyz@!$'));
  CheckEquals(true, TFormat_Copy.IsValid(SrcBuf));

  SetLength(SrcBuf, 0);
  CheckEquals(true, TFormat_Copy.IsValid(SrcBuf));
end;

procedure TestTFormat_Copy.TestIsValidTypeless;
var
  SrcBuf : TBytes;
  P      : ^Byte;
begin
  SrcBuf  := BytesOf(RawByteString('1234567890abcdefghijklmnopqrstuvwxyz@!$'));
  CheckEquals(true,  TFormat_Copy.IsValid(SrcBuf[0], Length(SrcBuf)));

  P := nil;
  CheckEquals(true,  TFormat_Copy.IsValid(P^, 0));
  CheckEquals(false, TFormat_Copy.IsValid(SrcBuf[0], -1));
end;

{ TestTFormat }

procedure TestTFormat.SetUp;
begin
  inherited;

end;

procedure TestTFormat.TearDown;
begin
  inherited;

end;

procedure TestTFormat.TestUpCaseBinary;
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

procedure TestTFormat.TestTableFindBinary;
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

procedure TestTFormat.TestIsClassListCreated;
begin
  CheckEquals(true, assigned(TDECFormat.ClassList), 'Class list has not been created in initialization');
end;

initialization
  {$IFNDEF DUnitX}
  // Register any test cases with the test runner
  RegisterTests('DECFormatBase', [TestTFormat.Suite, TestTFormat_Copy.Suite]);
  {$ELSE}
  TDUnitX.RegisterTestFixture(TestTFormat)
  TDUnitX.RegisterTestFixture(TestTFormat_Copy)
  {$ENDIF}
end.

