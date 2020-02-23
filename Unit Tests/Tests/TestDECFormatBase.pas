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
  TDUnitX.RegisterTestFixture(TestTFormat);
  TDUnitX.RegisterTestFixture(TestTFormat_Copy);
  {$ENDIF}
end.

